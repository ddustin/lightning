#include "config.h"
#include <ccan/cast/cast.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <channeld/channeld_wiregen.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <common/shutdown_scriptpubkey.h>
#include <common/type_to_string.h>
#include <common/wire_error.h>
#include <connectd/connectd_wiregen.h>
#include <errno.h>
#include <fcntl.h>
#include <hsmd/capabilities.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel.h>
#include <lightningd/channel_control.h>
#include <lightningd/closing_control.h>
#include <lightningd/coin_mvts.h>
#include <lightningd/dual_open_control.h>
#include <lightningd/gossip_control.h>
#include <lightningd/hsm_control.h>
#include <lightningd/notification.h>
#include <lightningd/peer_control.h>
#include <lightningd/peer_fd.h>
#include <wally_bip32.h>
#include <wally_psbt.h>

struct splice_command {
	/* Inside struct lightningd splice_commands. */
	struct list_node list;
	/* Command structure. This is the parent of the splice command. */
	struct command *cmd;
	/* Channel being spliced. */
	struct channel *channel;
};

void channel_update_feerates(struct lightningd *ld, const struct channel *channel)
{
	u8 *msg;
	u32 min_feerate, max_feerate;
	bool anchors = channel_type_has_anchors(channel->type);
	u32 feerate = unilateral_feerate(ld->topology, anchors);

	/* Nothing to do if we don't know feerate. */
	if (!feerate)
		return;

	/* For anchors, we just need the commitment tx to relay. */
	if (anchors)
		min_feerate = get_feerate_floor(ld->topology);
	else
		min_feerate = feerate_min(ld, NULL);
	max_feerate = feerate_max(ld, NULL);

	if (channel->ignore_fee_limits || ld->config.ignore_fee_limits) {
		min_feerate = 1;
		max_feerate = 0xFFFFFFFF;
	}

	log_debug(ld->log,
		  "update_feerates: feerate = %u, min=%u, max=%u, penalty=%u",
		  feerate,
		  min_feerate,
		  feerate_max(ld, NULL),
		  penalty_feerate(ld->topology));

	msg = towire_channeld_feerates(NULL, feerate,
				       min_feerate,
				       max_feerate,
				       penalty_feerate(ld->topology));
	subd_send_msg(channel->owner, take(msg));
}

static void try_update_feerates(struct lightningd *ld, struct channel *channel)
{
	/* No point until funding locked in */
	if (!channel_fees_can_change(channel))
		return;

	/* Can't if no daemon listening. */
	if (!channel->owner)
		return;

	channel_update_feerates(ld, channel);
}

static void try_update_blockheight(struct lightningd *ld,
				   struct channel *channel,
				   u32 blockheight)
{
	u8 *msg;

	log_debug(channel->log, "attempting update blockheight %s",
		  type_to_string(tmpctx, struct channel_id, &channel->cid));

	/* If they're offline, check that we're not too far behind anyway */
	if (!channel->owner) {
		if (channel->opener == REMOTE
		    && channel->lease_expiry > 0) {
			u32 peer_height
				= get_blockheight(channel->blockheight_states,
						  channel->opener, REMOTE);

			/* Lease no longer active, we don't (really) care */
			if (peer_height >= channel->lease_expiry)
				return;

			assert(peer_height + 1008 > peer_height);
			if (peer_height + 1008 < blockheight)
				channel_fail_permanent(channel,
						       REASON_PROTOCOL,
						       "Offline peer is too"
						       " far behind,"
						       " terminating leased"
						       " channel. Our current"
						       " %u, theirs %u",
						       blockheight,
						       peer_height);
		}
		return;
	}

	/* If we're not opened/locked in yet, don't send update */
	if (!channel_fees_can_change(channel))
		return;

	/* We don't update the blockheight for non-leased chans */
	if (channel->lease_expiry == 0)
		return;

	log_debug(ld->log, "update_blockheight: height = %u", blockheight);

	msg = towire_channeld_blockheight(NULL, blockheight);
	subd_send_msg(channel->owner, take(msg));
}

void notify_feerate_change(struct lightningd *ld)
{
	struct peer *peer;
	struct peer_node_id_map_iter it;

	for (peer = peer_node_id_map_first(ld->peers, &it);
	     peer;
	     peer = peer_node_id_map_next(ld->peers, &it)) {
		struct channel *channel;

		list_for_each(&peer->channels, channel, list)
			try_update_feerates(ld, channel);
	}

	/* FIXME: We choose not to drop to chain if we can't contact
	 * peer.  We *could* do so, however. */
}

static struct splice_command *splice_command_for_chan(struct lightningd *ld,
						      struct channel *channel)
{
	struct splice_command *cc;

	list_for_each(&ld->splice_commands, cc, list)
		if (channel == cc->channel)
			return cc;

	return NULL;
}

static void handle_splice_funding_error(struct lightningd *ld,
					 struct channel *channel,
					 const u8 *msg)
{
	struct splice_command *cc;
	struct amount_msat funding, req_funding;
	bool opener_error;

	if (!fromwire_channeld_splice_funding_error(msg, &funding,
						    &req_funding,
						    &opener_error)) {
		channel_internal_error(channel,
				       "bad channeld_splice_feerate_error %s",
				       tal_hex(channel, msg));
		return;
	}

	cc = splice_command_for_chan(ld, channel);
	if (cc) {
		struct json_stream *response = json_stream_success(cc->cmd);
		json_add_string(response, "message", "Splice funding too low");
		json_add_string(response, "error",
				tal_fmt(tmpctx,
					"%s provided %s but committed to %s.",
					opener_error ? "You" : "Peer",
					fmt_amount_msat(tmpctx, funding),
					fmt_amount_msat(tmpctx, req_funding)));

		was_pending(command_success(cc->cmd, response));
	}
	else
		log_peer_unusual(ld->log, &channel->peer->id,
				 "Splice funding too low. %s provided but %s"
				 " commited to %s",
				 opener_error ? "peer" : "you",
				 fmt_amount_msat(tmpctx, funding),
				 fmt_amount_msat(tmpctx, req_funding));
}

static void handle_splice_state_error(struct lightningd *ld,
				      struct channel *channel,
				      const u8 *msg)
{
	struct splice_command *cc;
	char *error_msg;

	if (!fromwire_channeld_splice_state_error(tmpctx, msg, &error_msg)) {
		channel_internal_error(channel,
				       "bad channeld_splice_state_error %s",
				       tal_hex(channel, msg));
		return;
	}

	cc = splice_command_for_chan(ld, channel);
	if (cc) {
		struct json_stream *response = json_stream_success(cc->cmd);
		json_add_string(response, "message", "Splice state error");
		json_add_string(response, "error", error_msg);

		was_pending(command_success(cc->cmd, response));
	}
	else
		log_peer_unusual(ld->log, &channel->peer->id,
				 "Splice state error: %s", error_msg);
}

static void handle_splice_feerate_error(struct lightningd *ld,
					 struct channel *channel,
					 const u8 *msg)
{
	struct splice_command *cc;
	struct amount_msat fee;
	bool too_high;

	if (!fromwire_channeld_splice_feerate_error(msg, &fee, &too_high)) {
		channel_internal_error(channel,
				       "bad fromwire_channeld_splice_feerate_error %s",
				       tal_hex(channel, msg));
		return;
	}

	cc = splice_command_for_chan(ld, channel);
	if (cc) {
		struct json_stream *response = json_stream_success(cc->cmd);
		json_add_string(response, "message", "Splice feerate failed");

		if (too_high)
			json_add_string(response, "error",
					tal_fmt(tmpctx, "Feerate too high. Do you "
						"really want to spend %s on fees?",
						fmt_amount_msat(tmpctx, fee)));
		else
			json_add_string(response, "error",
					tal_fmt(tmpctx, "Feerate too low. Your "
						"funding only provided %s in fees",
						fmt_amount_msat(tmpctx, fee)));

		was_pending(command_success(cc->cmd, response));
	}
	else
		log_peer_unusual(ld->log, &channel->peer->id, "Peer gave us a"
				 " splice pkg with too low of feerate (fee was"
				 " %s), we rejected it.",
				 fmt_amount_msat(tmpctx, fee));
}

/* When channeld finishes processing the `splice_init` command, this is called */
static void handle_splice_confirmed_init(struct lightningd *ld,
					 struct channel *channel,
					 const u8 *msg)
{
	struct splice_command *cc;
	struct wally_psbt *psbt;

	if (!fromwire_channeld_splice_confirmed_init(tmpctx, msg, &psbt)) {
		channel_internal_error(channel,
				       "bad splice_confirmed_init %s",
				       tal_hex(channel, msg));
		return;
	}

	cc = splice_command_for_chan(ld, channel);
	if (!cc) {
		channel_internal_error(channel, "splice_confirmed_init"
				       " received without an active command %s",
				       tal_hex(channel, msg));
		return;
	}

	struct json_stream *response = json_stream_success(cc->cmd);
	json_add_string(response, "psbt", psbt_to_b64(tmpctx, psbt));

	was_pending(command_success(cc->cmd, response));
}

/* Channeld sends us this in response to a user's `splice_update` request */
static void handle_splice_confirmed_update(struct lightningd *ld,
					   struct channel *channel,
					   const u8 *msg)
{
	struct splice_command *cc;
	struct wally_psbt *psbt;
	bool commitments_secured;

	if (!fromwire_channeld_splice_confirmed_update(tmpctx,
						      msg,
						      &psbt,
						      &commitments_secured)) {
		channel_internal_error(channel,
				       "bad splice_confirmed_update %s",
				       tal_hex(channel, msg));
		return;
	}

	cc = splice_command_for_chan(ld, channel);
	if (!cc) {
		channel_internal_error(channel, "splice_update_confirmed"
				       " received without an active command %s",
				       tal_hex(channel, msg));
		return;
	}

	struct json_stream *response = json_stream_success(cc->cmd);
	json_add_string(response, "psbt", psbt_to_b64(tmpctx, psbt));
	json_add_bool(response, "commitments_secured", commitments_secured);

	was_pending(command_success(cc->cmd, response));
}

/* Channeld uses this to request the funding transaction for help building the
 * splice tx */
static void handle_splice_lookup_tx(struct lightningd *ld,
				    struct channel *channel,
				    const u8 *msg)
{
	struct bitcoin_txid txid;
	struct bitcoin_tx *tx;
	u8 *outmsg;

	if (!fromwire_channeld_splice_lookup_tx(msg, &txid)) {
		channel_internal_error(channel,
				       "bad splice_lookup_tx %s",
				       tal_hex(channel, msg));
		return;
	}

	tx = wallet_transaction_get(tmpctx, ld->wallet, &txid);

	if (!tx) {
		channel_internal_error(channel,
				       "channel control unable to find txid %s",
				       type_to_string(tmpctx,
				       		      struct bitcoin_txid,
				       		      &txid));
		return;
	}

	outmsg = towire_channeld_splice_lookup_tx_result(NULL, tx);
	subd_send_msg(channel->owner, take(outmsg));
}

/* Extra splice data we want to store for bitcoin send tx interface */
struct send_splice_info
{
	struct splice_command *cc;
	struct channel *channel;
	const struct bitcoin_tx *final_tx;
	u32 output_index;
	const char *err_msg;
};

static void handle_tx_broadcast(struct send_splice_info *info)
{
	struct lightningd *ld = info->channel->peer->ld;
	struct amount_sat unused;
	struct json_stream *response;
	struct bitcoin_txid txid;
	u8 *tx_bytes;
	int num_utxos;

	tx_bytes = linearize_tx(tmpctx, info->final_tx);
	bitcoin_txid(info->final_tx, &txid);

	/* This might have spent UTXOs from our wallet */
	num_utxos = wallet_extract_owned_outputs(ld->wallet,
						 info->final_tx->wtx, false,
						 NULL, &unused);
	if (num_utxos)
		wallet_transaction_add(ld->wallet, info->final_tx->wtx, 0, 0);

	if (info->cc) {
		response = json_stream_success(info->cc->cmd);

		json_add_hex(response, "tx", tx_bytes, tal_bytelen(tx_bytes));
		json_add_txid(response, "txid", &txid);

		was_pending(command_success(info->cc->cmd, response));
	}
}

/* Succeeds if the utxo was found in the mempool or in the utxo set. If it's in
 * a block and spent it will fail but we're okay with that here. */
static void check_utxo_block(struct bitcoind *bitcoind UNUSED,
			     const struct bitcoin_tx_output *txout,
			     void *arg)
{
	struct send_splice_info *info = arg;

	if(!txout) {
		if (info->cc)
			was_pending(command_fail(info->cc->cmd,
						 SPLICE_BROADCAST_FAIL,
						 "Error broadcasting splice "
						 "tx: %s. Unsent tx discarded "
						 "%s.",
						 info->err_msg,
						 type_to_string(tmpctx,
								struct wally_tx,
								info->final_tx->wtx)));

		log_unusual(info->channel->log,
			    "Error broadcasting splice "
			    "tx: %s. Unsent tx discarded "
			    "%s.",
			    info->err_msg,
			    type_to_string(tmpctx, struct wally_tx,
			    		   info->final_tx->wtx));
	}
	else
		handle_tx_broadcast(info);

	tal_free(info);
}

/* Callback for after the splice tx is sent to bitcoind */
static void send_splice_tx_done(struct bitcoind *bitcoind UNUSED,
				bool success, const char *msg,
				struct send_splice_info *info)
{
	/* A NULL value of `info->cc` means we got here without user intiation.
	 * This means we are the ACCEPTER side of the splice */
	struct lightningd *ld = info->channel->peer->ld;
	struct bitcoin_outpoint outpoint;

	bitcoin_txid(info->final_tx, &outpoint.txid);
	outpoint.n = info->output_index;

	if (!success) {
		info->err_msg = tal_strdup(info, msg);
		bitcoind_getutxout(ld->topology->bitcoind, &outpoint,
				   check_utxo_block, info);
	} else {
		handle_tx_broadcast(info);
		tal_free(info);
	}
}

/* Where the splice tx gets finally transmitted to the chain */
static void send_splice_tx(struct channel *channel,
			   const struct bitcoin_tx *tx,
			   struct splice_command *cc,
			   u32 output_index)
{
	struct lightningd *ld = channel->peer->ld;
	u8* tx_bytes = linearize_tx(tmpctx, tx);

	log_debug(channel->log,
		  "Broadcasting splice tx %s for channel %s.",
		  tal_hex(tmpctx, tx_bytes),
		  type_to_string(tmpctx, struct channel_id, &channel->cid));

	struct send_splice_info *info = tal(NULL, struct send_splice_info);

	info->cc = tal_steal(info, cc);
	info->channel = channel;
	info->final_tx = tal_steal(info, tx);
	info->output_index = output_index;
	info->err_msg = NULL;

	bitcoind_sendrawtx(ld->topology->bitcoind,
			   cc ? cc->cmd->id : NULL,
			   tal_hex(tmpctx, tx_bytes),
			   false,
			   send_splice_tx_done, info);
}

/* After user signs PSBT with splice_signed, our node goes through the signing
 * process (adding it's own signatures and peers' sigs), sending the result to
 * us here: */
static void handle_splice_confirmed_signed(struct lightningd *ld,
					   struct channel *channel,
					   const u8 *msg)
{
	struct splice_command *cc;
	struct bitcoin_tx *tx;
	struct bitcoin_txid txid;
	struct channel_inflight *inflight;
	u32 output_index;

	if (!fromwire_channeld_splice_confirmed_signed(tmpctx, msg, &tx, &output_index)) {

		channel_internal_error(channel,
				       "bad splice_confirmed_signed %s",
				       tal_hex(channel, msg));
		return;
	}

	bitcoin_txid(tx, &txid);
	inflight = channel_inflight_find(channel, &txid);
	if (!inflight)
		channel_internal_error(channel, "Unable to load inflight for"
				       " splice_confirmed_signed txid %s",
				       type_to_string(tmpctx,
				       		      struct bitcoin_txid,
				       		      &txid));

	inflight->remote_tx_sigs = true;
	wallet_inflight_save(ld->wallet, inflight);

	if (channel->state != CHANNELD_NORMAL) {
		log_debug(channel->log,
			  "Would broadcast splice, but state %s"
			  " isn't CHANNELD_NORMAL",
			  channel_state_name(channel));
		return;
	}

	cc = splice_command_for_chan(ld, channel);
	/* If matching user command found, this was a user intiated splice */
	channel_set_state(channel,
			  CHANNELD_NORMAL,
			  CHANNELD_AWAITING_SPLICE,
			  cc ? REASON_USER : REASON_REMOTE,
			  "Broadcasting splice");

	send_splice_tx(channel, tx, cc, output_index);
}

static void handle_add_inflight(struct lightningd *ld,
				struct channel *channel,
				const u8 *msg)
{
	struct bitcoin_outpoint outpoint;
	u32 feerate;
	struct amount_sat satoshis;
	s64 splice_amnt;
	struct wally_psbt *psbt;
	struct channel_inflight *inflight;
	struct bitcoin_signature last_sig;
	bool i_am_initiator;

	if (!fromwire_channeld_add_inflight(tmpctx,
					    msg,
					    &outpoint.txid,
					    &outpoint.n,
					    &feerate,
					    &satoshis,
					    &splice_amnt,
					    &psbt,
					    &i_am_initiator)) {
		channel_internal_error(channel,
				       "bad channel_add_inflight %s",
				       tal_hex(channel, msg));
		return;
	}

	/* FIXME: DTODO: Use a pointer to a sig instead of zero'ing one out. */
	memset(&last_sig, 0, sizeof(last_sig));

	inflight = new_inflight(channel,
				&outpoint,
				feerate,
				satoshis,
				channel->our_funds,
				psbt,
				NULL,
				last_sig,
				channel->lease_expiry,
				channel->lease_commit_sig,
				channel->lease_chan_max_msat,
				channel->lease_chan_max_ppt,
				0,
				AMOUNT_MSAT(0),
				AMOUNT_SAT(0),
				splice_amnt,
				i_am_initiator);

	log_debug(channel->log, "lightningd adding inflight with txid %s",
		  type_to_string(tmpctx, struct bitcoin_txid,
		  		 &inflight->funding->outpoint.txid));

	wallet_inflight_add(ld->wallet, inflight);
	channel_watch_inflight(ld, channel, inflight);

	subd_send_msg(channel->owner, take(towire_channeld_got_inflight(NULL)));
}

static void handle_update_inflight(struct lightningd *ld,
				   struct channel *channel,
				   const u8 *msg)
{
	struct channel_inflight *inflight;
	struct wally_psbt *psbt;
	struct bitcoin_txid txid;
	struct bitcoin_tx *last_tx;
	struct bitcoin_signature *last_sig;

	if (!fromwire_channeld_update_inflight(tmpctx, msg, &psbt, &last_tx,
					       &last_sig)) {
		channel_internal_error(channel,
				       "bad channel_add_inflight %s",
				       tal_hex(channel, msg));
		return;
	}

	psbt_txid(tmpctx, psbt, &txid, NULL);
	inflight = channel_inflight_find(channel, &txid);
	if (!inflight)
		channel_internal_error(channel, "Unable to load inflight for"
				       " update_inflight txid %s",
				       type_to_string(tmpctx,
						      struct bitcoin_txid,
						      &txid));

	if (!!last_tx != !!last_sig)
		channel_internal_error(channel, "Must set last_tx and last_sig"
				       " together at the same time for"
				       " update_inflight txid %s",
				       type_to_string(tmpctx,
						      struct bitcoin_txid,
						      &txid));

	if (last_tx)
		inflight->last_tx = tal_steal(inflight, last_tx);

	if (last_sig)
		inflight->last_sig = *last_sig;

	tal_wally_start();
	if (wally_psbt_combine(inflight->funding_psbt, psbt) != WALLY_OK) {
		channel_internal_error(channel,
				       "Unable to combine PSBTs: %s, %s",
				       type_to_string(tmpctx,
						      struct wally_psbt,
						      inflight->funding_psbt),
				       type_to_string(tmpctx,
						      struct wally_psbt,
						      psbt));
		tal_wally_end(inflight->funding_psbt);
		return;
	}
	tal_wally_end(inflight->funding_psbt);

	psbt_finalize(inflight->funding_psbt);
	wallet_inflight_save(ld->wallet, inflight);
}

void channel_record_open(struct channel *channel, u32 blockheight, bool record_push)
{
	struct chain_coin_mvt *mvt;
	struct amount_msat start_balance;
	bool is_pushed = !amount_msat_zero(channel->push);
	bool is_leased = channel->lease_expiry > 0;

	/* If funds were pushed, add/sub them from the starting balance */
	if (channel->opener == LOCAL) {
		if (!amount_msat_add(&start_balance,
				     channel->our_msat, channel->push))
			fatal("Unable to add push_msat (%s) + our_msat (%s)",
			      type_to_string(tmpctx, struct amount_msat,
					     &channel->push),
			      type_to_string(tmpctx, struct amount_msat,
					     &channel->our_msat));
	} else {
		if (!amount_msat_sub(&start_balance,
				    channel->our_msat, channel->push))
			fatal("Unable to sub our_msat (%s) - push (%s)",
			      type_to_string(tmpctx, struct amount_msat,
					     &channel->our_msat),
			      type_to_string(tmpctx, struct amount_msat,
					     &channel->push));
	}

	/* If it's not in a block yet, send a proposal */
	if (blockheight > 0)
		mvt = new_coin_channel_open(tmpctx,
					    &channel->cid,
					    &channel->funding,
					    &channel->peer->id,
					    blockheight,
					    start_balance,
					    channel->funding_sats,
					    channel->opener == LOCAL,
					    is_leased);
	else
		mvt = new_coin_channel_open_proposed(tmpctx,
					    &channel->cid,
					    &channel->funding,
					    &channel->peer->id,
					    start_balance,
					    channel->funding_sats,
					    channel->opener == LOCAL,
					    is_leased);

	notify_chain_mvt(channel->peer->ld, mvt);

	/* If we pushed sats, *now* record them */
	if (is_pushed && record_push)
		notify_channel_mvt(channel->peer->ld,
				   new_coin_channel_push(tmpctx, &channel->cid,
							 channel->push,
							 is_leased ? LEASE_FEE : PUSHED,
							 channel->opener == REMOTE));
}

static void lockin_complete(struct channel *channel,
			    enum channel_state expected_state)
{
	if (!channel->scid &&
	    (!channel->alias[REMOTE] || !channel->alias[LOCAL])) {
		log_debug(channel->log, "Attempted lockin, but neither scid "
					"nor aliases are set, ignoring");
		return;
	}

	/* We set this once they're locked in. */
	assert(channel->remote_channel_ready);

	/* We might have already started shutting down */
	if (channel->state != expected_state) {
		log_debug(channel->log, "Lockin complete, but state %s",
			  channel_state_name(channel));
		return;
	}

	log_debug(channel->log, "Moving channel state from %s to %s",
		  channel_state_str(expected_state),
		  channel_state_str(CHANNELD_NORMAL));

	channel_set_state(channel,
			  expected_state,
			  CHANNELD_NORMAL,
			  REASON_UNKNOWN,
			  "Lockin complete");

	/* Fees might have changed (and we use IMMEDIATE once we're funded),
	 * so update now. */
	try_update_feerates(channel->peer->ld, channel);

	try_update_blockheight(channel->peer->ld, channel,
			       get_block_height(channel->peer->ld->topology));

	/* Emit an event for the channel open (or channel proposal if blockheight
	 * is zero) */
	channel_record_open(channel,
			    channel->scid ?
			    short_channel_id_blocknum(channel->scid) : 0,
			    true);
}

bool channel_on_channel_ready(struct channel *channel,
			      struct pubkey *next_per_commitment_point)
{
	if (channel->remote_channel_ready) {
		channel_internal_error(channel,
				       "channel_got_channel_ready twice");
		return false;
	}
	update_per_commit_point(channel, next_per_commitment_point);

	log_debug(channel->log, "Got channel_ready");
	channel->remote_channel_ready = true;

	return true;
}

static void handle_peer_splice_locked(struct channel *channel, const u8 *msg)
{
	struct amount_sat funding_sats;
	s64 splice_amnt;
	struct channel_inflight *inflight;
	struct bitcoin_txid locked_txid;

	if (!fromwire_channeld_got_splice_locked(msg, &funding_sats,
						 &splice_amnt,
						 &locked_txid)) {
		channel_internal_error(channel,
				       "bad channel_got_funding_locked %s",
				       tal_hex(channel, msg));
		return;
	}

	channel->our_msat.millisatoshis += splice_amnt * 1000; /* Raw: splicing */
	channel->msat_to_us_min.millisatoshis += splice_amnt * 1000; /* Raw: splicing */
	channel->msat_to_us_max.millisatoshis += splice_amnt * 1000; /* Raw: splicing */

	inflight = channel_inflight_find(channel, &locked_txid);
	if(!inflight)
		channel_internal_error(channel, "Unable to load inflight for"
				       " locked_txid %s",
				       type_to_string(tmpctx,
				       		      struct bitcoin_txid,
				       		      &locked_txid));

	wallet_htlcsigs_confirm_inflight(channel->peer->ld->wallet, channel,
					 &inflight->funding->outpoint);

	update_channel_from_inflight(channel->peer->ld, channel, inflight);

	/* Remember that we got the lockin */
	wallet_channel_save(channel->peer->ld->wallet, channel);

	/* Empty out the inflights */
	log_debug(channel->log, "lightningd, splice_locked clearing inflights");
	wallet_channel_clear_inflights(channel->peer->ld->wallet, channel);

	lockin_complete(channel, CHANNELD_AWAITING_SPLICE);
}

/* We were informed by channeld that channel is ready (reached mindepth) */
static void peer_got_channel_ready(struct channel *channel, const u8 *msg)
{
	struct pubkey next_per_commitment_point;
	struct short_channel_id *alias_remote;

	if (!fromwire_channeld_got_channel_ready(tmpctx,
		msg, &next_per_commitment_point, &alias_remote)) {
		channel_internal_error(channel,
				       "bad channel_got_channel_ready %s",
				       tal_hex(channel, msg));
		return;
	}

	if (!channel_on_channel_ready(channel, &next_per_commitment_point))
		return;

	if (channel->alias[REMOTE] == NULL)
		channel->alias[REMOTE] = tal_steal(channel, alias_remote);

	/* Remember that we got the lockin */
	wallet_channel_save(channel->peer->ld->wallet, channel);

	if (channel->depth >= channel->minimum_depth)
		lockin_complete(channel, CHANNELD_AWAITING_LOCKIN);
}

static void peer_got_announcement(struct channel *channel, const u8 *msg)
{
	secp256k1_ecdsa_signature remote_ann_node_sig;
	secp256k1_ecdsa_signature remote_ann_bitcoin_sig;

	if (!fromwire_channeld_got_announcement(msg,
					       &remote_ann_node_sig,
					       &remote_ann_bitcoin_sig)) {
		channel_internal_error(channel,
				       "bad channel_got_announcement %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	wallet_announcement_save(channel->peer->ld->wallet, channel->dbid,
				 &remote_ann_node_sig,
				 &remote_ann_bitcoin_sig);
}

static void peer_got_shutdown(struct channel *channel, const u8 *msg)
{
	u8 *scriptpubkey;
	struct lightningd *ld = channel->peer->ld;
	struct bitcoin_outpoint *wrong_funding;
	bool anysegwit = feature_negotiated(ld->our_features,
					    channel->peer->their_features,
					    OPT_SHUTDOWN_ANYSEGWIT);
	bool anchors = feature_negotiated(ld->our_features,
					  channel->peer->their_features,
					  OPT_ANCHOR_OUTPUTS)
		|| feature_negotiated(ld->our_features,
				      channel->peer->their_features,
				      OPT_ANCHORS_ZERO_FEE_HTLC_TX);

	if (!fromwire_channeld_got_shutdown(channel, msg, &scriptpubkey,
					    &wrong_funding)) {
		channel_internal_error(channel, "bad channel_got_shutdown %s",
				       tal_hex(msg, msg));
		return;
	}

	/* BOLT #2:
	 * A receiving node:
	 *...
	 *   - if the `scriptpubkey` is not in one of the above forms:
	 *     - SHOULD send a `warning`.
	 */
	if (!valid_shutdown_scriptpubkey(scriptpubkey, anysegwit, !anchors)) {
		u8 *warning = towire_warningfmt(NULL,
						&channel->cid,
						"Bad shutdown scriptpubkey %s",
						tal_hex(tmpctx, scriptpubkey));

		/* Get connectd to send warning, and then allow reconnect. */
		subd_send_msg(ld->connectd,
			      take(towire_connectd_peer_final_msg(NULL,
								  &channel->peer->id,
								  channel->peer->connectd_counter,
								  warning)));
		channel_fail_transient(channel, "Bad shutdown scriptpubkey %s",
				       tal_hex(tmpctx, scriptpubkey));
		return;
	}

	/* FIXME: Add to spec that we must allow repeated shutdown! */
	tal_free(channel->shutdown_scriptpubkey[REMOTE]);
	channel->shutdown_scriptpubkey[REMOTE] = scriptpubkey;

	/* If we weren't already shutting down, we are now */
	if (channel->state != CHANNELD_SHUTTING_DOWN)
		channel_set_state(channel,
				  channel->state,
				  CHANNELD_SHUTTING_DOWN,
				  REASON_REMOTE,
				  "Peer closes channel");

	/* If we set it, that's what we want.  Otherwise use their preference.
	 * We can't have both, since only opener can set this! */
	if (!channel->shutdown_wrong_funding)
		channel->shutdown_wrong_funding = wrong_funding;

	/* We now watch the "wrong" funding, in case we spend it. */
	channel_watch_wrong_funding(ld, channel);

	/* TODO(cdecker) Selectively save updated fields to DB */
	wallet_channel_save(ld->wallet, channel);
}

void channel_fallen_behind(struct channel *channel, const u8 *msg)
{

	/* per_commitment_point is NULL if option_static_remotekey, but we
	 * use its presence as a flag so set it any valid key in that case. */
	if (!channel->future_per_commitment_point) {
		struct pubkey *any = tal(channel, struct pubkey);
		if (!pubkey_from_node_id(any, &channel->peer->ld->id))
			fatal("Our own id invalid?");
		channel->future_per_commitment_point = any;
	}

	/* Peer sees this, so send a generic msg about unilateral close. */
	channel_fail_permanent(channel,
			       REASON_LOCAL,
			       "Awaiting unilateral close");
}

static void
channel_fail_fallen_behind(struct channel *channel, const u8 *msg)
{
	if (!fromwire_channeld_fail_fallen_behind(channel, msg,
						 cast_const2(struct pubkey **,
							    &channel->future_per_commitment_point))) {
		channel_internal_error(channel,
				       "bad channel_fail_fallen_behind %s",
				       tal_hex(tmpctx, msg));
		return;
	}

        channel_fallen_behind(channel, msg);
}

static void peer_start_closingd_after_shutdown(struct channel *channel,
					       const u8 *msg,
					       const int *fds)
{
	struct peer_fd *peer_fd;

	if (!fromwire_channeld_shutdown_complete(msg)) {
		channel_internal_error(channel, "bad shutdown_complete: %s",
				       tal_hex(msg, msg));
		return;
	}
	peer_fd = new_peer_fd_arr(msg, fds);

	/* This sets channel->owner, closes down channeld. */
	peer_start_closingd(channel, peer_fd);

	/* We might have reconnected, so already be here. */
	if (!channel_closed(channel)
	    && channel->state != CLOSINGD_SIGEXCHANGE)
		channel_set_state(channel,
				  CHANNELD_SHUTTING_DOWN,
				  CLOSINGD_SIGEXCHANGE,
				  REASON_UNKNOWN,
				  "Start closingd");
}

static void forget(struct channel *channel)
{
	struct command **forgets = tal_steal(tmpctx, channel->forgets);
	channel->forgets = tal_arr(channel, struct command *, 0);

	/* Forget the channel. */
	delete_channel(channel);

	for (size_t i = 0; i < tal_count(forgets); i++) {
		assert(!forgets[i]->json_stream);

		struct json_stream *response;
		response = json_stream_success(forgets[i]);
		json_add_string(response, "cancelled",
				"Channel open canceled by RPC(after"
				" fundchannel_complete)");
		was_pending(command_success(forgets[i], response));
	}

	tal_free(forgets);
}

static void handle_error_channel(struct channel *channel,
				 const u8 *msg)
{
	if (!fromwire_channeld_send_error_reply(msg)) {
		channel_internal_error(channel, "bad send_error_reply: %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	forget(channel);
}

static void handle_local_private_channel(struct channel *channel, const u8 *msg)
{
	struct amount_sat capacity;
	u8 *features;

	if (!fromwire_channeld_local_private_channel(msg, msg, &capacity,
						     &features)) {
		channel_internal_error(channel,
				       "bad channeld_local_private_channel %s",
				       tal_hex(channel, msg));
		return;
	}

	tell_gossipd_local_private_channel(channel->peer->ld, channel,
					   capacity, features);
}

static void forget_channel(struct channel *channel, const char *why)
{
	channel->error = towire_errorfmt(channel, &channel->cid, "%s", why);

	/* If the peer is connected, we let them know. Otherwise
	 * we just directly remove the channel */
	if (channel->owner)
		subd_send_msg(channel->owner,
			      take(towire_channeld_send_error(NULL, why)));
	else
		forget(channel);
}

static void handle_channel_upgrade(struct channel *channel,
				   const u8 *msg)
{
	struct channel_type *newtype;

	if (!fromwire_channeld_upgraded(msg, msg, &newtype)) {
		channel_internal_error(channel, "bad handle_channel_upgrade: %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	/* You can currently only upgrade to turn on option_static_remotekey:
	 * if they somehow thought anything else we need to close channel! */
	if (channel->static_remotekey_start[LOCAL] != 0x7FFFFFFFFFFFFFFFULL) {
		channel_internal_error(channel,
				       "channel_upgrade already static_remotekey? %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	if (!channel_type_eq(newtype, channel_type_static_remotekey(tmpctx))) {
		channel_internal_error(channel,
				       "channel_upgrade must be static_remotekey, not %s",
				       fmt_featurebits(tmpctx, newtype->features));
		return;
	}

	tal_free(channel->type);
	channel->type = channel_type_dup(channel, newtype);
	channel->static_remotekey_start[LOCAL] = channel->next_index[LOCAL];
	channel->static_remotekey_start[REMOTE] = channel->next_index[REMOTE];
	log_debug(channel->log,
		  "option_static_remotekey enabled at %"PRIu64"/%"PRIu64,
		  channel->static_remotekey_start[LOCAL],
		  channel->static_remotekey_start[REMOTE]);

	wallet_channel_save(channel->peer->ld->wallet, channel);
}

static bool get_inflight_outpoint_index(struct channel *channel,
					const struct bitcoin_txid *txid,
					u32 *index)
{
	struct channel_inflight *inflight;

	list_for_each(&channel->inflights, inflight, list) {
		if (bitcoin_txid_eq(txid, &inflight->funding->outpoint.txid)) {
			*index = inflight->funding->outpoint.n;
			return true;
		}
	}

	return false;
}

static unsigned channel_msg(struct subd *sd, const u8 *msg, const int *fds)
{
	enum channeld_wire t = fromwire_peektype(msg);

	switch (t) {
	case WIRE_CHANNELD_SENDING_COMMITSIG:
		peer_sending_commitsig(sd->channel, msg);
		break;
	case WIRE_CHANNELD_GOT_COMMITSIG:
		peer_got_commitsig(sd->channel, msg);
		break;
	case WIRE_CHANNELD_GOT_REVOKE:
		peer_got_revoke(sd->channel, msg);
		break;
	case WIRE_CHANNELD_GOT_CHANNEL_READY:
		peer_got_channel_ready(sd->channel, msg);
		break;
	case WIRE_CHANNELD_GOT_ANNOUNCEMENT:
		peer_got_announcement(sd->channel, msg);
		break;
	case WIRE_CHANNELD_GOT_SHUTDOWN:
		peer_got_shutdown(sd->channel, msg);
		break;
	case WIRE_CHANNELD_SHUTDOWN_COMPLETE:
		/* We expect 1 fd. */
		if (!fds)
			return 1;
		peer_start_closingd_after_shutdown(sd->channel, msg, fds);
		break;
	case WIRE_CHANNELD_FAIL_FALLEN_BEHIND:
		channel_fail_fallen_behind(sd->channel, msg);
		break;
	case WIRE_CHANNELD_SEND_ERROR_REPLY:
		handle_error_channel(sd->channel, msg);
		break;
	case WIRE_CHANNELD_USED_CHANNEL_UPDATE:
		/* This tells gossipd we used it. */
		get_channel_update(sd->channel);
		break;
	case WIRE_CHANNELD_LOCAL_CHANNEL_UPDATE:
		tell_gossipd_local_channel_update(sd->ld, sd->channel, msg);
		break;
	case WIRE_CHANNELD_LOCAL_CHANNEL_ANNOUNCEMENT:
		tell_gossipd_local_channel_announce(sd->ld, sd->channel, msg);
		break;
	case WIRE_CHANNELD_LOCAL_PRIVATE_CHANNEL:
		handle_local_private_channel(sd->channel, msg);
		break;
	case WIRE_CHANNELD_SPLICE_CONFIRMED_INIT:
		handle_splice_confirmed_init(sd->ld, sd->channel, msg);
		break;
	case WIRE_CHANNELD_SPLICE_FEERATE_ERROR:
		handle_splice_feerate_error(sd->ld, sd->channel, msg);
		break;
	case WIRE_CHANNELD_SPLICE_FUNDING_ERROR:
		handle_splice_funding_error(sd->ld, sd->channel, msg);
		break;
	case WIRE_CHANNELD_SPLICE_STATE_ERROR:
		handle_splice_state_error(sd->ld, sd->channel, msg);
		break;
	case WIRE_CHANNELD_SPLICE_CONFIRMED_UPDATE:
		handle_splice_confirmed_update(sd->ld, sd->channel, msg);
		break;
	case WIRE_CHANNELD_SPLICE_LOOKUP_TX:
		handle_splice_lookup_tx(sd->ld, sd->channel, msg);
		break;
	case WIRE_CHANNELD_SPLICE_CONFIRMED_SIGNED:
		handle_splice_confirmed_signed(sd->ld, sd->channel, msg);
		break;
	case WIRE_CHANNELD_ADD_INFLIGHT:
		handle_add_inflight(sd->ld, sd->channel, msg);
		break;
	case WIRE_CHANNELD_UPDATE_INFLIGHT:
		handle_update_inflight(sd->ld, sd->channel, msg);
		break;
	case WIRE_CHANNELD_GOT_SPLICE_LOCKED:
		handle_peer_splice_locked(sd->channel, msg);
		break;
	case WIRE_CHANNELD_UPGRADED:
		handle_channel_upgrade(sd->channel, msg);
		break;
	/* And we never get these from channeld. */
	case WIRE_CHANNELD_INIT:
	case WIRE_CHANNELD_FUNDING_DEPTH:
	case WIRE_CHANNELD_OFFER_HTLC:
	case WIRE_CHANNELD_FULFILL_HTLC:
	case WIRE_CHANNELD_FAIL_HTLC:
	case WIRE_CHANNELD_GOT_COMMITSIG_REPLY:
	case WIRE_CHANNELD_GOT_REVOKE_REPLY:
	case WIRE_CHANNELD_SENDING_COMMITSIG_REPLY:
	case WIRE_CHANNELD_SEND_SHUTDOWN:
	case WIRE_CHANNELD_DEV_REENABLE_COMMIT:
	case WIRE_CHANNELD_FEERATES:
	case WIRE_CHANNELD_BLOCKHEIGHT:
	case WIRE_CHANNELD_CONFIG_CHANNEL:
	case WIRE_CHANNELD_CHANNEL_UPDATE:
	case WIRE_CHANNELD_DEV_MEMLEAK:
	case WIRE_CHANNELD_DEV_QUIESCE:
	case WIRE_CHANNELD_GOT_INFLIGHT:
		/* Replies go to requests. */
	case WIRE_CHANNELD_OFFER_HTLC_REPLY:
	case WIRE_CHANNELD_DEV_REENABLE_COMMIT_REPLY:
	case WIRE_CHANNELD_DEV_MEMLEAK_REPLY:
	case WIRE_CHANNELD_SEND_ERROR:
	case WIRE_CHANNELD_SPLICE_INIT:
	case WIRE_CHANNELD_SPLICE_UPDATE:
	case WIRE_CHANNELD_SPLICE_LOOKUP_TX_RESULT:
	case WIRE_CHANNELD_SPLICE_SIGNED:
	case WIRE_CHANNELD_DEV_QUIESCE_REPLY:
		break;
	}

	return 0;
}

bool peer_start_channeld(struct channel *channel,
			 struct peer_fd *peer_fd,
			 const u8 *fwd_msg,
			 bool reconnected,
			 bool reestablish_only)
{
	u8 *initmsg;
	int hsmfd;
	const struct existing_htlc **htlcs;
	struct short_channel_id scid;
	u64 num_revocations;
	struct lightningd *ld = channel->peer->ld;
	const struct config *cfg = &ld->config;
	bool reached_announce_depth;
	struct secret last_remote_per_commit_secret;
	secp256k1_ecdsa_signature *remote_ann_node_sig, *remote_ann_bitcoin_sig;
	struct penalty_base *pbases;
	u32 min_feerate, max_feerate;
	struct channel_inflight *inflight;
	struct inflight **inflights;
	struct bitcoin_txid txid;

	hsmfd = hsm_get_client_fd(ld, &channel->peer->id,
				  channel->dbid,
				  HSM_CAP_SIGN_GOSSIP
				  | HSM_CAP_ECDH
				  | HSM_CAP_COMMITMENT_POINT
				  | HSM_CAP_SIGN_REMOTE_TX
				  | HSM_CAP_SIGN_ONCHAIN_TX
				  | HSM_CAP_SIGN_CLOSING_TX);

	channel_set_owner(channel,
			  new_channel_subd(channel, ld,
					   "lightning_channeld",
					   channel,
					   &channel->peer->id,
					   channel->log, true,
					   channeld_wire_name,
					   channel_msg,
					   channel_errmsg,
					   channel_set_billboard,
					   take(&peer_fd->fd),
					   take(&hsmfd), NULL));

	if (!channel->owner) {
		log_broken(channel->log, "Could not subdaemon channel: %s",
			   strerror(errno));
		/* Disconnect it. */
		subd_send_msg(ld->connectd,
			      take(towire_connectd_discard_peer(NULL, &channel->peer->id,
								channel->peer->connectd_counter)));
		return false;
	}

	htlcs = peer_htlcs(tmpctx, channel);

	if (channel->scid) {
		scid = *channel->scid;
		reached_announce_depth
			= is_scid_depth_announceable(&scid,
						     get_block_height(ld->topology));
		log_debug(channel->log, "Already have funding locked in%s",
			  reached_announce_depth
			  ? " (and ready to announce)" : "");
	} else {
		log_debug(channel->log, "Waiting for funding confirmations");
		memset(&scid, 0, sizeof(scid));
		reached_announce_depth = false;
	}

	num_revocations = revocations_received(&channel->their_shachain.chain);

	/* BOLT #2:
	 *     - if `next_revocation_number` equals 0:
	 *       - MUST set `your_last_per_commitment_secret` to all zeroes
	 *     - otherwise:
	 *       - MUST set `your_last_per_commitment_secret` to the last
	 *         `per_commitment_secret` it received
	 */
	if (num_revocations == 0)
		memset(&last_remote_per_commit_secret, 0,
		       sizeof(last_remote_per_commit_secret));
	else if (!shachain_get_secret(&channel->their_shachain.chain,
				      num_revocations-1,
				      &last_remote_per_commit_secret)) {
		channel_fail_permanent(channel,
				       REASON_LOCAL,
				       "Could not get revocation secret %"PRIu64,
				       num_revocations-1);
		return false;
	}

	/* Warn once. */
	if (channel->ignore_fee_limits || ld->config.ignore_fee_limits)
		log_unusual(channel->log, "Ignoring fee limits!");

	if (!wallet_remote_ann_sigs_load(tmpctx, channel->peer->ld->wallet,
					 channel->dbid,
					 &remote_ann_node_sig,
					 &remote_ann_bitcoin_sig)) {
		channel_internal_error(channel,
				       "Could not load remote announcement"
				       " signatures");
		return false;
	}

	pbases = wallet_penalty_base_load_for_channel(
	    tmpctx, channel->peer->ld->wallet, channel->dbid);

	struct ext_key final_ext_key;
	if (bip32_key_from_parent(
		    ld->bip32_base,
		    channel->final_key_idx,
		    BIP32_FLAG_KEY_PUBLIC,
		    &final_ext_key) != WALLY_OK) {
		channel_internal_error(channel,
				       "Could not derive final_ext_key %"PRIu64,
				       channel->final_key_idx);
		return false;
	}

	/* For anchors, we just need the commitment tx to relay. */
	if (channel_type_has_anchors(channel->type))
		min_feerate = get_feerate_floor(ld->topology);
	else
		min_feerate = feerate_min(ld, NULL);
	max_feerate = feerate_max(ld, NULL);

	if (channel->ignore_fee_limits || ld->config.ignore_fee_limits) {
		min_feerate = 1;
		max_feerate = 0xFFFFFFFF;
	}

	inflights = tal_arr(tmpctx, struct inflight *, 0);
	list_for_each(&channel->inflights, inflight, list) {
		struct inflight *infcopy = tal(inflights, struct inflight);

		infcopy->outpoint = inflight->funding->outpoint;
		infcopy->amnt = inflight->funding->total_funds;
		infcopy->splice_amnt = inflight->funding->splice_amnt;
		infcopy->last_tx = tal_dup(infcopy, struct bitcoin_tx, inflight->last_tx);
		infcopy->last_sig = inflight->last_sig;
		infcopy->i_am_initiator = inflight->i_am_initiator;
		tal_wally_start();
		wally_psbt_clone_alloc(inflight->funding_psbt, 0, &infcopy->psbt);
		tal_wally_end_onto(infcopy, infcopy->psbt, struct wally_psbt);
		tal_arr_expand(&inflights, infcopy);
	}

	initmsg = towire_channeld_init(tmpctx,
				       chainparams,
				       ld->our_features,
				       &channel->cid,
				       &channel->funding,
				       channel->funding_sats,
				       channel->minimum_depth,
				       get_block_height(ld->topology),
				       channel->blockheight_states,
				       channel->lease_expiry,
				       &channel->our_config,
				       &channel->channel_info.their_config,
				       channel->fee_states,
				       min_feerate,
				       max_feerate,
				       penalty_feerate(ld->topology),
				       &channel->last_sig,
				       &channel->channel_info.remote_fundingkey,
				       &channel->channel_info.theirbase,
				       &channel->channel_info.remote_per_commit,
				       &channel->channel_info.old_remote_per_commit,
				       channel->opener,
				       channel->feerate_base,
				       channel->feerate_ppm,
				       channel->htlc_minimum_msat,
				       channel->htlc_maximum_msat,
				       channel->our_msat,
				       &channel->local_basepoints,
				       &channel->local_funding_pubkey,
				       &ld->id,
				       &channel->peer->id,
				       cfg->commit_time_ms,
				       cfg->cltv_expiry_delta,
				       channel->last_was_revoke,
				       channel->last_sent_commit,
				       channel->next_index[LOCAL],
				       channel->next_index[REMOTE],
				       num_revocations,
				       channel->next_htlc_id,
				       htlcs,
				       channel->scid != NULL,
				       channel->remote_channel_ready,
				       &scid,
				       reconnected,
				       /* Anything that indicates we are or have
					* shut down */
				       channel->state == CHANNELD_SHUTTING_DOWN
				       || channel->state == CLOSINGD_SIGEXCHANGE
				       || channel_closed(channel),
				       channel->shutdown_scriptpubkey[REMOTE] != NULL,
				       channel->final_key_idx,
				       &final_ext_key,
				       channel->shutdown_scriptpubkey[LOCAL],
				       channel->channel_flags,
				       fwd_msg,
				       reached_announce_depth,
				       &last_remote_per_commit_secret,
				       channel->peer->their_features,
				       channel->remote_upfront_shutdown_script,
				       remote_ann_node_sig,
				       remote_ann_bitcoin_sig,
				       channel->type,
				       IFDEV(ld->dev_fast_gossip, false),
				       IFDEV(ld->dev_disable_commit == -1
					     ? NULL
					     : (u32 *)&ld->dev_disable_commit,
					     NULL),
				       pbases,
				       reestablish_only,
				       channel->channel_update,
				       ld->experimental_upgrade_protocol,
				       cast_const2(const struct inflight **,
				       		   inflights));

	/* We don't expect a response: we are triggered by funding_depth_cb. */
	subd_send_msg(channel->owner, take(initmsg));

	/* On restart, feerate and blockheight
	 * might not be what we expect: adjust now. */
	if (channel->opener == LOCAL) {
		try_update_feerates(ld, channel);
		try_update_blockheight(ld, channel,
				       get_block_height(ld->topology));
	}

	/* FIXME: DTODO: Use a pointer to a txid instead of zero'ing one out. */
	memset(&txid, 0, sizeof(txid));

	/* Artificial confirmation event for zeroconf */
	subd_send_msg(channel->owner,
		      take(towire_channeld_funding_depth(
			   NULL, channel->scid, channel->alias[LOCAL], 0, false,
			   &txid)));
	return true;
}

bool channel_tell_depth(struct lightningd *ld,
			struct channel *channel,
			const struct bitcoin_txid *txid,
			u32 depth)
{
	const char *txidstr;
	struct txlocator *loc;
	u32 outnum;

	txidstr = type_to_string(tmpctx, struct bitcoin_txid, txid);
	channel->depth = depth;

	if (!channel->owner) {
		log_debug(channel->log,
			  "Funding tx %s confirmed, but peer disconnected",
			  txidstr);
		return false;
	}

	if (channel->state == CHANNELD_AWAITING_SPLICE
	    && depth >= channel->minimum_depth) {
		if (!get_inflight_outpoint_index(channel, txid, &outnum)) {
			log_debug(channel->log, "Can't locate splice inflight"
				  " txid %s", txidstr);
			return false;
		}

		loc = wallet_transaction_locate(tmpctx, ld->wallet, txid);
		if (!loc) {
			channel_fail_permanent(channel,
					       REASON_LOCAL,
					       "Can't locate splice transaction"
					       " in wallet txid %s", txidstr);
			return false;
		}

		if (!mk_short_channel_id(channel->scid,
					 loc->blkheight, loc->index,
					 outnum)) {
			channel_fail_permanent(channel,
					       REASON_LOCAL,
					       "Invalid splice scid %u:%u:%u",
					       loc->blkheight, loc->index,
					       channel->funding.n);
			return false;
		}
	}

	if (streq(channel->owner->name, "dualopend")) {
		if (channel->state != DUALOPEND_AWAITING_LOCKIN) {
			log_debug(channel->log,
				  "Funding tx %s confirmed, but peer in"
				  " state %s",
				  txidstr, channel_state_name(channel));
			return true;
		}

		log_debug(channel->log,
			  "Funding tx %s confirmed, telling peer", txidstr);
		dualopen_tell_depth(channel->owner, channel,
				    txid, depth);
		return true;
	} else if (channel->state != CHANNELD_AWAITING_LOCKIN
	    && !channel_state_normalish(channel)) {
		/* If not awaiting lockin/announce, it doesn't
		 * care any more */
		log_debug(channel->log,
			  "Funding tx %s confirmed, but peer in state %s",
			  txidstr, channel_state_name(channel));
		return true;
	}

	log_debug(channel->log,
		  "Sending towire_channeld_funding_depth with channel state %s",
		  channel_state_str(channel->state));

	subd_send_msg(channel->owner,
		      take(towire_channeld_funding_depth(
			  NULL, channel->scid, channel->alias[LOCAL], depth,
			  channel->state == CHANNELD_AWAITING_SPLICE, txid)));

	if (channel->remote_channel_ready &&
	    channel->state == CHANNELD_AWAITING_LOCKIN &&
	    depth >= channel->minimum_depth) {
		lockin_complete(channel, CHANNELD_AWAITING_LOCKIN);
	} else if (depth == 1 && channel->minimum_depth == 0) {
		/* If we have a zeroconf channel, i.e., no scid yet
		 * but have exchange `channel_ready` messages, then we
		 * need to fire a second time, in order to trigger the
		 * `coin_movement` event. This is a subset of the
		 * `lockin_complete` function below. */

		assert(channel->scid != NULL);
		/* Fees might have changed (and we use IMMEDIATE once we're
		 * funded), so update now. */
		try_update_feerates(channel->peer->ld, channel);

		try_update_blockheight(
		    channel->peer->ld, channel,
		    get_block_height(channel->peer->ld->topology));

		/* Emit channel_open event */
		channel_record_open(channel,
				    short_channel_id_blocknum(channel->scid),
				    false);
	}
	return true;
}

/* Check if we are the fundee of this channel, the channel
 * funding transaction is still not yet seen onchain, and
 * it has been too long since the channel was first opened.
 * If so, we should forget the channel. */
static bool
is_fundee_should_forget(struct lightningd *ld,
			struct channel *channel,
			u32 block_height)
{
	/* BOLT #2:
	 *
	 * A non-funding node (fundee):
	 *   - SHOULD forget the channel if it does not see the
	 * correct funding transaction after a timeout of 2016 blocks.
	 */
	u32 max_funding_unconfirmed = IFDEV(ld->dev_max_funding_unconfirmed, 2016);

	/* Only applies if we are fundee. */
	if (channel->opener == LOCAL)
		return false;

	/* Does not apply if we already saw the funding tx. */
	if (channel->scid)
		return false;

	/* Not even reached previous starting blocknum.
	 * (e.g. if --rescan option is used) */
	if (block_height < channel->first_blocknum)
		return false;

	/* Timeout in blocks not yet reached. */
	if (block_height - channel->first_blocknum < max_funding_unconfirmed)
		return false;

	/* If we've got funds in the channel, don't forget it */
	if (!amount_sat_zero(channel->our_funds))
		return false;

	/* Ah forget it! */
	return true;
}

/* Notify all channels of new blocks. */
void channel_notify_new_block(struct lightningd *ld,
			      u32 block_height)
{
	struct peer *peer;
	struct channel *channel;
	struct channel **to_forget = tal_arr(NULL, struct channel *, 0);
	size_t i;
	struct peer_node_id_map_iter it;

	/* FIXME: keep separate block-aware channel structure instead? */
	for (peer = peer_node_id_map_first(ld->peers, &it);
	     peer;
	     peer = peer_node_id_map_next(ld->peers, &it)) {
		list_for_each(&peer->channels, channel, list) {
			if (channel_unsaved(channel))
				continue;
			if (is_fundee_should_forget(ld, channel, block_height)) {
				tal_arr_expand(&to_forget, channel);
			} else
				/* Let channels know about new blocks,
				 * required for lease updates */
				try_update_blockheight(ld, channel,
						       block_height);
		}
	}

	/* Need to forget in a separate loop, else the above
	 * nested loops may crash due to the last channel of
	 * a peer also deleting the peer, making the inner
	 * loop crash.
	 * list_for_each_safe does not work because it is not
	 * just the freeing of the channel that occurs, but the
	 * potential destruction of the peer that invalidates
	 * memory the inner loop is accessing. */
	for (i = 0; i < tal_count(to_forget); ++i) {
		channel = to_forget[i];
		/* Report it first. */
		log_unusual(channel->log,
			    "Forgetting channel: "
			    "It has been %"PRIu32" blocks without the "
			    "funding transaction %s getting deeply "
			    "confirmed. "
			    "We are fundee and can forget channel without "
			    "loss of funds.",
			    block_height - channel->first_blocknum,
			    type_to_string(tmpctx, struct bitcoin_txid,
					   &channel->funding.txid));
		/* FIXME: Send an error packet for this case! */
		/* And forget it. */
		delete_channel(channel);
	}

	tal_free(to_forget);
}

/* Since this could vanish while we're checking with bitcoind, we need to save
 * the details and re-lookup.
 *
 * channel_id *should* be unique, but it can be set by the counterparty, so
 * we cannot rely on that! */
struct channel_to_cancel {
	struct node_id peer;
	struct channel_id cid;
};

static void process_check_funding_broadcast(struct bitcoind *bitcoind,
					    const struct bitcoin_tx_output *txout,
					    void *arg)
{
	struct channel_to_cancel *cc = arg;
	struct peer *peer;
	struct channel *cancel;

	/* Peer could have errored out while we were waiting */
	peer = peer_by_id(bitcoind->ld, &cc->peer);
	if (!peer)
		goto cleanup;
	cancel = find_channel_by_id(peer, &cc->cid);
	if (!cancel)
		goto cleanup;

	if (txout != NULL) {
		for (size_t i = 0; i < tal_count(cancel->forgets); i++)
			was_pending(command_fail(cancel->forgets[i],
				    FUNDING_CANCEL_NOT_SAFE,
				    "The funding transaction has been broadcast, "
				    "please consider `close` or `dev-fail`! "));
		tal_free(cancel->forgets);
		cancel->forgets = tal_arr(cancel, struct command *, 0);
		goto cleanup;
	}

	char *error_reason = "Cancel channel by our RPC "
			     "command before funding "
			     "transaction broadcast.";
	forget_channel(cancel, error_reason);

cleanup:
	tal_free(cc);
	return;
}

struct command_result *cancel_channel_before_broadcast(struct command *cmd,
						       struct peer *peer)
{
	struct channel *cancel_channel;
	struct channel_to_cancel *cc = tal(cmd, struct channel_to_cancel);
	struct channel *channel;

	cc->peer = peer->id;
	cancel_channel = NULL;
	list_for_each(&peer->channels, channel, list) {
		/* After `fundchannel_complete`, channel is in
		 * `CHANNELD_AWAITING_LOCKIN` state.
		 *
		 * TODO: This assumes only one channel at a time
		 * can be in this state, which is true at the
		 * time of this writing, but may change *if* we
		 * ever implement multiple channels per peer.
		 */
		if (channel->state != CHANNELD_AWAITING_LOCKIN)
			continue;
		cancel_channel = channel;
		break;
	}
	if (!cancel_channel)
		return command_fail(cmd, FUNDING_NOTHING_TO_CANCEL,
				    "No channels being opened or "
				    "awaiting lock-in for "
				    "peer_id %s",
				    type_to_string(tmpctx, struct node_id,
						   &peer->id));
	cc->cid = cancel_channel->cid;

	if (cancel_channel->opener == REMOTE)
		return command_fail(cmd, FUNDING_CANCEL_NOT_SAFE,
				    "Cannot cancel channel that was "
				    "initiated by peer");

	/* Check if we broadcast the transaction. (We store the transaction
	 * type into DB before broadcast). */
	if (wallet_transaction_get(tmpctx, cmd->ld->wallet,
				   &cancel_channel->funding.txid))
		return command_fail(cmd, FUNDING_CANCEL_NOT_SAFE,
				    "Has the funding transaction been"
				    " broadcast? Please use `close` or"
				    " `dev-fail` instead.");

	if (channel_has_htlc_out(cancel_channel) ||
	    channel_has_htlc_in(cancel_channel)) {
		return command_fail(cmd, FUNDING_CANCEL_NOT_SAFE,
				    "This channel has HTLCs attached and it"
				    " is not safe to cancel. Has the funding"
				    " transaction been broadcast? Please use"
				    " `close` or `dev-fail` instead.");
	}

	tal_arr_expand(&cancel_channel->forgets, cmd);
	/* Now, cmd will be ended by forget() or process_check_funding_broadcast(),
	 * but in the shutdown case it might be freed first and those crash.  So instead
	 * we make it a child if forgets so it will stay around at least that long! */
	tal_steal(cancel_channel->forgets, cmd);

	/* Check if the transaction is onchain. */
	/* Note: The above check and this check can't completely ensure that
	 * the funding transaction isn't broadcast. We can't know if the funding
	 * is broadcast by external wallet and the transaction hasn't
	 * been onchain. */
	bitcoind_getutxout(cmd->ld->topology->bitcoind,
			   &cancel_channel->funding,
			   process_check_funding_broadcast,
			   /* Freed by callback */
			   tal_steal(NULL, cc));
	return command_still_pending(cmd);
}

void channel_replace_update(struct channel *channel, u8 *update TAKES)
{
	tal_free(channel->channel_update);
	channel->channel_update = tal_dup_talarr(channel, u8, update);

	/* Keep channeld up-to-date */
	if (!channel->owner || !streq(channel->owner->name, "channeld"))
		return;

	subd_send_msg(channel->owner,
		      take(towire_channeld_channel_update(NULL,
							  channel->channel_update)));
}

static struct command_result *param_channel_for_splice(struct command *cmd,
						       const char *name,
						       const char *buffer,
						       const jsmntok_t *tok,
						       struct channel **channel)
{
	struct command_result *result;
	struct channel_id *cid;

	result = param_channel_id(cmd, name, buffer, tok, &cid);

	if (result != NULL)
		return result;

	*channel = channel_by_cid(cmd->ld, cid);
	if (!*channel)
		return command_fail(cmd, SPLICE_UNKNOWN_CHANNEL,
				    "Unknown channel %s",
				    type_to_string(tmpctx, struct channel_id,
						   cid));

	if (!feature_negotiated(cmd->ld->our_features,
			        (*channel)->peer->their_features,
				OPT_SPLICE))
		return command_fail(cmd, SPLICE_NOT_SUPPORTED,
				    "splicing not supported");

	if (!(*channel)->owner)
		return command_fail(cmd, SPLICE_WRONG_OWNER,
				    "Channel is disconnected");

	if (!streq((*channel)->owner->name, "channeld"))
		return command_fail(cmd,
				    SPLICE_WRONG_OWNER,
				    "Channel hasn't finished connecting or in "
				    "abnormal owner state %s",
				    (*channel)->owner->name);

	if ((*channel)->state != CHANNELD_NORMAL)
		return command_fail(cmd,
				    SPLICE_INVALID_CHANNEL_STATE,
				    "Channel needs to be in normal state but "
				    "is in state %s",
				    channel_state_name(*channel));

	return NULL;
}

static void destroy_splice_command(struct splice_command *cc)
{
	list_del(&cc->list);
}

static struct command_result *json_splice_init(struct command *cmd,
					       const char *buffer,
					       const jsmntok_t *obj UNNEEDED,
					       const jsmntok_t *params)
{
	struct channel *channel;
	struct splice_command *cc;
	struct wally_psbt *initialpsbt;
	s64 *relative_amount;
	u32 *feerate_per_kw;
	bool *force_feerate;
	u8 *msg;

	if (!param(cmd, buffer, params,
		  p_req("channel_id", param_channel_for_splice, &channel),
		  p_req("relative_amount", param_s64, &relative_amount),
		  p_opt("initialpsbt", param_psbt, &initialpsbt),
		  p_opt("feerate_per_kw", param_feerate, &feerate_per_kw),
		  p_opt_def("force_feerate", param_bool, &force_feerate, false),
		  NULL))
		return command_param_failed();

	if (!feerate_per_kw) {
		feerate_per_kw = tal(cmd, u32);
		*feerate_per_kw = opening_feerate(cmd->ld->topology);
	}

	if (splice_command_for_chan(cmd->ld, channel))
		return command_fail(cmd,
				    SPLICE_BUSY_ERROR,
				    "Currently waiting on previous splice"
				    " command to finish.");

	if (!initialpsbt)
		initialpsbt = create_psbt(cmd, 0, 0, 0);
	if (!validate_psbt(initialpsbt))
		return command_fail(cmd,
				    SPLICE_INPUT_ERROR,
				    "PSBT failed to validate.");

	log_debug(cmd->ld->log, "splice_init input PSBT version %d",
		  initialpsbt->version);

	cc = tal(cmd, struct splice_command);

	list_add_tail(&cmd->ld->splice_commands, &cc->list);
	tal_add_destructor(cc, destroy_splice_command);

	cc->cmd = cmd;
	cc->channel = channel;

	msg = towire_channeld_splice_init(NULL, initialpsbt, *relative_amount,
					  *feerate_per_kw, *force_feerate);

	subd_send_msg(channel->owner, take(msg));
	return command_still_pending(cmd);
}

static struct command_result *json_splice_update(struct command *cmd,
						 const char *buffer,
						 const jsmntok_t *obj UNNEEDED,
						 const jsmntok_t *params)
{
	struct channel *channel;
	struct splice_command *cc;
	struct wally_psbt *psbt;

	if (!param(cmd, buffer, params,
		  p_req("channel_id", param_channel_for_splice, &channel),
		  p_req("psbt", param_psbt, &psbt),
		  NULL))
		return command_param_failed();

	if (splice_command_for_chan(cmd->ld, channel))
		return command_fail(cmd,
				    SPLICE_BUSY_ERROR,
				    "Currently waiting on previous splice"
				    " command to finish.");
	if (!validate_psbt(psbt))
		return command_fail(cmd,
				    SPLICE_INPUT_ERROR,
				    "PSBT failed to validate.");

	log_debug(cmd->ld->log, "splice_update input PSBT version %d",
		  psbt->version);

	cc = tal(cmd, struct splice_command);

	list_add_tail(&cmd->ld->splice_commands, &cc->list);
	tal_add_destructor(cc, destroy_splice_command);

	cc->cmd = cmd;
	cc->channel = channel;

	subd_send_msg(channel->owner,
		      take(towire_channeld_splice_update(NULL, psbt)));
	return command_still_pending(cmd);
}

static struct command_result *json_splice_signed(struct command *cmd,
						 const char *buffer,
						 const jsmntok_t *obj UNNEEDED,
						 const jsmntok_t *params)
{
	u8 *msg;
	struct channel *channel;
	struct splice_command *cc;
	struct wally_psbt *psbt;
	bool *sign_first;

	if (!param(cmd, buffer, params,
		  p_req("channel_id", param_channel_for_splice, &channel),
		  p_req("psbt", param_psbt, &psbt),
		  p_opt_def("sign_first", param_bool, &sign_first, false),
		  NULL))
		return command_param_failed();

	if (splice_command_for_chan(cmd->ld, channel))
		return command_fail(cmd,
				    SPLICE_BUSY_ERROR,
				    "Currently waiting on previous splice"
				    " command to finish.");
	if (!validate_psbt(psbt))
		return command_fail(cmd,
				    SPLICE_INPUT_ERROR,
				    "PSBT failed to validate.");

	log_debug(cmd->ld->log, "splice_signed input PSBT version %d",
		  psbt->version);

	cc = tal(cmd, struct splice_command);

	list_add_tail(&cmd->ld->splice_commands, &cc->list);
	tal_add_destructor(cc, destroy_splice_command);

	cc->cmd = cmd;
	cc->channel = channel;

	msg = towire_channeld_splice_signed(tmpctx, psbt, *sign_first);
	subd_send_msg(channel->owner, take(msg));
	return command_still_pending(cmd);
}

static const struct json_command splice_init_command = {
	"splice_init",
	"channels",
	json_splice_init,
	"Init a channel splice to {channel_id} for {relative_amount} satoshis with {initialpsbt}. "
	"Returns updated {psbt} with (partial) contributions from peer"
};
AUTODATA(json_command, &splice_init_command);

static const struct json_command splice_update_command = {
	"splice_update",
	"channels",
	json_splice_update,
	"Update {channel_id} currently active negotiated splice with {psbt}. "
	""
	"Returns updated {psbt} with (partial) contributions from peer. "
	"If {commitments_secured} is true, next call may be to splicechannel_finalize, "
	"otherwise keep calling splice_update passing back in the returned PSBT until "
	"{commitments_secured} is true."
};
AUTODATA(json_command, &splice_update_command);

static const struct json_command splice_signed_command = {
	"splice_signed",
	"channels",
	json_splice_signed,
	"Send our {signed_psbt}'s tx sigs for {channel_id}."
};
AUTODATA(json_command, &splice_signed_command);

#if DEVELOPER
static struct command_result *json_dev_feerate(struct command *cmd,
					       const char *buffer,
					       const jsmntok_t *obj UNNEEDED,
					       const jsmntok_t *params)
{
	u32 *feerate;
	struct node_id *id;
	struct peer *peer;
	struct json_stream *response;
	struct channel *channel;
	const u8 *msg;
	bool more_than_one;

	if (!param(cmd, buffer, params,
		   p_req("id", param_node_id, &id),
		   p_req("feerate", param_number, &feerate),
		   NULL))
		return command_param_failed();

	peer = peer_by_id(cmd->ld, id);
	if (!peer)
		return command_fail(cmd, LIGHTNINGD, "Peer not connected");

	channel = peer_any_active_channel(peer, &more_than_one);
	if (!channel || !channel->owner || !channel_state_normalish(channel))
		return command_fail(cmd, LIGHTNINGD, "Peer bad state");
	/* This is a dev command: fix the api if you need this! */
	if (more_than_one)
		return command_fail(cmd, LIGHTNINGD, "More than one channel");

	msg = towire_channeld_feerates(NULL, *feerate,
				       feerate_min(cmd->ld, NULL),
				       feerate_max(cmd->ld, NULL),
				       penalty_feerate(cmd->ld->topology));
	subd_send_msg(channel->owner, take(msg));

	response = json_stream_success(cmd);
	json_add_node_id(response, "id", id);
	json_add_u32(response, "feerate", *feerate);

	return command_success(cmd, response);
}

static const struct json_command dev_feerate_command = {
	"dev-feerate",
	"developer",
	json_dev_feerate,
	"Set feerate for {id} to {feerate}"
};
AUTODATA(json_command, &dev_feerate_command);

static void quiesce_reply(struct subd *channeld UNUSED,
			  const u8 *reply,
			  const int *fds UNUSED,
			  struct command *cmd)
{
	struct json_stream *response;

	response = json_stream_success(cmd);
	was_pending(command_success(cmd, response));
}

static struct command_result *json_dev_quiesce(struct command *cmd,
					       const char *buffer,
					       const jsmntok_t *obj UNNEEDED,
					       const jsmntok_t *params)
{
	struct node_id *id;
	struct peer *peer;
	struct channel *channel;
	const u8 *msg;
	bool more_than_one;

	if (!param(cmd, buffer, params,
		   p_req("id", param_node_id, &id),
		   NULL))
		return command_param_failed();

	peer = peer_by_id(cmd->ld, id);
	if (!peer)
		return command_fail(cmd, LIGHTNINGD, "Peer not connected");

	/* FIXME: If this becomes a real API, check for OPT_QUIESCE! */
	channel = peer_any_active_channel(peer, &more_than_one);
	if (!channel || !channel->owner || !channel_state_normalish(channel))
		return command_fail(cmd, LIGHTNINGD, "Peer bad state");
	/* This is a dev command: fix the api if you need this! */
	if (more_than_one)
		return command_fail(cmd, LIGHTNINGD, "More than one channel");

	msg = towire_channeld_dev_quiesce(NULL);
	subd_req(channel->owner, channel->owner, take(msg), -1, 0,
		 quiesce_reply, cmd);
	return command_still_pending(cmd);
}

static const struct json_command dev_quiesce_command = {
	"dev-quiesce",
	"developer",
	json_dev_quiesce,
	"Initiate quiscence protocol with peer"
};
AUTODATA(json_command, &dev_quiesce_command);
#endif /* DEVELOPER */
