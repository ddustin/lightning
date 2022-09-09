#include "config.h"
#include "interactivetx.h"
#include <bitcoin/chainparams.h>
#include <bitcoin/script.h>
#include <bitcoin/psbt.h>
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/billboard.h>
#include <common/blockheight_states.h>
#include <common/channel_type.h>
#include <common/gossip_rcvd_filter.h>
#include <common/gossip_store.h>
#include <common/initial_channel.h>
#include <common/lease_rates.h>
#include <common/memleak.h>
#include <common/peer_billboard.h>
#include <common/peer_failed.h>
#include <common/psbt_internal.h>
#include <common/psbt_open.h>
#include <common/read_peer_msg.h>
#include <common/setup.h>
#include <common/status.h>
#include <common/subdaemon.h>
#include <common/type_to_string.h>
#include <common/wire_error.h>
#include <common/peer_io.h>
#include <common/per_peer_state.h>

#include <fcntl.h>
#include <unistd.h>

/* tx_add_input, tx_add_output, tx_rm_input, tx_rm_output */
#define NUM_TX_MSGS (TX_RM_OUTPUT + 1)
enum tx_msgs {
	TX_ADD_INPUT,
	TX_ADD_OUTPUT,
	TX_RM_INPUT,
	TX_RM_OUTPUT,
};

/*
 * BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
 * The maximum inputs and outputs are capped at 252. This effectively fixes
 * the byte size of the input and output counts on the transaction to one (1).
 */
#define MAX_TX_MSG_RCVD (1 << 12)

static bool is_segwit_output(struct wally_tx_output *output,
			     const u8 *redeemscript)
{
	const u8 *wit_prog;
	if (tal_bytelen(redeemscript) > 0)
		wit_prog = redeemscript;
	else
		wit_prog = wally_tx_output_get_script(tmpctx, output);

	return is_p2wsh(wit_prog, NULL) || is_p2wpkh(wit_prog, NULL);
}

/* Return first non-handled message or NULL if connection is aborted */
static u8 *read_next_msg(const tal_t *ctx, struct interactivetx_context *state, char **error)
{
	for (;;) {
		u8 *msg;
		char *err;
		bool warning;
		struct channel_id actual;
		enum peer_wire t;

		/* The event loop is responsible for freeing tmpctx, so our
		 * temporary allocations don't grow unbounded. */
		// clean_tmpctx(); // TODO: <- crash here......

		/* This helper routine polls the peer. */
		msg = peer_read(ctx, state->pps);

		/* BOLT #1:
		 *
		 * A receiving node:
		 *   - upon receiving a message of _odd_, unknown type:
		 *     - MUST ignore the received message.
		 */
		if (is_unknown_msg_discardable(msg))
			continue;

		/* A helper which decodes an error. */
		if (is_peer_error(tmpctx, msg, &state->channel_id,
				  &err, &warning)) {
			/* BOLT #1:
			 *
			 *  - if no existing channel is referred to by the
			 *    message:
			 *    - MUST ignore the message.
			 */
			/* In this case, is_peer_error returns true, but sets
			 * err to NULL */
			if (!err) {
				tal_free(msg);
				continue;
			}
			*error = tal_fmt(tmpctx, "They sent %s", err);
			/* Return NULL so caller knows to stop negotiating. */
			return NULL;
		}

		/*~ We do not support multiple "live" channels, though the
		 * protocol has a "channel_id" field in all non-gossip messages
		 * so it's possible.  Our one-process-one-channel mechanism
		 * keeps things simple: if we wanted to change this, we would
		 * probably be best with another daemon to de-multiplex them;
		 * this could be connectd itself, in fact. */
		if (is_wrong_channel(msg, &state->channel_id, &actual)) {
			status_debug("Rejecting %s for unknown channel_id %s",
				     peer_wire_name(fromwire_peektype(msg)),
				     type_to_string(tmpctx, struct channel_id,
						    &actual));
			peer_write(state->pps,
				   take(towire_errorfmt(NULL, &actual,
							"Multiple channels"
							" unsupported")));
			tal_free(msg);
			continue;
		}

		/* In theory, we're in the middle of an open/RBF, but
		 * it's possible we can get some different messages in
		 * the meantime! */
		t = fromwire_peektype(msg);
		switch (t) {
		case WIRE_TX_ADD_INPUT:
		case WIRE_TX_REMOVE_INPUT:
		case WIRE_TX_ADD_OUTPUT:
		case WIRE_TX_REMOVE_OUTPUT:
		case WIRE_TX_COMPLETE:
			return msg;
		case WIRE_TX_SIGNATURES:
		case WIRE_FUNDING_LOCKED:
		case WIRE_INIT_RBF:
		case WIRE_OPEN_CHANNEL2:
		case WIRE_INIT:
		case WIRE_ERROR:
		case WIRE_OPEN_CHANNEL:
		case WIRE_ACCEPT_CHANNEL:
		case WIRE_FUNDING_CREATED:
		case WIRE_FUNDING_SIGNED:
		case WIRE_CLOSING_SIGNED:
		case WIRE_UPDATE_ADD_HTLC:
		case WIRE_UPDATE_FULFILL_HTLC:
		case WIRE_UPDATE_FAIL_HTLC:
		case WIRE_UPDATE_FAIL_MALFORMED_HTLC:
		case WIRE_COMMITMENT_SIGNED:
		case WIRE_REVOKE_AND_ACK:
		case WIRE_UPDATE_FEE:
		case WIRE_UPDATE_BLOCKHEIGHT:
		case WIRE_CHANNEL_REESTABLISH:
		case WIRE_ANNOUNCEMENT_SIGNATURES:
		case WIRE_GOSSIP_TIMESTAMP_FILTER:
		case WIRE_OBS2_ONION_MESSAGE:
		case WIRE_ONION_MESSAGE:
		case WIRE_ACCEPT_CHANNEL2:
		case WIRE_ACK_RBF:
		case WIRE_CHANNEL_ANNOUNCEMENT:
		case WIRE_CHANNEL_UPDATE:
		case WIRE_NODE_ANNOUNCEMENT:
		case WIRE_QUERY_CHANNEL_RANGE:
		case WIRE_REPLY_CHANNEL_RANGE:
		case WIRE_QUERY_SHORT_CHANNEL_IDS:
		case WIRE_REPLY_SHORT_CHANNEL_IDS_END:
		case WIRE_WARNING:
		case WIRE_PING:
		case WIRE_PONG:
		case WIRE_SHUTDOWN:
		case WIRE_SPLICE:
		case WIRE_SPLICE_ACK:
#if EXPERIMENTAL_FEATURES
		case WIRE_STFU:
#endif
		*error = tal_fmt(tmpctx, "Received invalid message from peer: %d", t);
		return NULL;
		}
	}

	return NULL;
}

static char *send_next(struct interactivetx_context *ictx, bool *finished)
{
	struct channel_id *cid = &ictx->channel_id;
	u64 serial_id;
	u8 *msg;

	*finished = false;

	/* Go ask Alice for changes, I think she'll know. */
	struct wally_psbt *next_psbt = ictx->next_update(ictx);

	if(!next_psbt)
		goto tx_complete;

	struct psbt_changeset *set = psbt_get_changeset(tmpctx,
							ictx->current_psbt,
							next_psbt);

	if (tal_count(set->added_ins) != 0) {

		const struct input_set *in = &set->added_ins[0];
		struct wally_psbt_input *localin;
		struct amount_sat sats;
		u8 *outpointScript;
		u8 *script;

		if (!psbt_get_serial_id(&in->input.unknowns, &serial_id))
			abort();

		u8 *prevtx = NULL;

		//D We dont have the input utxo here...
		//  thats causing problems...
		if(in->input.utxo) {

			prevtx = linearize_wtx(tmpctx,
				      in->input.utxo);
		}
		else {

			//D TODO prevtx = LOADME

			/* FIXME: For now we jam the txid into where the prevtx goes */
			prevtx = tal_dup_arr(tmpctx, u8, in->tx_input.txhash,
					     WALLY_TXHASH_LEN, 0);

			//FIXME: for now we stuff amount and script onto the end

			tal_resize(&prevtx, WALLY_TXHASH_LEN + 8 + in->input.witness_utxo->script_len);

			*(u64*)&prevtx[WALLY_TXHASH_LEN] = in->input.witness_utxo->satoshi;

			memcpy(prevtx + WALLY_TXHASH_LEN + 8,
			       in->input.witness_utxo->script,
			       in->input.witness_utxo->script_len);
		}

		if (in->input.redeem_script_len) {

			script = tal_dup_arr(tmpctx, u8,
					     in->input.redeem_script,
					     in->input.redeem_script_len, 0);
		}
		else
			script = NULL;

		msg = towire_tx_add_input(tmpctx, cid, serial_id,
					  prevtx, in->tx_input.index,
					  in->tx_input.sequence,
					  script);

		//D TODO: apply "psbt_changeset *set" to current_psbt and repeat
		// for the 3 other modes below

		struct bitcoin_outpoint outpoint;

		outpoint.n = in->tx_input.index;

		memcpy(outpoint.txid.shad.sha.u.u8, in->tx_input.txhash, WALLY_TXHASH_LEN);

		localin = psbt_append_input(ictx->current_psbt, &outpoint,
					    in->tx_input.sequence, NULL,
					    NULL,
					    script);

		outpointScript = tal_dup_arr(tmpctx, u8,
					     in->input.witness_utxo->script,
					     in->input.witness_utxo->script_len, 0);

		sats.satoshis = in->input.witness_utxo->satoshi;

		psbt_input_set_wit_utxo(ictx->current_psbt,
					ictx->current_psbt->num_inputs - 1,
					outpointScript,
					sats);

		psbt_input_set_serial_id(tmpctx, localin, serial_id);
		
	}
	else if (tal_count(set->rm_ins) != 0) {

		if (!psbt_get_serial_id(&set->rm_ins[0].input.unknowns,
					&serial_id))
			abort();

		msg = towire_tx_remove_input(tmpctx, cid, serial_id);

		//D TODO: psbt_remove_input
	}
	else if (tal_count(set->added_outs) != 0) {

		struct amount_sat sats;
		struct amount_asset asset_amt;
		struct wally_psbt_output *local_out;

		const struct output_set *out = &set->added_outs[0];
		if (!psbt_get_serial_id(&out->output.unknowns, &serial_id))
			abort();

		asset_amt = wally_tx_output_get_amount(&out->tx_output);
		sats = amount_asset_to_sat(&asset_amt);
		const u8 *script = wally_tx_output_get_script(tmpctx,
							      &out->tx_output);

		msg = towire_tx_add_output(tmpctx, cid, serial_id,
					   sats.satoshis, /* Raw: wire interface */
					   script);

		local_out = psbt_append_output(ictx->current_psbt, script, sats);
		psbt_output_set_serial_id(ictx->current_psbt, local_out, serial_id);
	}
	else if (tal_count(set->rm_outs) != 0) {

		if (!psbt_get_serial_id(&set->rm_outs[0].output.unknowns,
					&serial_id))
			abort();

		msg = towire_tx_remove_output(tmpctx, cid, serial_id);

		//D TODO: psbt_remove_output
	}
	else { /* no changes to psbt */

		assert(!psbt_contribs_changed(ictx->current_psbt, next_psbt));

		goto tx_complete;
	}

	if(msg) {

		peer_write(ictx->pps, msg);
		return NULL;
	}

	return "Interactivetx::send_next should not get here.";

tx_complete:

	*finished = true;

	msg = towire_tx_complete(tmpctx, cid);
	peer_write(ictx->pps, msg);

	return NULL;
}

char *process_interactivetx_updates(struct interactivetx_context *ictx)
{
	assert(NUM_TX_MSGS == INTERACTIVETX_NUM_TX_MSGS);

	if(ictx->current_psbt == NULL)
		ictx->current_psbt = create_psbt(tmpctx, 0, 0, 0);

	/* Opener always sends the first utxo info */
	bool we_complete = false, they_complete = false;
	u8 *msg;
	char *error = NULL;

	if(ictx->our_role == TX_INITIATOR) {

		char *error = send_next(ictx, &we_complete);

		if(error)
			return error;
	}

	while (!(we_complete && they_complete)) {
		struct channel_id cid;
		enum peer_wire t;
		u64 serial_id;

		/* Reset their_complete to false every round,
		 * they have to re-affirm every time  */
		they_complete = false;

		msg = read_next_msg(tmpctx, ictx, &error);

		if(error)
			return error;

		if (!msg)
			return "Interactivetx::read_next_msg failed with no error";

		t = fromwire_peektype(msg);
		switch (t) {
		case WIRE_TX_ADD_INPUT: {
			const u8 *tx_bytes, *redeemscript;
			u32 sequence;
			size_t len_unused;
			struct bitcoin_tx *tx_unused;
			struct bitcoin_outpoint outpoint;
			struct amount_sat amt;
			u8 *outpointScript;

			//D TODO: Use these variables again.
			(void)len_unused;
			(void)tx_unused;
			(void)is_segwit_output;

			if (!fromwire_tx_add_input(tmpctx, msg, &cid,
						   &serial_id,
						   cast_const2(u8 **,
							       &tx_bytes),
						   &outpoint.n, &sequence,
						   cast_const2(u8 **,
							       &redeemscript)))
				return tal_fmt(tmpctx,
					       "Parsing tx_add_input %s",
					       tal_hex(tmpctx, msg));

			/* FIXME: For now we stuff the funding txid into tx_bytes */

			memcpy(outpoint.txid.shad.sha.u.u8, tx_bytes, WALLY_TXHASH_LEN);
			
			amt.satoshis = *(u64*)&tx_bytes[WALLY_TXHASH_LEN];

			int prefixlen = WALLY_TXHASH_LEN + 8;

			outpointScript = tal_dup_arr(tmpctx,
						     u8,
						     tx_bytes + prefixlen,
						     tal_count(tx_bytes) - prefixlen,
						     0);

			/*
			 * BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node: ...
			 *   - MUST fail the negotiation if: ...
			 *   - if has received 4096 `tx_add_input`
			 *   messages during this negotiation
			 */
			if (++ictx->tx_msg_count[TX_ADD_INPUT] > MAX_TX_MSG_RCVD)
				return tal_fmt(tmpctx, "Too many `tx_add_input`s"
					       " received %d", MAX_TX_MSG_RCVD);
			/*
			 * BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node: ...
			 *   - MUST fail the negotiation if: ...
			 *   - the `serial_id` has the wrong parity
			 */
			if (serial_id % 2 == ictx->our_role)
				return tal_fmt(tmpctx,
					       "Invalid serial_id rcvd. %"PRIu64,
					       serial_id);
			/*
			 * BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node: ...
			 *   - MUST fail the negotiation if: ...
			 *   - the `serial_id` is already included in
			 *   the transaction
			 */
			if (psbt_find_serial_input(ictx->current_psbt, serial_id) != -1)
				return tal_fmt(tmpctx, "Duplicate serial_id rcvd."
					       " %"PRIu64, serial_id);

			// TODO: add back these checks

			/* Convert tx_bytes to a tx! */
			// len = tal_bytelen(tx_bytes);
			// tx = pull_bitcoin_tx(tmpctx, &tx_bytes, &len);

			// if (!tx || len != 0)
			// 	return tal_fmt(tmpctx, "Invalid tx sent. len: %d", (int)len);

			// if (outpoint.n >= tx->wtx->num_outputs)
			// 	return tal_fmt(tmpctx,
			// 		       "Invalid tx outnum sent. %u",
			// 		       outpoint.n);
			/*
			 * BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node: ...
			 *   - MUST fail the negotiation if: ...
			 *   - the `prevtx_out` input of `prevtx` is
			 *   not an `OP_0` to `OP_16` followed by a single push
			 */
			// if (!is_segwit_output(&tx->wtx->outputs[outpoint.n],
			// 		      redeemscript))
			// 	return tal_fmt(tmpctx,
			// 		       "Invalid tx sent. Not SegWit %s",
			// 		       type_to_string(tmpctx,
			// 				      struct bitcoin_tx,
			// 				      tx));

			/*
			 * BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 *   The receiving node: ...
			 *    - MUST fail the negotiation if:
			 *    - the `prevtx` and `prevtx_vout` are
			 *    identical to a previously added (and not
			 *    removed) input's
			 */
			// bitcoin_txid(tx, &outpoint.txid);
			// if (psbt_has_input(ictx->current_psbt, &outpoint))
			// 	return tal_fmt(tmpctx,
			// 		       "Unable to add input %s- "
			// 		       "already present",
			// 		       type_to_string(tmpctx,
			// 				      struct bitcoin_outpoint,
			// 				      &outpoint));

			/*
			 * BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node:
			 *  - MUST add all received inputs to the transaction
			 */
			struct wally_psbt_input *in =
				psbt_append_input(ictx->current_psbt, &outpoint,
						  sequence, NULL,
						  NULL,
						  redeemscript);
			if (!in)
				return tal_fmt(tmpctx,
					       "Unable to add input %s",
					       type_to_string(tmpctx,
							      struct bitcoin_outpoint,
							      &outpoint));

			psbt_input_set_wit_utxo(ictx->current_psbt,
						ictx->current_psbt->num_inputs - 1,
						outpointScript,
						amt);

			psbt_input_set_serial_id(ictx->current_psbt, in, serial_id);

			break;
		}
		case WIRE_TX_REMOVE_INPUT: {
			int input_index;

			if (!fromwire_tx_remove_input(msg, &cid, &serial_id))
				return tal_fmt(tmpctx,
					       "Parsing tx_remove_input %s",
					       tal_hex(tmpctx, msg));

			/* BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node:  ...
			 *   - MUST fail the negotiation if: ...
			 *   - the input or output identified by the
			 *   `serial_id` was not added by the sender
			 */
			if (serial_id % 2 == ictx->our_role)
				return tal_fmt(tmpctx,
					       "Invalid serial_id rcvd. %"PRIu64,
					       serial_id);

			/* BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node:  ...
			 *   - MUST fail the negotiation if: ...
			 *   - the `serial_id` does not correspond
			 *     to a currently added input (or output)
			 */
			input_index = psbt_find_serial_input(ictx->current_psbt, serial_id);
			/* We choose to error/fail negotiation */
			if (input_index == -1)
				return tal_fmt(tmpctx,
					       "No input added with serial_id"
					       " %"PRIu64, serial_id);

			psbt_rm_input(ictx->current_psbt, input_index);
			break;
		}
		case WIRE_TX_ADD_OUTPUT: {
			u64 value;
			u8 *scriptpubkey;
			struct wally_psbt_output *out;
			struct amount_sat amt;
			if (!fromwire_tx_add_output(tmpctx, msg, &cid,
						    &serial_id, &value,
						    &scriptpubkey))
				return tal_fmt(tmpctx,
					       "Parsing tx_add_output %s",
					       tal_hex(tmpctx, msg));

			/*
			 * BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node: ...
			 * - MUST fail the negotiation if: ...
			 *   - it has received 4096 `tx_add_output`
			 *   messages during this negotiation
			 */
			if (++ictx->tx_msg_count[TX_ADD_OUTPUT] > MAX_TX_MSG_RCVD)
				return tal_fmt(tmpctx,
					       "Too many `tx_add_output`s"
					       " received (%d)",
					       MAX_TX_MSG_RCVD);

			/* BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node: ...
			 * - MUST fail the negotiation if: ...
			 *   - the `serial_id` has the wrong parity
			 */
			if (serial_id % 2 == ictx->our_role)
				return tal_fmt(tmpctx,
					       "Invalid serial_id rcvd. %"PRIu64,
					       serial_id);

			/* BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node: ...
			 * - MUST fail the negotiation if: ...
			 *   - the `serial_id` is already included
			 *   in the transaction */
			if (psbt_find_serial_output(ictx->current_psbt, serial_id) != -1)
				return tal_fmt(tmpctx,
					       "Duplicate serial_id rcvd."
					       " %"PRIu64, serial_id);
			amt = amount_sat(value);

			/* BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node: ...
			 * - MAY fail the negotiation if `script`
			 *   is non-standard */
			if (!is_known_scripttype(scriptpubkey))
				return tal_fmt(tmpctx, "Script is not standard");

			out = psbt_append_output(ictx->current_psbt, scriptpubkey, amt);
			psbt_output_set_serial_id(ictx->current_psbt, out, serial_id);
			break;
		}
		case WIRE_TX_REMOVE_OUTPUT: {
			int output_index;

			if (!fromwire_tx_remove_output(msg, &cid, &serial_id))
				return tal_fmt(tmpctx,
						 "Parsing tx_remove_output %s",
						 tal_hex(tmpctx, msg));

			/* BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node: ...
			 * - MUST fail the negotiation if: ...
			 *   - the input or output identified by the
			 *   `serial_id` was not added by the sender
			 */
			if (serial_id % 2 == ictx->our_role)
				return tal_fmt(tmpctx,
					       "Invalid serial_id rcvd."
					       " %"PRIu64, serial_id);

			/* BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node: ...
			 * - MUST fail the negotiation if: ...
			 *   - the `serial_id` does not correspond to a
			 *     currently added input (or output)
			 */
			output_index = psbt_find_serial_output(ictx->current_psbt, serial_id);
			if (output_index == -1)
				return tal_fmt(tmpctx,
					       "No output added with serial_id"
					       " %"PRIu64, serial_id);
			psbt_rm_output(ictx->current_psbt, output_index);
			break;
		}
		case WIRE_TX_COMPLETE:
			if (!fromwire_tx_complete(msg, &cid))
				return tal_fmt(tmpctx,
					       "Parsing tx_complete %s",
					       tal_hex(tmpctx, msg));
			they_complete = true;
			break;
		case WIRE_INIT:
		case WIRE_ERROR:
		case WIRE_WARNING:
		case WIRE_OPEN_CHANNEL:
		case WIRE_ACCEPT_CHANNEL:
		case WIRE_FUNDING_CREATED:
		case WIRE_FUNDING_SIGNED:
		case WIRE_FUNDING_LOCKED:
		case WIRE_SHUTDOWN:
		case WIRE_CLOSING_SIGNED:
		case WIRE_UPDATE_ADD_HTLC:
		case WIRE_UPDATE_FULFILL_HTLC:
		case WIRE_UPDATE_FAIL_HTLC:
		case WIRE_UPDATE_FAIL_MALFORMED_HTLC:
		case WIRE_COMMITMENT_SIGNED:
		case WIRE_REVOKE_AND_ACK:
		case WIRE_UPDATE_FEE:
		case WIRE_UPDATE_BLOCKHEIGHT:
		case WIRE_CHANNEL_REESTABLISH:
		case WIRE_ANNOUNCEMENT_SIGNATURES:
		case WIRE_GOSSIP_TIMESTAMP_FILTER:
		case WIRE_OBS2_ONION_MESSAGE:
		case WIRE_ONION_MESSAGE:
		case WIRE_TX_SIGNATURES:
		case WIRE_OPEN_CHANNEL2:
		case WIRE_ACCEPT_CHANNEL2:
		case WIRE_INIT_RBF:
		case WIRE_ACK_RBF:
		case WIRE_CHANNEL_ANNOUNCEMENT:
		case WIRE_CHANNEL_UPDATE:
		case WIRE_NODE_ANNOUNCEMENT:
		case WIRE_QUERY_CHANNEL_RANGE:
		case WIRE_REPLY_CHANNEL_RANGE:
		case WIRE_QUERY_SHORT_CHANNEL_IDS:
		case WIRE_REPLY_SHORT_CHANNEL_IDS_END:
		case WIRE_PING:
		case WIRE_PONG:
		case WIRE_SPLICE:
		case WIRE_SPLICE_ACK:
#if EXPERIMENTAL_FEATURES
		case WIRE_STFU:
#endif
			return tal_fmt(tmpctx, "Unexpected wire message %s",
						 tal_hex(tmpctx, msg));
		}

		if (!(we_complete && they_complete))
			send_next(ictx, &we_complete);
	}

	/* Sort psbt! */
	psbt_sort_by_serial_id(ictx->current_psbt);

	return NULL;
}
