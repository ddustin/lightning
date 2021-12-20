#include "config.h"
int unused_main(int argc, char *argv[]);
#define main unused_main
#include "../gossipd.c"
#undef main
#include <ccan/str/hex/hex.h>
#include <common/blinding.h>
#include <common/channel_type.h>
#include <common/ecdh.h>
#include <common/json_stream.h>
#include <common/onion.h>
#include <common/onionreply.h>
#include <common/setup.h>
#include <secp256k1_ecdh.h>
#include <stdio.h>

#if DEVELOPER
bool dev_suppress_gossip;

/* Generated stub for dev_set_max_scids_encode_size */
void dev_set_max_scids_encode_size(struct daemon *daemon UNNEEDED,
				   const u8 *msg UNNEEDED)
{ fprintf(stderr, "dev_set_max_scids_encode_size called!\n"); abort(); }
/* Generated stub for dump_memleak */
bool dump_memleak(struct htable *memtable UNNEEDED,
		  void  (*print)(const char *fmt UNNEEDED, ...))
{ fprintf(stderr, "dump_memleak called!\n"); abort(); }
/* Generated stub for memleak_status_broken */
void memleak_status_broken(const char *fmt UNNEEDED, ...)
{ fprintf(stderr, "memleak_status_broken called!\n"); abort(); }
#endif

/* AUTOGENERATED MOCKS START */
/* Generated stub for add_to_txout_failures */
void add_to_txout_failures(struct routing_state *rstate UNNEEDED,
			   const struct short_channel_id *scid UNNEEDED)
{ fprintf(stderr, "add_to_txout_failures called!\n"); abort(); }
/* Generated stub for daemon_conn_new_ */
struct daemon_conn *daemon_conn_new_(const tal_t *ctx UNNEEDED, int fd UNNEEDED,
				     struct io_plan *(*recv)(struct io_conn * UNNEEDED,
							     const u8 * UNNEEDED,
							     void *) UNNEEDED,
				     void (*outq_empty)(void *) UNNEEDED,
				     void *arg UNNEEDED)
{ fprintf(stderr, "daemon_conn_new_ called!\n"); abort(); }
/* Generated stub for daemon_conn_read_next */
struct io_plan *daemon_conn_read_next(struct io_conn *conn UNNEEDED,
				      struct daemon_conn *dc UNNEEDED)
{ fprintf(stderr, "daemon_conn_read_next called!\n"); abort(); }
/* Generated stub for daemon_conn_send */
void daemon_conn_send(struct daemon_conn *dc UNNEEDED, const u8 *msg UNNEEDED)
{ fprintf(stderr, "daemon_conn_send called!\n"); abort(); }
/* Generated stub for daemon_conn_send_fd */
void daemon_conn_send_fd(struct daemon_conn *dc UNNEEDED, int fd UNNEEDED)
{ fprintf(stderr, "daemon_conn_send_fd called!\n"); abort(); }
/* Generated stub for daemon_shutdown */
void daemon_shutdown(void)
{ fprintf(stderr, "daemon_shutdown called!\n"); abort(); }
/* Generated stub for ecdh */
void ecdh(const struct pubkey *point UNNEEDED, struct secret *ss UNNEEDED)
{ fprintf(stderr, "ecdh called!\n"); abort(); }
/* Generated stub for ecdh_hsmd_setup */
void ecdh_hsmd_setup(int hsm_fd UNNEEDED,
		     void (*failed)(enum status_failreason UNNEEDED,
				    const char *fmt UNNEEDED, ...))
{ fprintf(stderr, "ecdh_hsmd_setup called!\n"); abort(); }
/* Generated stub for first_chan */
struct chan *first_chan(const struct node *node UNNEEDED, struct chan_map_iter *i UNNEEDED)
{ fprintf(stderr, "first_chan called!\n"); abort(); }
/* Generated stub for fmt_wireaddr_without_port */
char *fmt_wireaddr_without_port(const tal_t *ctx UNNEEDED, const struct wireaddr *a UNNEEDED)
{ fprintf(stderr, "fmt_wireaddr_without_port called!\n"); abort(); }
/* Generated stub for free_chan */
void free_chan(struct routing_state *rstate UNNEEDED, struct chan *chan UNNEEDED)
{ fprintf(stderr, "free_chan called!\n"); abort(); }
/* Generated stub for fromwire_gossipd_addgossip */
bool fromwire_gossipd_addgossip(const tal_t *ctx UNNEEDED, const void *p UNNEEDED, u8 **msg UNNEEDED)
{ fprintf(stderr, "fromwire_gossipd_addgossip called!\n"); abort(); }
/* Generated stub for fromwire_gossipd_dev_set_time */
bool fromwire_gossipd_dev_set_time(const void *p UNNEEDED, u32 *dev_gossip_time UNNEEDED)
{ fprintf(stderr, "fromwire_gossipd_dev_set_time called!\n"); abort(); }
/* Generated stub for fromwire_gossipd_dev_suppress */
bool fromwire_gossipd_dev_suppress(const void *p UNNEEDED)
{ fprintf(stderr, "fromwire_gossipd_dev_suppress called!\n"); abort(); }
/* Generated stub for fromwire_gossipd_get_addrs */
bool fromwire_gossipd_get_addrs(const void *p UNNEEDED, struct node_id *id UNNEEDED)
{ fprintf(stderr, "fromwire_gossipd_get_addrs called!\n"); abort(); }
/* Generated stub for fromwire_gossipd_get_txout_reply */
bool fromwire_gossipd_get_txout_reply(const tal_t *ctx UNNEEDED, const void *p UNNEEDED, struct short_channel_id *short_channel_id UNNEEDED, struct amount_sat *satoshis UNNEEDED, u8 **outscript UNNEEDED)
{ fprintf(stderr, "fromwire_gossipd_get_txout_reply called!\n"); abort(); }
/* Generated stub for fromwire_gossipd_init */
bool fromwire_gossipd_init(const tal_t *ctx UNNEEDED, const void *p UNNEEDED, const struct chainparams **chainparams UNNEEDED, struct feature_set **our_features UNNEEDED, struct node_id *id UNNEEDED, u8 rgb[3] UNNEEDED, u8 alias[32] UNNEEDED, struct wireaddr **announcable UNNEEDED, u32 **dev_gossip_time UNNEEDED, bool *dev_fast_gossip UNNEEDED, bool *dev_fast_gossip_prune UNNEEDED)
{ fprintf(stderr, "fromwire_gossipd_init called!\n"); abort(); }
/* Generated stub for fromwire_gossipd_local_channel_announcement */
bool fromwire_gossipd_local_channel_announcement(const tal_t *ctx UNNEEDED, const void *p UNNEEDED, struct node_id *id UNNEEDED, u8 **cannounce UNNEEDED)
{ fprintf(stderr, "fromwire_gossipd_local_channel_announcement called!\n"); abort(); }
/* Generated stub for fromwire_gossipd_local_channel_close */
bool fromwire_gossipd_local_channel_close(const void *p UNNEEDED, struct short_channel_id *short_channel_id UNNEEDED)
{ fprintf(stderr, "fromwire_gossipd_local_channel_close called!\n"); abort(); }
/* Generated stub for fromwire_gossipd_local_private_channel */
bool fromwire_gossipd_local_private_channel(const tal_t *ctx UNNEEDED, const void *p UNNEEDED, struct node_id *id UNNEEDED, struct amount_sat *capacity UNNEEDED, struct short_channel_id *scid UNNEEDED, u8 **features UNNEEDED)
{ fprintf(stderr, "fromwire_gossipd_local_private_channel called!\n"); abort(); }
/* Generated stub for fromwire_gossipd_new_blockheight */
bool fromwire_gossipd_new_blockheight(const void *p UNNEEDED, u32 *blockheight UNNEEDED)
{ fprintf(stderr, "fromwire_gossipd_new_blockheight called!\n"); abort(); }
/* Generated stub for fromwire_gossipd_new_lease_rates */
bool fromwire_gossipd_new_lease_rates(const void *p UNNEEDED, struct lease_rates *rates UNNEEDED)
{ fprintf(stderr, "fromwire_gossipd_new_lease_rates called!\n"); abort(); }
/* Generated stub for fromwire_gossipd_new_peer */
bool fromwire_gossipd_new_peer(const void *p UNNEEDED, struct node_id *id UNNEEDED, bool *gossip_queries_feature UNNEEDED)
{ fprintf(stderr, "fromwire_gossipd_new_peer called!\n"); abort(); }
/* Generated stub for fromwire_gossipd_outpoint_spent */
bool fromwire_gossipd_outpoint_spent(const void *p UNNEEDED, struct short_channel_id *short_channel_id UNNEEDED)
{ fprintf(stderr, "fromwire_gossipd_outpoint_spent called!\n"); abort(); }
/* Generated stub for fromwire_gossipd_recv_gossip */
bool fromwire_gossipd_recv_gossip(const tal_t *ctx UNNEEDED, const void *p UNNEEDED, struct node_id *id UNNEEDED, u8 **msg UNNEEDED)
{ fprintf(stderr, "fromwire_gossipd_recv_gossip called!\n"); abort(); }
/* Generated stub for fromwire_gossipd_send_onionmsg */
bool fromwire_gossipd_send_onionmsg(const tal_t *ctx UNNEEDED, const void *p UNNEEDED, bool *obs2 UNNEEDED, struct node_id *id UNNEEDED, u8 **onion UNNEEDED, struct pubkey *blinding UNNEEDED)
{ fprintf(stderr, "fromwire_gossipd_send_onionmsg called!\n"); abort(); }
/* Generated stub for fromwire_wireaddr_array */
struct wireaddr *fromwire_wireaddr_array(const tal_t *ctx UNNEEDED, const u8 *ser UNNEEDED)
{ fprintf(stderr, "fromwire_wireaddr_array called!\n"); abort(); }
/* Generated stub for get_node */
struct node *get_node(struct routing_state *rstate UNNEEDED,
		      const struct node_id *id UNNEEDED)
{ fprintf(stderr, "get_node called!\n"); abort(); }
/* Generated stub for gossip_store_compact */
bool gossip_store_compact(struct gossip_store *gs UNNEEDED)
{ fprintf(stderr, "gossip_store_compact called!\n"); abort(); }
/* Generated stub for gossip_store_get */
const u8 *gossip_store_get(const tal_t *ctx UNNEEDED,
			   struct gossip_store *gs UNNEEDED,
			   u64 offset UNNEEDED)
{ fprintf(stderr, "gossip_store_get called!\n"); abort(); }
/* Generated stub for gossip_store_load */
u32 gossip_store_load(struct routing_state *rstate UNNEEDED, struct gossip_store *gs UNNEEDED)
{ fprintf(stderr, "gossip_store_load called!\n"); abort(); }
/* Generated stub for gossip_time_now */
struct timeabs gossip_time_now(const struct routing_state *rstate UNNEEDED)
{ fprintf(stderr, "gossip_time_now called!\n"); abort(); }
/* Generated stub for handle_channel_announcement */
u8 *handle_channel_announcement(struct routing_state *rstate UNNEEDED,
				const u8 *announce TAKES UNNEEDED,
				u32 current_blockheight UNNEEDED,
				const struct short_channel_id **scid UNNEEDED,
				struct peer *peer UNNEEDED)
{ fprintf(stderr, "handle_channel_announcement called!\n"); abort(); }
/* Generated stub for handle_channel_update */
u8 *handle_channel_update(struct routing_state *rstate UNNEEDED, const u8 *update TAKES UNNEEDED,
			  struct peer *peer UNNEEDED,
			  struct short_channel_id *unknown_scid UNNEEDED,
			  bool force UNNEEDED)
{ fprintf(stderr, "handle_channel_update called!\n"); abort(); }
/* Generated stub for handle_local_channel_update */
void handle_local_channel_update(struct daemon *daemon UNNEEDED, const u8 *msg UNNEEDED)
{ fprintf(stderr, "handle_local_channel_update called!\n"); abort(); }
/* Generated stub for handle_node_announcement */
u8 *handle_node_announcement(struct routing_state *rstate UNNEEDED, const u8 *node UNNEEDED,
			     struct peer *peer UNNEEDED, bool *was_unknown UNNEEDED)
{ fprintf(stderr, "handle_node_announcement called!\n"); abort(); }
/* Generated stub for handle_pending_cannouncement */
bool handle_pending_cannouncement(struct daemon *daemon UNNEEDED,
				  struct routing_state *rstate UNNEEDED,
				  const struct short_channel_id *scid UNNEEDED,
				  const struct amount_sat sat UNNEEDED,
				  const u8 *txscript UNNEEDED)
{ fprintf(stderr, "handle_pending_cannouncement called!\n"); abort(); }
/* Generated stub for handle_query_channel_range */
const u8 *handle_query_channel_range(struct peer *peer UNNEEDED, const u8 *msg UNNEEDED)
{ fprintf(stderr, "handle_query_channel_range called!\n"); abort(); }
/* Generated stub for handle_query_short_channel_ids */
const u8 *handle_query_short_channel_ids(struct peer *peer UNNEEDED, const u8 *msg UNNEEDED)
{ fprintf(stderr, "handle_query_short_channel_ids called!\n"); abort(); }
/* Generated stub for handle_reply_channel_range */
const u8 *handle_reply_channel_range(struct peer *peer UNNEEDED, const u8 *msg UNNEEDED)
{ fprintf(stderr, "handle_reply_channel_range called!\n"); abort(); }
/* Generated stub for handle_reply_short_channel_ids_end */
const u8 *handle_reply_short_channel_ids_end(struct peer *peer UNNEEDED, const u8 *msg UNNEEDED)
{ fprintf(stderr, "handle_reply_short_channel_ids_end called!\n"); abort(); }
/* Generated stub for handle_used_local_channel_update */
void handle_used_local_channel_update(struct daemon *daemon UNNEEDED, const u8 *msg UNNEEDED)
{ fprintf(stderr, "handle_used_local_channel_update called!\n"); abort(); }
/* Generated stub for json_add_member */
void json_add_member(struct json_stream *js UNNEEDED,
		     const char *fieldname UNNEEDED,
		     bool quote UNNEEDED,
		     const char *fmt UNNEEDED, ...)
{ fprintf(stderr, "json_add_member called!\n"); abort(); }
/* Generated stub for json_member_direct */
char *json_member_direct(struct json_stream *js UNNEEDED,
			 const char *fieldname UNNEEDED, size_t extra UNNEEDED)
{ fprintf(stderr, "json_member_direct called!\n"); abort(); }
/* Generated stub for json_object_end */
void json_object_end(struct json_stream *js UNNEEDED)
{ fprintf(stderr, "json_object_end called!\n"); abort(); }
/* Generated stub for json_object_start */
void json_object_start(struct json_stream *ks UNNEEDED, const char *fieldname UNNEEDED)
{ fprintf(stderr, "json_object_start called!\n"); abort(); }
/* Generated stub for local_disable_chan */
void local_disable_chan(struct daemon *daemon UNNEEDED, const struct chan *chan UNNEEDED, int direction UNNEEDED)
{ fprintf(stderr, "local_disable_chan called!\n"); abort(); }
/* Generated stub for local_enable_chan */
void local_enable_chan(struct daemon *daemon UNNEEDED, const struct chan *chan UNNEEDED, int direction UNNEEDED)
{ fprintf(stderr, "local_enable_chan called!\n"); abort(); }
/* Generated stub for master_badmsg */
void master_badmsg(u32 type_expected UNNEEDED, const u8 *msg)
{ fprintf(stderr, "master_badmsg called!\n"); abort(); }
/* Generated stub for maybe_send_own_node_announce */
void maybe_send_own_node_announce(struct daemon *daemon UNNEEDED, bool startup UNNEEDED)
{ fprintf(stderr, "maybe_send_own_node_announce called!\n"); abort(); }
/* Generated stub for maybe_send_query_responses */
void maybe_send_query_responses(struct daemon *daemon UNNEEDED)
{ fprintf(stderr, "maybe_send_query_responses called!\n"); abort(); }
/* Generated stub for memleak_find_allocations */
struct htable *memleak_find_allocations(const tal_t *ctx UNNEEDED,
					const void *exclude1 UNNEEDED,
					const void *exclude2 UNNEEDED)
{ fprintf(stderr, "memleak_find_allocations called!\n"); abort(); }
/* Generated stub for memleak_remove_region */
void memleak_remove_region(struct htable *memtable UNNEEDED,
			   const void *p UNNEEDED, size_t bytelen UNNEEDED)
{ fprintf(stderr, "memleak_remove_region called!\n"); abort(); }
/* Generated stub for new_onionreply */
struct onionreply *new_onionreply(const tal_t *ctx UNNEEDED, const u8 *contents TAKES UNNEEDED)
{ fprintf(stderr, "new_onionreply called!\n"); abort(); }
/* Generated stub for new_reltimer_ */
struct oneshot *new_reltimer_(struct timers *timers UNNEEDED,
			      const tal_t *ctx UNNEEDED,
			      struct timerel expire UNNEEDED,
			      void (*cb)(void *) UNNEEDED, void *arg UNNEEDED)
{ fprintf(stderr, "new_reltimer_ called!\n"); abort(); }
/* Generated stub for new_routing_state */
struct routing_state *new_routing_state(const tal_t *ctx UNNEEDED,
					const struct node_id *local_id UNNEEDED,
					struct list_head *peers UNNEEDED,
					struct timers *timers UNNEEDED,
					const u32 *dev_gossip_time TAKES UNNEEDED,
					bool dev_fast_gossip UNNEEDED,
					bool dev_fast_gossip_prune UNNEEDED)
{ fprintf(stderr, "new_routing_state called!\n"); abort(); }
/* Generated stub for new_seeker */
struct seeker *new_seeker(struct daemon *daemon UNNEEDED)
{ fprintf(stderr, "new_seeker called!\n"); abort(); }
/* Generated stub for next_chan */
struct chan *next_chan(const struct node *node UNNEEDED, struct chan_map_iter *i UNNEEDED)
{ fprintf(stderr, "next_chan called!\n"); abort(); }
/* Generated stub for notleak_ */
void *notleak_(void *ptr UNNEEDED, bool plus_children UNNEEDED)
{ fprintf(stderr, "notleak_ called!\n"); abort(); }
/* Generated stub for private_channel_announcement */
const u8 *private_channel_announcement(const tal_t *ctx UNNEEDED,
				       const struct short_channel_id *scid UNNEEDED,
				       const struct node_id *local_node_id UNNEEDED,
				       const struct node_id *remote_node_id UNNEEDED,
				       const u8 *features UNNEEDED)
{ fprintf(stderr, "private_channel_announcement called!\n"); abort(); }
/* Generated stub for query_unknown_channel */
void query_unknown_channel(struct daemon *daemon UNNEEDED,
			   struct peer *peer UNNEEDED,
			   const struct short_channel_id *id UNNEEDED)
{ fprintf(stderr, "query_unknown_channel called!\n"); abort(); }
/* Generated stub for query_unknown_node */
void query_unknown_node(struct seeker *seeker UNNEEDED, struct peer *peer UNNEEDED)
{ fprintf(stderr, "query_unknown_node called!\n"); abort(); }
/* Generated stub for refresh_local_channel */
void refresh_local_channel(struct daemon *daemon UNNEEDED,
			   struct chan *chan UNNEEDED, int direction UNNEEDED)
{ fprintf(stderr, "refresh_local_channel called!\n"); abort(); }
/* Generated stub for remove_channel_from_store */
void remove_channel_from_store(struct routing_state *rstate UNNEEDED,
			       struct chan *chan UNNEEDED)
{ fprintf(stderr, "remove_channel_from_store called!\n"); abort(); }
/* Generated stub for remove_unknown_scid */
bool remove_unknown_scid(struct seeker *seeker UNNEEDED,
			 const struct short_channel_id *scid UNNEEDED,
			 bool found UNNEEDED)
{ fprintf(stderr, "remove_unknown_scid called!\n"); abort(); }
/* Generated stub for route_prune */
void route_prune(struct routing_state *rstate UNNEEDED)
{ fprintf(stderr, "route_prune called!\n"); abort(); }
/* Generated stub for routing_add_private_channel */
bool routing_add_private_channel(struct routing_state *rstate UNNEEDED,
				 const struct node_id *id UNNEEDED,
				 struct amount_sat sat UNNEEDED,
				 const u8 *chan_ann UNNEEDED, u64 index UNNEEDED)
{ fprintf(stderr, "routing_add_private_channel called!\n"); abort(); }
/* Generated stub for sanitize_error */
char *sanitize_error(const tal_t *ctx UNNEEDED, const u8 *errmsg UNNEEDED,
		     struct channel_id *channel_id UNNEEDED)
{ fprintf(stderr, "sanitize_error called!\n"); abort(); }
/* Generated stub for seeker_setup_peer_gossip */
void seeker_setup_peer_gossip(struct seeker *seeker UNNEEDED, struct peer *peer UNNEEDED)
{ fprintf(stderr, "seeker_setup_peer_gossip called!\n"); abort(); }
/* Generated stub for status_failed */
void status_failed(enum status_failreason code UNNEEDED,
		   const char *fmt UNNEEDED, ...)
{ fprintf(stderr, "status_failed called!\n"); abort(); }
/* Generated stub for status_fmt */
void status_fmt(enum log_level level UNNEEDED,
		const struct node_id *peer UNNEEDED,
		const char *fmt UNNEEDED, ...)

{ fprintf(stderr, "status_fmt called!\n"); abort(); }
/* Generated stub for status_setup_async */
void status_setup_async(struct daemon_conn *master UNNEEDED)
{ fprintf(stderr, "status_setup_async called!\n"); abort(); }
/* Generated stub for subdaemon_setup */
void subdaemon_setup(int argc UNNEEDED, char *argv[])
{ fprintf(stderr, "subdaemon_setup called!\n"); abort(); }
/* Generated stub for timer_expired */
void timer_expired(struct timer *timer UNNEEDED)
{ fprintf(stderr, "timer_expired called!\n"); abort(); }
/* Generated stub for towire_gossipd_addgossip_reply */
u8 *towire_gossipd_addgossip_reply(const tal_t *ctx UNNEEDED, const wirestring *err UNNEEDED)
{ fprintf(stderr, "towire_gossipd_addgossip_reply called!\n"); abort(); }
/* Generated stub for towire_gossipd_dev_compact_store_reply */
u8 *towire_gossipd_dev_compact_store_reply(const tal_t *ctx UNNEEDED, bool success UNNEEDED)
{ fprintf(stderr, "towire_gossipd_dev_compact_store_reply called!\n"); abort(); }
/* Generated stub for towire_gossipd_dev_memleak_reply */
u8 *towire_gossipd_dev_memleak_reply(const tal_t *ctx UNNEEDED, bool leak UNNEEDED)
{ fprintf(stderr, "towire_gossipd_dev_memleak_reply called!\n"); abort(); }
/* Generated stub for towire_gossipd_get_addrs_reply */
u8 *towire_gossipd_get_addrs_reply(const tal_t *ctx UNNEEDED, const struct wireaddr *addrs UNNEEDED)
{ fprintf(stderr, "towire_gossipd_get_addrs_reply called!\n"); abort(); }
/* Generated stub for towire_gossipd_get_txout */
u8 *towire_gossipd_get_txout(const tal_t *ctx UNNEEDED, const struct short_channel_id *short_channel_id UNNEEDED)
{ fprintf(stderr, "towire_gossipd_get_txout called!\n"); abort(); }
/* Generated stub for towire_gossipd_got_onionmsg_to_us */
u8 *towire_gossipd_got_onionmsg_to_us(const tal_t *ctx UNNEEDED, bool obs2 UNNEEDED, const struct pubkey *node_alias UNNEEDED, const struct secret *self_id UNNEEDED, const struct pubkey *reply_blinding UNNEEDED, const struct pubkey *reply_first_node UNNEEDED, const struct onionmsg_path **reply_path UNNEEDED, const u8 *rawmsg UNNEEDED)
{ fprintf(stderr, "towire_gossipd_got_onionmsg_to_us called!\n"); abort(); }
/* Generated stub for towire_gossipd_init_reply */
u8 *towire_gossipd_init_reply(const tal_t *ctx UNNEEDED)
{ fprintf(stderr, "towire_gossipd_init_reply called!\n"); abort(); }
/* Generated stub for towire_gossipd_new_peer_reply */
u8 *towire_gossipd_new_peer_reply(const tal_t *ctx UNNEEDED, bool success UNNEEDED)
{ fprintf(stderr, "towire_gossipd_new_peer_reply called!\n"); abort(); }
/* Generated stub for towire_gossipd_send_gossip */
u8 *towire_gossipd_send_gossip(const tal_t *ctx UNNEEDED, const struct node_id *id UNNEEDED, const u8 *msg UNNEEDED)
{ fprintf(stderr, "towire_gossipd_send_gossip called!\n"); abort(); }
/* Generated stub for towire_warningfmt */
u8 *towire_warningfmt(const tal_t *ctx UNNEEDED,
		      const struct channel_id *channel UNNEEDED,
		      const char *fmt UNNEEDED, ...)
{ fprintf(stderr, "towire_warningfmt called!\n"); abort(); }
/* AUTOGENERATED MOCKS END */

/* Updated each time, as we pretend to be Alice, Bob, Carol */
static const struct privkey *mykey;

static void test_ecdh(const struct pubkey *point, struct secret *ss)
{
	if (secp256k1_ecdh(secp256k1_ctx, ss->data, &point->pubkey,
			   mykey->secret.data, NULL, NULL) != 1)
		abort();
}

static void json_strfield(const char *name, const char *val)
{
	printf("\t\"%s\": \"%s\",\n", name, val);
}

static void json_onionmsg_payload(const struct tlv_obs2_onionmsg_payload *om)
{
	if (om->reply_path) {
		printf("\t\"reply_path\": {\n");
		json_strfield("first_node_id",
			      type_to_string(tmpctx, struct pubkey,
					     &om->reply_path->first_node_id));
		json_strfield("blinding",
			      type_to_string(tmpctx, struct pubkey,
					     &om->reply_path->blinding));
		printf("\t\"path\": [\n");
		for (size_t i = 0; i < tal_count(om->reply_path->path); i++) {
			json_strfield("node_id",
				      type_to_string(tmpctx, struct pubkey,
						     &om->reply_path->path[i]->node_id));
			json_strfield("encrypted_recipient_data",
				      tal_hex(tmpctx,
					      om->reply_path->path[i]->encrypted_recipient_data));
		}
		printf("]}\n");
	}
	if (om->invoice)
		json_strfield("invoice", tal_hex(tmpctx, om->invoice));
	if (om->invoice_request)
		json_strfield("invoice_request",
			      tal_hex(tmpctx, om->invoice_request));
	if (om->invoice_error)
		json_strfield("invoice_error",
			      tal_hex(tmpctx, om->invoice_error));
}

/* Return next onion (and updates blinding), or NULL */
static u8 *json_test(const char *testname,
		     const u8 *data,
		     const struct privkey *me,
		     const struct privkey *blinding_priv,
		     struct pubkey *blinding)
{
	struct pubkey my_id, next_node;
	struct secret ss, onion_ss;
	struct pubkey ephemeral;
	struct route_step *rs;
	const u8 *cursor;
	size_t max, maxlen;
	struct onionpacket *op;
	struct tlv_obs2_onionmsg_payload *om;

	op = parse_onionpacket(tmpctx, data, tal_bytelen(data), NULL);
	assert(op);

	pubkey_from_privkey(me, &my_id);
	printf("{");
	json_strfield("test name", testname);
	json_strfield("reader_privkey",
		      type_to_string(tmpctx, struct privkey, me));
	json_strfield("reader_id",
		      type_to_string(tmpctx, struct pubkey, &my_id));

	if (blinding_priv)
		json_strfield("blinding_privkey",
			      type_to_string(tmpctx, struct privkey,
					     blinding_priv));
	json_strfield("blinding",
		      type_to_string(tmpctx, struct pubkey, blinding));
	printf("\"onionmsg\": {\n");
	json_strfield("raw", tal_hex(tmpctx, data));
	json_strfield("version", tal_fmt(tmpctx, "%i", op->version));
	json_strfield("public_key",
		      type_to_string(tmpctx, struct pubkey, &op->ephemeralkey));
	json_strfield("hop_payloads",
		      tal_hex(tmpctx, op->routinginfo));
	json_strfield("hmac",
		      tal_hexstr(tmpctx, &op->hmac, sizeof(op->hmac)));
	printf("},\n");

	ephemeral = op->ephemeralkey;

	/* Set this for test_ecdh */
	mykey = me;
	assert(unblind_onion(blinding, test_ecdh, &ephemeral, &ss));
	json_strfield("ECDH shared secret",
		      type_to_string(tmpctx, struct secret, &ss));
	/* Reproduce internal calc from unblind_onion */
	{
		struct secret hmac;
		subkey_from_hmac("blinded_node_id", &ss, &hmac);
		json_strfield("HMAC256(\\\"blinded_node_id\\\", ss(i)) * k(i)",
			      type_to_string(tmpctx, struct secret, &hmac));
	}
	json_strfield("Tweaked onion pubkey",
		      type_to_string(tmpctx, struct pubkey, &ephemeral));

	/* Now get onion shared secret and parse it. */
	test_ecdh(&ephemeral, &onion_ss);
	json_strfield("onion shared secret",
		      type_to_string(tmpctx, struct secret, &onion_ss));
	rs = process_onionpacket(tmpctx, op, &onion_ss, NULL, 0, false);
	assert(rs);

	printf("\"onion contents\": {\n");
	json_strfield("raw", tal_hex(tmpctx, rs->raw_payload));

	cursor = rs->raw_payload;
	max = tal_bytelen(rs->raw_payload);
	maxlen = fromwire_bigsize(&cursor, &max);
	json_strfield("length", tal_fmt(tmpctx, "%zu", maxlen));
	json_strfield("rawtlv", tal_hexstr(tmpctx, cursor, maxlen));
	json_strfield("hmac", tal_hexstr(tmpctx, rs->next->hmac.bytes,
					 sizeof(rs->next->hmac.bytes)));
	om = tlv_obs2_onionmsg_payload_new(tmpctx);
	assert(fromwire_obs2_onionmsg_payload(&cursor, &maxlen, om));

	json_onionmsg_payload(om);

	/* We expect one of these. */
	assert(om->enctlv);

	printf("\t\"encrypted_data_tlv\": {\n");
	json_strfield("raw", tal_hex(tmpctx, om->enctlv));

	if (rs->nextcase == ONION_END) {
		struct secret *self_id;
		struct pubkey alias;
		assert(decrypt_obs2_final_enctlv(tmpctx,
						 blinding, &ss,
						 om->enctlv,
						 &my_id, &alias, &self_id));
		if (self_id) {
			json_strfield("self_id",
				      type_to_string(tmpctx, struct secret,
						     self_id));
		}
		printf("}\n");
		return NULL;
	} else {
		assert(decrypt_obs2_enctlv(blinding, &ss, om->enctlv, &next_node,
					   blinding));
		json_strfield("next_node",
			      type_to_string(tmpctx, struct pubkey, &next_node));
		json_strfield("next_blinding",
			      type_to_string(tmpctx, struct pubkey,
					     blinding));
		printf("}");
		printf("},\n");
		return serialize_onionpacket(tmpctx, rs->next);
	}
}

int main(int argc, char *argv[])
{
	struct onionpacket *op;
	u8 *data;
	struct privkey alice, bob, carol, dave, blinding_priv;
	struct pubkey alice_id, bob_id, carol_id, dave_id;
	struct pubkey blinding;

	common_setup(argv[0]);

	memset(&alice, 'A', sizeof(alice));
	memset(&bob, 'B', sizeof(bob));
	memset(&carol, 'C', sizeof(carol));
	memset(&dave, 'D', sizeof(dave));
	pubkey_from_privkey(&alice, &alice_id);
	pubkey_from_privkey(&bob, &bob_id);
	pubkey_from_privkey(&carol, &carol_id);
	pubkey_from_privkey(&dave, &dave_id);

	/* ThomasH sends via email:
	 *
	 *  {
	 *  "version":0,
	 *  "public_key":
	 *  "0256b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967",
	 *  "hop_payloads":
	 *  "37df67dcefdb678725cb8074d3224dfe235ba3f22f71ac8a2c9d1398b1175295b1dd3f14c02d698021e8a8856637306c6f195e01494eb8dc636b4462367533a84786b8592e580086cdf0f1c58b77eb68703a2fb82ecc2e91307a25b6d5e4045174551b1c867264d3905e4f05b2e5bcfed7e7276660bf7e956bce5afa395e7e4c15883b856bc93dd9d6a968838ef51314d38dd41e5ab84b8846dca3c61d87e55780e7a7da336a965a4652263413cdef41daa68f7bb7cd4d566c19a1c4eece369c47e604575f38e7a246a985c3441b60ae33c564395bb7a4bbe28325ccdb07503285dacf90b5e09f4e455fb42459741f9d497000298b99f1e70adc28f59a1be85a96952f27b6a6c5d6a08822b4f5cae05daa6c2ce2f8ca5fdd4e8f0df46b94791b3159fe8eace11bcf8d58be425b49ce2b47c007affefd5cea785c1996ad805f8c8c5ca79f15ab26e2bd4080b1d74328e7ce5bd2a579c71a6bd25f33f2ce475a2cfbe67ed1f4eb8fbd86920f41d573488abe059166aabbc3be187c435423ead6a5473994e0246efe76e419893aa2d7566b2645f3496d97585de9c92b8c5a5226398cc459ce84abc02fe2b45b5ecaf21961730d4a34bbe6fdfe720e71e3d81a494c01080d8039360d534c6ee5a3c47a1874e526969add9126b30d9192f85ba45bcfd7029cc7560f0e25e14b5deaa805360c4967705e85325ac055922863470f5397e8404022488caebf9204acd6cb02a11088aebf7e497b4ff1172f0a9c6bf980914cc4eb42fc78b457add549abf1134f84922b217502938b42d10b35079f44c5168d4c3e9fe7ca8094ef72ed73ef84f1d3530b6b3545f9f4f013e7e8cbcf2619f57754a7380ce6a9532ee14c55990faa43df6c09530a314b5f4ce597f5ec9b776e8597ce258ac47dac43bd3ac9e52788ff3a66b7dc07cd1bc3e6d197339d85fa8d3d6c3054dd1a5e416c714b544de6eb55209e40e3cac412a51748370160d2d73b6d97abd62f7bae70df27cd199c511fa693019c5717d471e934906b98cd974fda4dd1cb5e2d721044a0be2bdf24d0971e09f2f39488fe389fc5230699b4df7cec7447e5be4ea49bd7c3fe1a5ec7358510dc1dd9c1a8da68c0863188d80549e49f7c00f57d2009b2427b2aed1569603fc247734039469f9fdf3ddd3a22fa95c5d8066a468327a02b474c9915419af82c8edc67686984767fe7885207c6820f6c2e57cb8fd0bcb9981ebc8065c74e970a5d593c3b73ee25a0877ca096a9f7edfee6d43bd817c7d415fea9abb6f206c61aa36942df9318762a76b9da26d0d41a0ae9eee042a175f82dc134bf6f2d46a218db358d6852940e6e30df4a58ac6cb409e7ce99afe1e3f42768bd617af4d0a235d0ba0dd5075f9cc091784395d30e7e42d4e006db21bea9b45d1f122b75c051e84e2281573ef54ebad053218fff0cc28ea89a06adc218d4134f407654990592e75462f5ee4a463c1e46425222d48761162da8049613cafd7ecc52ff8024e9d58512b958e3a3d12dede84e1441247700bca0f992875349448b430683c756438fd4e91f3d44f3cf624ed21f3c63cf92615ecc201d0cd3159b1b3fccd8f29d2daba9ac5ba87b1dd2f83323a2b2d3176b803ce9c7bdc4bae615925eb22a213df1eeb2f8ff95586536caf042d565984aacf1425a120a5d8d7a9cbb70bf4852e116b89ff5b198d672220af2be4246372e7c3836cf50d732212a3e3346ff92873ace57fa687b2b1aab3e8dc6cb9f93f865d998cff0a1680d9012a9597c90a070e525f66226cc287814f4ac4157b15a0b25aa110946cd69fd404fafd5656669bfd1d9e509eabc004c5a",
	 *  "hmac": "564bb85911bea8f90d306f4acdafa1c0887619ac72606b11e6b2765734d810ac"
	 *  }
	 */
	op = tal(tmpctx, struct onionpacket);
	op->version = 0;
	assert(pubkey_from_hexstr("0256b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967", strlen("0256b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967"), &op->ephemeralkey));
	assert(hex_decode("564bb85911bea8f90d306f4acdafa1c0887619ac72606b11e6b2765734d810ac",
			  strlen("564bb85911bea8f90d306f4acdafa1c0887619ac72606b11e6b2765734d810ac"),
			  &op->hmac, sizeof(op->hmac)));
	op->routinginfo = tal_hexdata(op, "37df67dcefdb678725cb8074d3224dfe235ba3f22f71ac8a2c9d1398b1175295b1dd3f14c02d698021e8a8856637306c6f195e01494eb8dc636b4462367533a84786b8592e580086cdf0f1c58b77eb68703a2fb82ecc2e91307a25b6d5e4045174551b1c867264d3905e4f05b2e5bcfed7e7276660bf7e956bce5afa395e7e4c15883b856bc93dd9d6a968838ef51314d38dd41e5ab84b8846dca3c61d87e55780e7a7da336a965a4652263413cdef41daa68f7bb7cd4d566c19a1c4eece369c47e604575f38e7a246a985c3441b60ae33c564395bb7a4bbe28325ccdb07503285dacf90b5e09f4e455fb42459741f9d497000298b99f1e70adc28f59a1be85a96952f27b6a6c5d6a08822b4f5cae05daa6c2ce2f8ca5fdd4e8f0df46b94791b3159fe8eace11bcf8d58be425b49ce2b47c007affefd5cea785c1996ad805f8c8c5ca79f15ab26e2bd4080b1d74328e7ce5bd2a579c71a6bd25f33f2ce475a2cfbe67ed1f4eb8fbd86920f41d573488abe059166aabbc3be187c435423ead6a5473994e0246efe76e419893aa2d7566b2645f3496d97585de9c92b8c5a5226398cc459ce84abc02fe2b45b5ecaf21961730d4a34bbe6fdfe720e71e3d81a494c01080d8039360d534c6ee5a3c47a1874e526969add9126b30d9192f85ba45bcfd7029cc7560f0e25e14b5deaa805360c4967705e85325ac055922863470f5397e8404022488caebf9204acd6cb02a11088aebf7e497b4ff1172f0a9c6bf980914cc4eb42fc78b457add549abf1134f84922b217502938b42d10b35079f44c5168d4c3e9fe7ca8094ef72ed73ef84f1d3530b6b3545f9f4f013e7e8cbcf2619f57754a7380ce6a9532ee14c55990faa43df6c09530a314b5f4ce597f5ec9b776e8597ce258ac47dac43bd3ac9e52788ff3a66b7dc07cd1bc3e6d197339d85fa8d3d6c3054dd1a5e416c714b544de6eb55209e40e3cac412a51748370160d2d73b6d97abd62f7bae70df27cd199c511fa693019c5717d471e934906b98cd974fda4dd1cb5e2d721044a0be2bdf24d0971e09f2f39488fe389fc5230699b4df7cec7447e5be4ea49bd7c3fe1a5ec7358510dc1dd9c1a8da68c0863188d80549e49f7c00f57d2009b2427b2aed1569603fc247734039469f9fdf3ddd3a22fa95c5d8066a468327a02b474c9915419af82c8edc67686984767fe7885207c6820f6c2e57cb8fd0bcb9981ebc8065c74e970a5d593c3b73ee25a0877ca096a9f7edfee6d43bd817c7d415fea9abb6f206c61aa36942df9318762a76b9da26d0d41a0ae9eee042a175f82dc134bf6f2d46a218db358d6852940e6e30df4a58ac6cb409e7ce99afe1e3f42768bd617af4d0a235d0ba0dd5075f9cc091784395d30e7e42d4e006db21bea9b45d1f122b75c051e84e2281573ef54ebad053218fff0cc28ea89a06adc218d4134f407654990592e75462f5ee4a463c1e46425222d48761162da8049613cafd7ecc52ff8024e9d58512b958e3a3d12dede84e1441247700bca0f992875349448b430683c756438fd4e91f3d44f3cf624ed21f3c63cf92615ecc201d0cd3159b1b3fccd8f29d2daba9ac5ba87b1dd2f83323a2b2d3176b803ce9c7bdc4bae615925eb22a213df1eeb2f8ff95586536caf042d565984aacf1425a120a5d8d7a9cbb70bf4852e116b89ff5b198d672220af2be4246372e7c3836cf50d732212a3e3346ff92873ace57fa687b2b1aab3e8dc6cb9f93f865d998cff0a1680d9012a9597c90a070e525f66226cc287814f4ac4157b15a0b25aa110946cd69fd404fafd5656669bfd1d9e509eabc004c5a",
				     strlen("37df67dcefdb678725cb8074d3224dfe235ba3f22f71ac8a2c9d1398b1175295b1dd3f14c02d698021e8a8856637306c6f195e01494eb8dc636b4462367533a84786b8592e580086cdf0f1c58b77eb68703a2fb82ecc2e91307a25b6d5e4045174551b1c867264d3905e4f05b2e5bcfed7e7276660bf7e956bce5afa395e7e4c15883b856bc93dd9d6a968838ef51314d38dd41e5ab84b8846dca3c61d87e55780e7a7da336a965a4652263413cdef41daa68f7bb7cd4d566c19a1c4eece369c47e604575f38e7a246a985c3441b60ae33c564395bb7a4bbe28325ccdb07503285dacf90b5e09f4e455fb42459741f9d497000298b99f1e70adc28f59a1be85a96952f27b6a6c5d6a08822b4f5cae05daa6c2ce2f8ca5fdd4e8f0df46b94791b3159fe8eace11bcf8d58be425b49ce2b47c007affefd5cea785c1996ad805f8c8c5ca79f15ab26e2bd4080b1d74328e7ce5bd2a579c71a6bd25f33f2ce475a2cfbe67ed1f4eb8fbd86920f41d573488abe059166aabbc3be187c435423ead6a5473994e0246efe76e419893aa2d7566b2645f3496d97585de9c92b8c5a5226398cc459ce84abc02fe2b45b5ecaf21961730d4a34bbe6fdfe720e71e3d81a494c01080d8039360d534c6ee5a3c47a1874e526969add9126b30d9192f85ba45bcfd7029cc7560f0e25e14b5deaa805360c4967705e85325ac055922863470f5397e8404022488caebf9204acd6cb02a11088aebf7e497b4ff1172f0a9c6bf980914cc4eb42fc78b457add549abf1134f84922b217502938b42d10b35079f44c5168d4c3e9fe7ca8094ef72ed73ef84f1d3530b6b3545f9f4f013e7e8cbcf2619f57754a7380ce6a9532ee14c55990faa43df6c09530a314b5f4ce597f5ec9b776e8597ce258ac47dac43bd3ac9e52788ff3a66b7dc07cd1bc3e6d197339d85fa8d3d6c3054dd1a5e416c714b544de6eb55209e40e3cac412a51748370160d2d73b6d97abd62f7bae70df27cd199c511fa693019c5717d471e934906b98cd974fda4dd1cb5e2d721044a0be2bdf24d0971e09f2f39488fe389fc5230699b4df7cec7447e5be4ea49bd7c3fe1a5ec7358510dc1dd9c1a8da68c0863188d80549e49f7c00f57d2009b2427b2aed1569603fc247734039469f9fdf3ddd3a22fa95c5d8066a468327a02b474c9915419af82c8edc67686984767fe7885207c6820f6c2e57cb8fd0bcb9981ebc8065c74e970a5d593c3b73ee25a0877ca096a9f7edfee6d43bd817c7d415fea9abb6f206c61aa36942df9318762a76b9da26d0d41a0ae9eee042a175f82dc134bf6f2d46a218db358d6852940e6e30df4a58ac6cb409e7ce99afe1e3f42768bd617af4d0a235d0ba0dd5075f9cc091784395d30e7e42d4e006db21bea9b45d1f122b75c051e84e2281573ef54ebad053218fff0cc28ea89a06adc218d4134f407654990592e75462f5ee4a463c1e46425222d48761162da8049613cafd7ecc52ff8024e9d58512b958e3a3d12dede84e1441247700bca0f992875349448b430683c756438fd4e91f3d44f3cf624ed21f3c63cf92615ecc201d0cd3159b1b3fccd8f29d2daba9ac5ba87b1dd2f83323a2b2d3176b803ce9c7bdc4bae615925eb22a213df1eeb2f8ff95586536caf042d565984aacf1425a120a5d8d7a9cbb70bf4852e116b89ff5b198d672220af2be4246372e7c3836cf50d732212a3e3346ff92873ace57fa687b2b1aab3e8dc6cb9f93f865d998cff0a1680d9012a9597c90a070e525f66226cc287814f4ac4157b15a0b25aa110946cd69fd404fafd5656669bfd1d9e509eabc004c5a"));

	data = serialize_onionpacket(tmpctx, op);
	printf("[\n");

	memset(&blinding_priv, 5, sizeof(blinding_priv));
	pubkey_from_privkey(&blinding_priv, &blinding);

	data = json_test("onion message for Alice",
			 data,
			 &alice,
			 &blinding_priv,
			 &blinding);

	data = json_test("onion message for Bob",
			 data,
			 &bob,
			 NULL,
			 &blinding);

	data = json_test("onion message for Carol",
			 data,
			 &carol,
			 NULL,
			 &blinding);

	data = json_test("onion message for Dave",
			 data,
			 &dave,
			 NULL,
			 &blinding);

	assert(!data);
	printf("]\n");

	common_shutdown();
	return 0;
}
