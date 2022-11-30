/* Bug https://github.com/ElementsProject/lightning/issues/2820
 *
 No valid signature found for 3 htlc_timeout_txs feerate 10992-15370, last tx 0200000001a02a38c6ec5541963704a2a035b3094b18d69cc25cc7419d75e02894618329720000000000000000000191ea3000000000002200208bfadb3554f41cc06f00de0ec2e2f91e36ee45b5006a1f606146784755356ba532f10800, input 3215967sat, signature 3045022100917efdc8577e8578aef5e513fad25edbb55921466e8ffccb05ce8bb05a54ae6902205c2fded9d7bfc290920821bfc828720bc24287f3dad9a62fb4f806e2404ed0f401, cltvs 585998/585998/586034 wscripts 76a914f454b1fe5b95428d6beec58ed3131a6ea611b2fa8763ac672103f83ca95b22920e71487736a7284696dd52443fd8f7ce683153ac31d1d1db7da67c820120876475527c21026ebaa1d08757b86110e40e3f4a081803eec694e23ec75ee0bfd753589df896e752ae67a9148dbcec4a5d782dd87588801607ea7dfc8874ffee88ac6868/76a914f454b1fe5b95428d6beec58ed3131a6ea611b2fa8763ac672103f83ca95b22920e71487736a7284696dd52443fd8f7ce683153ac31d1d1db7da67c820120876475527c21026ebaa1d08757b86110e40e3f4a081803eec694e23ec75ee0bfd753589df896e752ae67a9148dbcec4a5d782dd87588801607ea7dfc8874ffee88ac6868/76a914f454b1fe5b95428d6beec58ed3131a6ea611b2fa8763ac672103f83ca95b22920e71487736a7284696dd52443fd8f7ce683153ac31d1d1db7da67c820120876475527c21026ebaa1d08757b86110e40e3f4a081803eec694e23ec75ee0bfd753589df896e752ae67a9148dbcec4a5d782dd87588801607ea7dfc8874ffee88ac6868 (version v0.7.1-57-gb3215a8)"
*/
#include "config.h"
#include <ccan/str/hex/hex.h>
#include <common/setup.h>
#include <stdio.h>

#define main test_main
int test_main(int argc, char *argv[]);
#include "../onchaind.c"
#undef main

/* AUTOGENERATED MOCKS START */
/* Generated stub for commit_number_obscurer */
u64 commit_number_obscurer(const struct pubkey *opener_payment_basepoint UNNEEDED,
			   const struct pubkey *accepter_payment_basepoint UNNEEDED)
{ fprintf(stderr, "commit_number_obscurer called!\n"); abort(); }
/* Generated stub for daemon_shutdown */
void daemon_shutdown(void)
{ fprintf(stderr, "daemon_shutdown called!\n"); abort(); }
/* Generated stub for derive_keyset */
bool derive_keyset(const struct pubkey *per_commitment_point UNNEEDED,
		   const struct basepoints *self UNNEEDED,
		   const struct basepoints *other UNNEEDED,
		   bool option_static_remotekey UNNEEDED,
		   struct keyset *keyset UNNEEDED)
{ fprintf(stderr, "derive_keyset called!\n"); abort(); }
/* Generated stub for fromwire */
const u8 *fromwire(const u8 **cursor UNNEEDED, size_t *max UNNEEDED, void *copy UNNEEDED, size_t n UNNEEDED)
{ fprintf(stderr, "fromwire called!\n"); abort(); }
/* Generated stub for fromwire_bool */
bool fromwire_bool(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_bool called!\n"); abort(); }
/* Generated stub for fromwire_fail */
void *fromwire_fail(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_fail called!\n"); abort(); }
/* Generated stub for fromwire_hsmd_get_per_commitment_point_reply */
bool fromwire_hsmd_get_per_commitment_point_reply(const tal_t *ctx UNNEEDED, const void *p UNNEEDED, struct pubkey *per_commitment_point UNNEEDED, struct secret **old_commitment_secret UNNEEDED)
{ fprintf(stderr, "fromwire_hsmd_get_per_commitment_point_reply called!\n"); abort(); }
/* Generated stub for fromwire_onchaind_depth */
bool fromwire_onchaind_depth(const void *p UNNEEDED, struct bitcoin_txid *txid UNNEEDED, u32 *depth UNNEEDED)
{ fprintf(stderr, "fromwire_onchaind_depth called!\n"); abort(); }
/* Generated stub for fromwire_onchaind_dev_memleak */
bool fromwire_onchaind_dev_memleak(const void *p UNNEEDED)
{ fprintf(stderr, "fromwire_onchaind_dev_memleak called!\n"); abort(); }
/* Generated stub for fromwire_onchaind_htlcs */
bool fromwire_onchaind_htlcs(const tal_t *ctx UNNEEDED, const void *p UNNEEDED, struct htlc_stub **htlc UNNEEDED, bool **tell_if_missing UNNEEDED, bool **tell_immediately UNNEEDED)
{ fprintf(stderr, "fromwire_onchaind_htlcs called!\n"); abort(); }
/* Generated stub for fromwire_onchaind_init */
bool fromwire_onchaind_init(const tal_t *ctx UNNEEDED, const void *p UNNEEDED, struct shachain *shachain UNNEEDED, const struct chainparams **chainparams UNNEEDED, struct amount_sat *funding_amount_satoshi UNNEEDED, struct amount_msat *our_msat UNNEEDED, struct pubkey *old_remote_per_commitment_point UNNEEDED, struct pubkey *remote_per_commitment_point UNNEEDED, u32 *local_to_self_delay UNNEEDED, u32 *remote_to_self_delay UNNEEDED, u32 *delayed_to_us_feerate UNNEEDED, u32 *htlc_feerate UNNEEDED, u32 *penalty_feerate UNNEEDED, struct amount_sat *local_dust_limit_satoshi UNNEEDED, struct bitcoin_txid *our_broadcast_txid UNNEEDED, u8 **local_scriptpubkey UNNEEDED, u8 **remote_scriptpubkey UNNEEDED, u32 *ourwallet_index UNNEEDED, struct ext_key *ourwallet_ext_key UNNEEDED, struct pubkey *ourwallet_pubkey UNNEEDED, enum side *opener UNNEEDED, struct basepoints *local_basepoints UNNEEDED, struct basepoints *remote_basepoints UNNEEDED, struct tx_parts **tx_parts UNNEEDED, u32 *locktime UNNEEDED, u32 *tx_blockheight UNNEEDED, u32 *reasonable_depth UNNEEDED, struct bitcoin_signature **htlc_signature UNNEEDED, u32 *min_possible_feerate UNNEEDED, u32 *max_possible_feerate UNNEEDED, struct pubkey **possible_remote_per_commit_point UNNEEDED, struct pubkey *local_funding_pubkey UNNEEDED, struct pubkey *remote_funding_pubkey UNNEEDED, u64 *local_static_remotekey_start UNNEEDED, u64 *remote_static_remotekey_start UNNEEDED, bool *option_anchor_outputs UNNEEDED, u32 *min_relay_feerate UNNEEDED)
{ fprintf(stderr, "fromwire_onchaind_init called!\n"); abort(); }
/* Generated stub for fromwire_onchaind_known_preimage */
bool fromwire_onchaind_known_preimage(const void *p UNNEEDED, struct preimage *preimage UNNEEDED)
{ fprintf(stderr, "fromwire_onchaind_known_preimage called!\n"); abort(); }
/* Generated stub for fromwire_onchaind_spent */
bool fromwire_onchaind_spent(const tal_t *ctx UNNEEDED, const void *p UNNEEDED, struct tx_parts **tx UNNEEDED, u32 *locktime UNNEEDED, u32 *input_num UNNEEDED, u32 *blockheight UNNEEDED)
{ fprintf(stderr, "fromwire_onchaind_spent called!\n"); abort(); }
/* Generated stub for fromwire_peektype */
int fromwire_peektype(const u8 *cursor UNNEEDED)
{ fprintf(stderr, "fromwire_peektype called!\n"); abort(); }
/* Generated stub for fromwire_secp256k1_ecdsa_signature */
void fromwire_secp256k1_ecdsa_signature(const u8 **cursor UNNEEDED, size_t *max UNNEEDED,
					secp256k1_ecdsa_signature *signature UNNEEDED)
{ fprintf(stderr, "fromwire_secp256k1_ecdsa_signature called!\n"); abort(); }
/* Generated stub for fromwire_sha256 */
void fromwire_sha256(const u8 **cursor UNNEEDED, size_t *max UNNEEDED, struct sha256 *sha256 UNNEEDED)
{ fprintf(stderr, "fromwire_sha256 called!\n"); abort(); }
/* Generated stub for fromwire_tal_arrn */
u8 *fromwire_tal_arrn(const tal_t *ctx UNNEEDED,
		       const u8 **cursor UNNEEDED, size_t *max UNNEEDED, size_t num UNNEEDED)
{ fprintf(stderr, "fromwire_tal_arrn called!\n"); abort(); }
/* Generated stub for fromwire_u16 */
u16 fromwire_u16(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_u16 called!\n"); abort(); }
/* Generated stub for fromwire_u32 */
u32 fromwire_u32(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_u32 called!\n"); abort(); }
/* Generated stub for fromwire_u64 */
u64 fromwire_u64(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_u64 called!\n"); abort(); }
/* Generated stub for fromwire_u8 */
u8 fromwire_u8(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_u8 called!\n"); abort(); }
/* Generated stub for fromwire_u8_array */
void fromwire_u8_array(const u8 **cursor UNNEEDED, size_t *max UNNEEDED, u8 *arr UNNEEDED, size_t num UNNEEDED)
{ fprintf(stderr, "fromwire_u8_array called!\n"); abort(); }
/* Generated stub for htlc_offered_wscript */
u8 *htlc_offered_wscript(const tal_t *ctx UNNEEDED,
			 const struct ripemd160 *ripemd UNNEEDED,
			 const struct keyset *keyset UNNEEDED,
			 bool option_anchor_outputs UNNEEDED)
{ fprintf(stderr, "htlc_offered_wscript called!\n"); abort(); }
/* Generated stub for htlc_received_wscript */
u8 *htlc_received_wscript(const tal_t *ctx UNNEEDED,
			  const struct ripemd160 *ripemd UNNEEDED,
			  const struct abs_locktime *expiry UNNEEDED,
			  const struct keyset *keyset UNNEEDED,
			  bool option_anchor_outputs UNNEEDED)
{ fprintf(stderr, "htlc_received_wscript called!\n"); abort(); }
/* Generated stub for htlc_success_tx */
struct bitcoin_tx *htlc_success_tx(const tal_t *ctx UNNEEDED,
				   const struct chainparams *chainparams UNNEEDED,
				   const struct bitcoin_outpoint *commit UNNEEDED,
				   const u8 *commit_wscript UNNEEDED,
				   struct amount_msat htlc_msatoshi UNNEEDED,
				   u16 to_self_delay UNNEEDED,
				   u32 feerate_per_kw UNNEEDED,
				   const struct keyset *keyset UNNEEDED,
				   bool option_anchor_outputs UNNEEDED)
{ fprintf(stderr, "htlc_success_tx called!\n"); abort(); }
/* Generated stub for master_badmsg */
void master_badmsg(u32 type_expected UNNEEDED, const u8 *msg)
{ fprintf(stderr, "master_badmsg called!\n"); abort(); }
/* Generated stub for new_coin_channel_close */
struct chain_coin_mvt *new_coin_channel_close(const tal_t *ctx UNNEEDED,
					      const struct bitcoin_txid *txid UNNEEDED,
					      const struct bitcoin_outpoint *out UNNEEDED,
					      u32 blockheight UNNEEDED,
					      const struct amount_msat amount UNNEEDED,
					      const struct amount_sat output_val UNNEEDED,
					      u32 output_count)

{ fprintf(stderr, "new_coin_channel_close called!\n"); abort(); }
/* Generated stub for new_coin_external_deposit */
struct chain_coin_mvt *new_coin_external_deposit(const tal_t *ctx UNNEEDED,
						 const struct bitcoin_outpoint *outpoint UNNEEDED,
						 u32 blockheight UNNEEDED,
						 struct amount_sat amount UNNEEDED,
						 enum mvt_tag tag)

{ fprintf(stderr, "new_coin_external_deposit called!\n"); abort(); }
/* Generated stub for new_coin_external_spend */
struct chain_coin_mvt *new_coin_external_spend(const tal_t *ctx UNNEEDED,
					       const struct bitcoin_outpoint *outpoint UNNEEDED,
					       const struct bitcoin_txid *txid UNNEEDED,
					       u32 blockheight UNNEEDED,
					       struct amount_sat amount UNNEEDED,
					       enum mvt_tag tag)

{ fprintf(stderr, "new_coin_external_spend called!\n"); abort(); }
/* Generated stub for new_coin_wallet_deposit */
struct chain_coin_mvt *new_coin_wallet_deposit(const tal_t *ctx UNNEEDED,
					       const struct bitcoin_outpoint *outpoint UNNEEDED,
					       u32 blockheight UNNEEDED,
					       struct amount_sat amount UNNEEDED,
					       enum mvt_tag tag)

{ fprintf(stderr, "new_coin_wallet_deposit called!\n"); abort(); }
/* Generated stub for new_onchain_htlc_deposit */
struct chain_coin_mvt *new_onchain_htlc_deposit(const tal_t *ctx UNNEEDED,
						const struct bitcoin_outpoint *outpoint UNNEEDED,
						u32 blockheight UNNEEDED,
						struct amount_sat amount UNNEEDED,
						const struct sha256 *payment_hash)

{ fprintf(stderr, "new_onchain_htlc_deposit called!\n"); abort(); }
/* Generated stub for new_onchain_htlc_withdraw */
struct chain_coin_mvt *new_onchain_htlc_withdraw(const tal_t *ctx UNNEEDED,
						 const struct bitcoin_outpoint *outpoint UNNEEDED,
						 u32 blockheight UNNEEDED,
						 struct amount_sat amount UNNEEDED,
						 const struct sha256 *payment_hash)

{ fprintf(stderr, "new_onchain_htlc_withdraw called!\n"); abort(); }
/* Generated stub for new_onchaind_deposit */
struct chain_coin_mvt *new_onchaind_deposit(const tal_t *ctx UNNEEDED,
					    const struct bitcoin_outpoint *outpoint UNNEEDED,
					    u32 blockheight UNNEEDED,
					    struct amount_sat amount UNNEEDED,
					    enum mvt_tag tag)

{ fprintf(stderr, "new_onchaind_deposit called!\n"); abort(); }
/* Generated stub for new_onchaind_withdraw */
struct chain_coin_mvt *new_onchaind_withdraw(const tal_t *ctx UNNEEDED,
					     const struct bitcoin_outpoint *outpoint UNNEEDED,
					     const struct bitcoin_txid *spend_txid UNNEEDED,
					     u32 blockheight UNNEEDED,
					     struct amount_sat amount UNNEEDED,
					     enum mvt_tag tag)

{ fprintf(stderr, "new_onchaind_withdraw called!\n"); abort(); }
/* Generated stub for notleak_ */
void *notleak_(void *ptr UNNEEDED, bool plus_children UNNEEDED)
{ fprintf(stderr, "notleak_ called!\n"); abort(); }
/* Generated stub for onchaind_wire_name */
const char *onchaind_wire_name(int e UNNEEDED)
{ fprintf(stderr, "onchaind_wire_name called!\n"); abort(); }
/* Generated stub for peer_billboard */
void peer_billboard(bool perm UNNEEDED, const char *fmt UNNEEDED, ...)
{ fprintf(stderr, "peer_billboard called!\n"); abort(); }
/* Generated stub for shachain_get_secret */
bool shachain_get_secret(const struct shachain *shachain UNNEEDED,
			 u64 commit_num UNNEEDED,
			 struct secret *preimage UNNEEDED)
{ fprintf(stderr, "shachain_get_secret called!\n"); abort(); }
/* Generated stub for status_failed */
void status_failed(enum status_failreason code UNNEEDED,
		   const char *fmt UNNEEDED, ...)
{ fprintf(stderr, "status_failed called!\n"); abort(); }
/* Generated stub for status_setup_sync */
void status_setup_sync(int fd UNNEEDED)
{ fprintf(stderr, "status_setup_sync called!\n"); abort(); }
/* Generated stub for subdaemon_setup */
void subdaemon_setup(int argc UNNEEDED, char *argv[])
{ fprintf(stderr, "subdaemon_setup called!\n"); abort(); }
/* Generated stub for to_self_wscript */
u8 *to_self_wscript(const tal_t *ctx UNNEEDED,
		    u16 to_self_delay UNNEEDED,
		    u32 csv UNNEEDED,
		    const struct keyset *keyset UNNEEDED)
{ fprintf(stderr, "to_self_wscript called!\n"); abort(); }
/* Generated stub for towire */
void towire(u8 **pptr UNNEEDED, const void *data UNNEEDED, size_t len UNNEEDED)
{ fprintf(stderr, "towire called!\n"); abort(); }
/* Generated stub for towire_bool */
void towire_bool(u8 **pptr UNNEEDED, bool v UNNEEDED)
{ fprintf(stderr, "towire_bool called!\n"); abort(); }
/* Generated stub for towire_hsmd_get_per_commitment_point */
u8 *towire_hsmd_get_per_commitment_point(const tal_t *ctx UNNEEDED, u64 n UNNEEDED)
{ fprintf(stderr, "towire_hsmd_get_per_commitment_point called!\n"); abort(); }
/* Generated stub for towire_hsmd_sign_delayed_payment_to_us */
u8 *towire_hsmd_sign_delayed_payment_to_us(const tal_t *ctx UNNEEDED, u64 commit_num UNNEEDED, const struct bitcoin_tx *tx UNNEEDED, const u8 *wscript UNNEEDED)
{ fprintf(stderr, "towire_hsmd_sign_delayed_payment_to_us called!\n"); abort(); }
/* Generated stub for towire_hsmd_sign_penalty_to_us */
u8 *towire_hsmd_sign_penalty_to_us(const tal_t *ctx UNNEEDED, const struct secret *revocation_secret UNNEEDED, const struct bitcoin_tx *tx UNNEEDED, const u8 *wscript UNNEEDED)
{ fprintf(stderr, "towire_hsmd_sign_penalty_to_us called!\n"); abort(); }
/* Generated stub for towire_hsmd_sign_remote_htlc_to_us */
u8 *towire_hsmd_sign_remote_htlc_to_us(const tal_t *ctx UNNEEDED, const struct pubkey *remote_per_commitment_point UNNEEDED, const struct bitcoin_tx *tx UNNEEDED, const u8 *wscript UNNEEDED, bool option_anchor_outputs UNNEEDED)
{ fprintf(stderr, "towire_hsmd_sign_remote_htlc_to_us called!\n"); abort(); }
/* Generated stub for towire_onchaind_add_utxo */
u8 *towire_onchaind_add_utxo(const tal_t *ctx UNNEEDED, const struct bitcoin_outpoint *prev_out UNNEEDED, const struct pubkey *per_commit_point UNNEEDED, struct amount_sat value UNNEEDED, u32 blockheight UNNEEDED, const u8 *scriptpubkey UNNEEDED, u32 csv_lock UNNEEDED)
{ fprintf(stderr, "towire_onchaind_add_utxo called!\n"); abort(); }
/* Generated stub for towire_onchaind_all_irrevocably_resolved */
u8 *towire_onchaind_all_irrevocably_resolved(const tal_t *ctx UNNEEDED)
{ fprintf(stderr, "towire_onchaind_all_irrevocably_resolved called!\n"); abort(); }
/* Generated stub for towire_onchaind_annotate_txin */
u8 *towire_onchaind_annotate_txin(const tal_t *ctx UNNEEDED, const struct bitcoin_txid *txid UNNEEDED, u32 innum UNNEEDED, enum wallet_tx_type type UNNEEDED)
{ fprintf(stderr, "towire_onchaind_annotate_txin called!\n"); abort(); }
/* Generated stub for towire_onchaind_annotate_txout */
u8 *towire_onchaind_annotate_txout(const tal_t *ctx UNNEEDED, const struct bitcoin_outpoint *outpoint UNNEEDED, enum wallet_tx_type type UNNEEDED)
{ fprintf(stderr, "towire_onchaind_annotate_txout called!\n"); abort(); }
/* Generated stub for towire_onchaind_broadcast_tx */
u8 *towire_onchaind_broadcast_tx(const tal_t *ctx UNNEEDED, const struct bitcoin_tx *tx UNNEEDED, enum wallet_tx_type type UNNEEDED, bool is_rbf UNNEEDED)
{ fprintf(stderr, "towire_onchaind_broadcast_tx called!\n"); abort(); }
/* Generated stub for towire_onchaind_dev_memleak_reply */
u8 *towire_onchaind_dev_memleak_reply(const tal_t *ctx UNNEEDED, bool leak UNNEEDED)
{ fprintf(stderr, "towire_onchaind_dev_memleak_reply called!\n"); abort(); }
/* Generated stub for towire_onchaind_extracted_preimage */
u8 *towire_onchaind_extracted_preimage(const tal_t *ctx UNNEEDED, const struct preimage *preimage UNNEEDED)
{ fprintf(stderr, "towire_onchaind_extracted_preimage called!\n"); abort(); }
/* Generated stub for towire_onchaind_htlc_timeout */
u8 *towire_onchaind_htlc_timeout(const tal_t *ctx UNNEEDED, const struct htlc_stub *htlc UNNEEDED)
{ fprintf(stderr, "towire_onchaind_htlc_timeout called!\n"); abort(); }
/* Generated stub for towire_onchaind_init_reply */
u8 *towire_onchaind_init_reply(const tal_t *ctx UNNEEDED, u64 commit_num UNNEEDED)
{ fprintf(stderr, "towire_onchaind_init_reply called!\n"); abort(); }
/* Generated stub for towire_onchaind_missing_htlc_output */
u8 *towire_onchaind_missing_htlc_output(const tal_t *ctx UNNEEDED, const struct htlc_stub *htlc UNNEEDED)
{ fprintf(stderr, "towire_onchaind_missing_htlc_output called!\n"); abort(); }
/* Generated stub for towire_onchaind_notify_coin_mvt */
u8 *towire_onchaind_notify_coin_mvt(const tal_t *ctx UNNEEDED, const struct chain_coin_mvt *mvt UNNEEDED)
{ fprintf(stderr, "towire_onchaind_notify_coin_mvt called!\n"); abort(); }
/* Generated stub for towire_onchaind_unwatch_tx */
u8 *towire_onchaind_unwatch_tx(const tal_t *ctx UNNEEDED, const struct bitcoin_txid *txid UNNEEDED)
{ fprintf(stderr, "towire_onchaind_unwatch_tx called!\n"); abort(); }
/* Generated stub for towire_secp256k1_ecdsa_signature */
void towire_secp256k1_ecdsa_signature(u8 **pptr UNNEEDED,
			      const secp256k1_ecdsa_signature *signature UNNEEDED)
{ fprintf(stderr, "towire_secp256k1_ecdsa_signature called!\n"); abort(); }
/* Generated stub for towire_sha256 */
void towire_sha256(u8 **pptr UNNEEDED, const struct sha256 *sha256 UNNEEDED)
{ fprintf(stderr, "towire_sha256 called!\n"); abort(); }
/* Generated stub for towire_u16 */
void towire_u16(u8 **pptr UNNEEDED, u16 v UNNEEDED)
{ fprintf(stderr, "towire_u16 called!\n"); abort(); }
/* Generated stub for towire_u32 */
void towire_u32(u8 **pptr UNNEEDED, u32 v UNNEEDED)
{ fprintf(stderr, "towire_u32 called!\n"); abort(); }
/* Generated stub for towire_u64 */
void towire_u64(u8 **pptr UNNEEDED, u64 v UNNEEDED)
{ fprintf(stderr, "towire_u64 called!\n"); abort(); }
/* Generated stub for towire_u8 */
void towire_u8(u8 **pptr UNNEEDED, u8 v UNNEEDED)
{ fprintf(stderr, "towire_u8 called!\n"); abort(); }
/* Generated stub for towire_u8_array */
void towire_u8_array(u8 **pptr UNNEEDED, const u8 *arr UNNEEDED, size_t num UNNEEDED)
{ fprintf(stderr, "towire_u8_array called!\n"); abort(); }
/* AUTOGENERATED MOCKS END */

#if DEVELOPER
/* Generated stub for memleak_find_allocations */
struct htable *memleak_find_allocations(const tal_t *ctx UNNEEDED,
					const void *exclude1 UNNEEDED,
					const void *exclude2 UNNEEDED)
{ fprintf(stderr, "memleak_find_allocations called!\n"); abort(); }
/* Generated stub for memleak_remove_region */
void memleak_remove_region(struct htable *memtable UNNEEDED,
			   const void *p UNNEEDED, size_t bytelen UNNEEDED)
{ fprintf(stderr, "memleak_remove_region called!\n"); abort(); }
/* Generated stub for memleak_status_broken */
void memleak_status_broken(const char *fmt UNNEEDED, ...)
{ fprintf(stderr, "memleak_status_broken called!\n"); abort(); }
/* Generated stub for dump_memleak */
bool dump_memleak(struct htable *memtable UNNEEDED,
		  void  (*print)(const char *fmt UNNEEDED, ...))
{ fprintf(stderr, "dump_memleak called!\n"); abort(); }
#endif

/* Stubs which do get called. */
u8 *towire_hsmd_sign_local_htlc_tx(const tal_t *ctx UNNEEDED, u64 commit_num UNNEEDED, const struct bitcoin_tx *tx UNNEEDED, const u8 *wscript UNNEEDED, bool option_anchor_outputs UNNEEDED)
{
	return NULL;
}

u8 *wire_sync_read(const tal_t *ctx UNNEEDED, int fd UNNEEDED)
{
	return (u8 *)ctx;
}

bool wire_sync_write(int fd UNNEEDED, const void *msg TAKES)
{
	if (taken(msg))
		tal_free(msg);
	return true;
}

/* Generated stub for fromwire_hsmd_sign_tx_reply */
bool fromwire_hsmd_sign_tx_reply(const void *p UNNEEDED, struct bitcoin_signature *sig)
{
	memset(sig, 0, sizeof(*sig));
	return true;
}

void status_fmt(enum log_level level UNNEEDED,
		const struct node_id *node_id,
		const char *fmt UNNEEDED, ...)
{
}

static void signature_from_hex(const char *hex, struct bitcoin_signature *sig)
{
	u8 der[74];
	size_t len = hex_data_size(strlen(hex));

	sig->sighash_type = SIGHASH_ALL;
	assert(len < sizeof(der));
	if (!hex_decode(hex, strlen(hex), der, len))
		abort();

	if (!signature_from_der(der, len, sig))
		abort();
}

/* We don't have enough info to make this from first principles, but we have
 * an example tx, so just mangle that. */
struct bitcoin_tx *htlc_timeout_tx(const tal_t *ctx,
				   const struct chainparams *chainparams,
				   const struct bitcoin_outpoint *commit UNNEEDED,
				   const u8* commit_wscript,
				   struct amount_msat htlc_msatoshi,
				   u32 cltv_expiry,
				   u16 to_self_delay UNNEEDED,
				   u32 feerate_per_kw UNNEEDED,
				   const struct keyset *keyset UNNEEDED,
				   bool option_anchor_outputs)
{
 	struct bitcoin_tx *tx;
	struct amount_sat in_amount;

	tx = bitcoin_tx_from_hex(ctx, "0200000001a02a38c6ec5541963704a2a035b3094b18d69cc25cc7419d75e02894618329720000000000000000000191ea3000000000002200208bfadb3554f41cc06f00de0ec2e2f91e36ee45b5006a1f606146784755356ba532f10800",
				 strlen("0200000001a02a38c6ec5541963704a2a035b3094b18d69cc25cc7419d75e02894618329720000000000000000000191ea3000000000002200208bfadb3554f41cc06f00de0ec2e2f91e36ee45b5006a1f606146784755356ba532f10800"));
	assert(tx);

	in_amount = amount_msat_to_sat_round_down(htlc_msatoshi);
	psbt_input_set_wit_utxo(tx->psbt, 0,
				scriptpubkey_p2wsh(tx->psbt, commit_wscript),
				in_amount);
	psbt_input_set_witscript(tx->psbt, 0, commit_wscript);
	tx->chainparams = chainparams;

	bitcoin_tx_set_locktime(tx, cltv_expiry);
	return tx;
}

int main(int argc, char *argv[])
{
	struct bitcoin_signature remotesig;
	struct tracked_output *out;
	struct keyset *keys;
	size_t *matches;
	struct htlc_stub htlcs[3];
	u8 *htlc_scripts[3];

	common_setup(argv[0]);
	chainparams = chainparams_for_network("bitcoin");

	htlcs[0].cltv_expiry = 585998;
	htlcs[1].cltv_expiry = 585998;
	htlcs[2].cltv_expiry = 586034;
	htlc_scripts[0] = tal_hexdata(tmpctx, "76a914f454b1fe5b95428d6beec58ed3131a6ea611b2fa8763ac672103f83ca95b22920e71487736a7284696dd52443fd8f7ce683153ac31d1d1db7da67c820120876475527c21026ebaa1d08757b86110e40e3f4a081803eec694e23ec75ee0bfd753589df896e752ae67a9148dbcec4a5d782dd87588801607ea7dfc8874ffee88ac6868",
				      strlen("76a914f454b1fe5b95428d6beec58ed3131a6ea611b2fa8763ac672103f83ca95b22920e71487736a7284696dd52443fd8f7ce683153ac31d1d1db7da67c820120876475527c21026ebaa1d08757b86110e40e3f4a081803eec694e23ec75ee0bfd753589df896e752ae67a9148dbcec4a5d782dd87588801607ea7dfc8874ffee88ac6868"));
	htlc_scripts[1] = tal_hexdata(tmpctx, "76a914f454b1fe5b95428d6beec58ed3131a6ea611b2fa8763ac672103f83ca95b22920e71487736a7284696dd52443fd8f7ce683153ac31d1d1db7da67c820120876475527c21026ebaa1d08757b86110e40e3f4a081803eec694e23ec75ee0bfd753589df896e752ae67a9148dbcec4a5d782dd87588801607ea7dfc8874ffee88ac6868",
				      strlen("76a914f454b1fe5b95428d6beec58ed3131a6ea611b2fa8763ac672103f83ca95b22920e71487736a7284696dd52443fd8f7ce683153ac31d1d1db7da67c820120876475527c21026ebaa1d08757b86110e40e3f4a081803eec694e23ec75ee0bfd753589df896e752ae67a9148dbcec4a5d782dd87588801607ea7dfc8874ffee88ac6868"));
	htlc_scripts[2] = tal_hexdata(tmpctx, "76a914f454b1fe5b95428d6beec58ed3131a6ea611b2fa8763ac672103f83ca95b22920e71487736a7284696dd52443fd8f7ce683153ac31d1d1db7da67c820120876475527c21026ebaa1d08757b86110e40e3f4a081803eec694e23ec75ee0bfd753589df896e752ae67a9148dbcec4a5d782dd87588801607ea7dfc8874ffee88ac6868",
				 strlen("76a914f454b1fe5b95428d6beec58ed3131a6ea611b2fa8763ac672103f83ca95b22920e71487736a7284696dd52443fd8f7ce683153ac31d1d1db7da67c820120876475527c21026ebaa1d08757b86110e40e3f4a081803eec694e23ec75ee0bfd753589df896e752ae67a9148dbcec4a5d782dd87588801607ea7dfc8874ffee88ac6868"));

	/* talz keeps valgrind happy. */
	out = talz(tmpctx, struct tracked_output);
	bitcoin_txid_from_hex("722983619428e0759d41c75cc29cd6184b09b335a0a20437964155ecc6382aa0", strlen("722983619428e0759d41c75cc29cd6184b09b335a0a20437964155ecc6382aa0"), &out->outpoint.txid);
	out->outpoint.n = 0;
	if (!parse_amount_sat(&out->sat, "3215967sat", strlen("3215967sat")))
		abort();
	signature_from_hex("3045022100917efdc8577e8578aef5e513fad25edbb55921466e8ffccb05ce8bb05a54ae6902205c2fded9d7bfc290920821bfc828720bc24287f3dad9a62fb4f806e2404ed0f401", &remotesig);
	out->remote_htlc_sig = tal_dup(out, struct bitcoin_signature, &remotesig);

	/* Make mapping 1:1 for this */
	matches = tal_arr(tmpctx, size_t, 3);
	matches[0] = 0;
	matches[1] = 1;
	matches[2] = 2;

	keyset = keys = tal(tmpctx, struct keyset);
	if (!pubkey_from_hexstr("03f83ca95b22920e71487736a7284696dd52443fd8f7ce683153ac31d1d1db7da6",
				strlen("03f83ca95b22920e71487736a7284696dd52443fd8f7ce683153ac31d1d1db7da6"),
				&keys->other_htlc_key))
		abort();

	min_possible_feerate = 10992;
	max_possible_feerate = 15370;

	size_t ret = resolve_our_htlc_ourcommit(out,
						matches,
						htlcs,
						htlc_scripts);

	assert(ret == 2);
	common_shutdown();
}
