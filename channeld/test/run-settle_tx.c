#include "config.h"
#include <inttypes.h>
#include <stdio.h>
#include <common/type_to_string.h>
static bool print_superverbose;
#define SUPERVERBOSE(...)					\
	do { if (print_superverbose) printf(__VA_ARGS__); } while(0)
#define PRINT_ACTUAL_FEE
#include "../settle_tx.c"
#include <bitcoin/tx.h>
#include <bitcoin/preimage.h>
#include <bitcoin/psbt.h>
#include <ccan/array_size/array_size.h>
#include <ccan/err/err.h>
#include <ccan/str/hex/hex.h>
#include <common/channel_id.h>
#include <common/initial_settlement_tx.h>
#include <common/key_derive.h>
#include <common/setup.h>
#include <common/status.h>
#include <common/update_tx.h>

/* Turn this on to brute-force fee values */
/*#define DEBUG */

/* AUTOGENERATED MOCKS START */
/* Generated stub for fromwire_bigsize */
bigsize_t fromwire_bigsize(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_bigsize called!\n"); abort(); }
/* Generated stub for fromwire_channel_id */
bool fromwire_channel_id(const u8 **cursor UNNEEDED, size_t *max UNNEEDED,
			 struct channel_id *channel_id UNNEEDED)
{ fprintf(stderr, "fromwire_channel_id called!\n"); abort(); }
/* Generated stub for fromwire_node_id */
void fromwire_node_id(const u8 **cursor UNNEEDED, size_t *max UNNEEDED, struct node_id *id UNNEEDED)
{ fprintf(stderr, "fromwire_node_id called!\n"); abort(); }
/* Generated stub for fromwire_wireaddr */
bool fromwire_wireaddr(const u8 **cursor UNNEEDED, size_t *max UNNEEDED, struct wireaddr *addr UNNEEDED)
{ fprintf(stderr, "fromwire_wireaddr called!\n"); abort(); }
/* Generated stub for status_fmt */
void status_fmt(enum log_level level UNNEEDED,
		const struct node_id *peer UNNEEDED,
		const char *fmt UNNEEDED, ...)

{ fprintf(stderr, "status_fmt called!\n"); abort(); }
/* Generated stub for towire_bigsize */
void towire_bigsize(u8 **pptr UNNEEDED, const bigsize_t val UNNEEDED)
{ fprintf(stderr, "towire_bigsize called!\n"); abort(); }
/* Generated stub for towire_channel_id */
void towire_channel_id(u8 **pptr UNNEEDED, const struct channel_id *channel_id UNNEEDED)
{ fprintf(stderr, "towire_channel_id called!\n"); abort(); }
/* Generated stub for towire_node_id */
void towire_node_id(u8 **pptr UNNEEDED, const struct node_id *id UNNEEDED)
{ fprintf(stderr, "towire_node_id called!\n"); abort(); }
/* Generated stub for towire_wireaddr */
void towire_wireaddr(u8 **pptr UNNEEDED, const struct wireaddr *addr UNNEEDED)
{ fprintf(stderr, "towire_wireaddr called!\n"); abort(); }
/* AUTOGENERATED MOCKS END */

char regression_tx_hex[] = "02000000000101ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000002a00000003000000000000000001511027000000000000225120c2f25ad5b139599cceb1ba1b330dfabe3e9298e4d14eec125d229536d532ef781ce80000000000002251202302f780a9d31218dbfd03f4d410ab0803995ed4795dc7963ea105b020de58ab026541a93aa6809e14e2196758dbdee73f4a077ea48e129716c79ff04592a9de15c76012e46d67acbe5882f524ecd72e4b40afba3ae3a13b3621513913813c3617ec94c1210179be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac41c1442b558d2430be010fc3aa405a78b81d3c254145fc96dc28f9347e4748cc70a4b4d868d7231ff3d15775dbd01acf0051b86eccd1f1139772222152b32986c4df0065cd1d";

static char *fmt_bitcoin_tx(const tal_t *ctx, const struct bitcoin_tx *tx)
{
    u8 *lin = linearize_tx(ctx, tx);
    char *s = tal_hex(ctx, lin);
    tal_free(lin);
    return s;
}

/* bitcoind loves its backwards txids! */
static struct bitcoin_txid txid_from_hex(const char *hex)
{
	struct bitcoin_txid txid;

	if (!bitcoin_txid_from_hex(hex, strlen(hex), &txid))
		abort();
	return txid;
}

static struct secret secret_from_hex(const char *hex)
{
	struct secret s;
	size_t len;
	if (strstarts(hex, "0x"))
		hex += 2;
	len = strlen(hex);
	/* BOLT #3:
	 *
	 * - Private keys are displayed as 32 bytes plus a trailing 1
	 *   (Bitcoin's convention for "compressed" private keys, i.e. keys
	 *   for which the public key is compressed).
	 */
	if (len == 66 && strends(hex, "01"))
		len -= 2;
	if (!hex_decode(hex, len, &s, sizeof(s)))
		abort();
	return s;
}

static struct bip340sig musig_sign(struct bitcoin_tx *update_tx, u8 *annex, struct privkey *alice_privkey, struct privkey *bob_privkey, struct pubkey *inner_pubkey, secp256k1_musig_keyagg_cache *keyagg_cache)
{
    const secp256k1_musig_pubnonce *pubnonce_ptrs[2];
    struct sha256_double msg_out;
    secp256k1_musig_session session[2];
    const secp256k1_musig_partial_sig *p_sig_ptrs[2];
    secp256k1_musig_partial_sig p_sigs[2];
    struct bip340sig sig;
    int i;
    bool ok;
    secp256k1_musig_secnonce secnonce[2];
    secp256k1_musig_pubnonce pubnonces[2];

    for (i=0; i<2; ++i){

        /* "Presharing" nonces here */
        bipmusig_gen_nonce(&secnonce[i],
               &pubnonces[i],
               (i == 0) ? alice_privkey : bob_privkey,
               &keyagg_cache[i],
               /* msg32 */ NULL);
        pubnonce_ptrs[i] = &pubnonces[i];
    }

    for (i=0; i<2; ++i){
        bitcoin_tx_taproot_hash_for_sig(update_tx, /* input_index */ 0, SIGHASH_ANYPREVOUTANYSCRIPT|SIGHASH_SINGLE, /* non-NULL script signals bip342... */ annex, annex, &msg_out);
        bipmusig_partial_sign((i == 0) ? alice_privkey : bob_privkey,
               &secnonce[i],
               pubnonce_ptrs,
               2,
               &msg_out,
               &keyagg_cache[i],
               &session[i],
               &p_sigs[i]);
        p_sig_ptrs[i] = &p_sigs[i];
    }

    /* Finally, combine sig */
    for (i=0; i<2; ++i){
        ok = bipmusig_partial_sigs_combine_verify(p_sig_ptrs,
               2,
               inner_pubkey,
               &session[i],
               &msg_out,
               &sig);
        assert(ok);
    }

    return sig;
}

static void tx_must_be_eq(const struct bitcoin_tx *a,
			  const struct bitcoin_tx *b)
{
	u8 *lina, *linb;
	size_t i;

	lina = linearize_tx(tmpctx, a);
	linb = linearize_tx(tmpctx, b);

	for (i = 0; i < tal_count(lina); i++) {
		if (i >= tal_count(linb))
			errx(1, "Second tx is truncated:\n"
			     "%s\n"
			     "%s",
			     tal_hex(tmpctx, lina),
			     tal_hex(tmpctx, linb));
		if (lina[i] != linb[i])
			errx(1, "tx differ at offset %zu:\n"
			     "%s\n"
			     "%s",
			     i,
			     tal_hex(tmpctx, lina),
			     tal_hex(tmpctx, linb));
	}
	if (i != tal_count(linb))
		errx(1, "First tx is truncated:\n"
		     "%s\n"
		     "%s",
		     tal_hex(tmpctx, lina),
		     tal_hex(tmpctx, linb));
}

/* BOLT #3:
 *
 *    htlc 0 direction: remote->local
 *    htlc 0 amount_msat: 1000000
 *    htlc 0 expiry: 500
 *    htlc 0 payment_preimage: 0000000000000000000000000000000000000000000000000000000000000000
 *    htlc 1 direction: remote->local
 *    htlc 1 amount_msat: 2000000
 *    htlc 1 expiry: 501
 *    htlc 1 payment_preimage: 0101010101010101010101010101010101010101010101010101010101010101
 *    htlc 2 direction: local->remote
 *    htlc 2 amount_msat: 2000000
 *    htlc 2 expiry: 502
 *    htlc 2 payment_preimage: 0202020202020202020202020202020202020202020202020202020202020202
 *    htlc 3 direction: local->remote
 *    htlc 3 amount_msat: 3000000
 *    htlc 3 expiry: 503
 *    htlc 3 payment_preimage: 0303030303030303030303030303030303030303030303030303030303030303
 *    htlc 4 direction: remote->local
 *    htlc 4 amount_msat: 4000000
 *    htlc 4 expiry: 504
 *    htlc 4 payment_preimage: 0404040404040404040404040404040404040404040404040404040404040404
 */
static const struct htlc **setup_htlcs_0_to_4(const tal_t *ctx)
{
	const struct htlc **htlcs = tal_arr(ctx, const struct htlc *, 5);
	int i;

	for (i = 0; i < 5; i++) {
		struct htlc *htlc = tal(htlcs, struct htlc);

		htlc->id = i;
		switch (i) {
		case 0:
			htlc->state = RCVD_ADD_ACK_REVOCATION;
			htlc->amount = AMOUNT_MSAT(1000000);
			break;
		case 1:
			htlc->state = RCVD_ADD_ACK_REVOCATION;
			htlc->amount = AMOUNT_MSAT(2000000);
			break;
		case 2:
			htlc->state = SENT_ADD_ACK_REVOCATION;
			htlc->amount = AMOUNT_MSAT(2000000);
			break;
		case 3:
			htlc->state = SENT_ADD_ACK_REVOCATION;
			htlc->amount = AMOUNT_MSAT(3000000);
			break;
		case 4:
			htlc->state = RCVD_ADD_ACK_REVOCATION;
			htlc->amount = AMOUNT_MSAT(4000000);
			break;
		}

		htlc->expiry.locktime = 500 + i;
		htlc->r = tal(htlc, struct preimage);
		memset(htlc->r, i, sizeof(*htlc->r));
		sha256(&htlc->rhash, htlc->r, sizeof(*htlc->r));
		htlcs[i] = htlc;
	}
	return htlcs;
}

/* BOLT #3:
 *    htlc 5 direction: local->remote
 *    htlc 5 amount_msat: 5000000
 *    htlc 5 expiry: 506
 *    htlc 5 payment_preimage: 0505050505050505050505050505050505050505050505050505050505050505
 *    htlc 6 direction: local->remote
 *    htlc 6 amount_msat: 5000001
 *    htlc 6 expiry: 505
 *    htlc 6 payment_preimage: 0505050505050505050505050505050505050505050505050505050505050505
*/
static const struct htlc **setup_htlcs_1_5_and_6(const tal_t *ctx)
{
	const struct htlc **htlcs = tal_arr(ctx, const struct htlc *, 3);
	int i;
	const u64 htlc_ids[] = {1, 5, 6};

	for (i = 0; i < 3; i++) {
		struct htlc *htlc = tal(htlcs, struct htlc);

		htlc->r = tal(htlc, struct preimage);
		htlc->id = htlc_ids[i];
		switch (htlc->id) {
		case 1:
			htlc->state = RCVD_ADD_ACK_REVOCATION;
			htlc->amount = AMOUNT_MSAT(2000000);
			htlc->expiry.locktime = 501;
			memset(htlc->r, 1, sizeof(*htlc->r));
			break;
		case 5:
			htlc->state = SENT_ADD_ACK_REVOCATION;
			htlc->amount = AMOUNT_MSAT(5000000);
			htlc->expiry.locktime = 505;
			memset(htlc->r, 5, sizeof(*htlc->r));
			break;
		case 6:
			htlc->state = SENT_ADD_ACK_REVOCATION;
			htlc->amount = AMOUNT_MSAT(5000001);
			htlc->expiry.locktime = 506;
			memset(htlc->r, 5, sizeof(*htlc->r));
			break;
		}
		sha256(&htlc->rhash, htlc->r, sizeof(*htlc->r));
		htlcs[i] = htlc;
	}
	return htlcs;
}


static int test_settlement_tx(void)
{
    struct bitcoin_outpoint update_output;
    struct amount_sat update_output_sats;
    u32 shared_delay;
    struct eltoo_keyset eltoo_keyset;
    struct amount_sat dust_limit;
    struct amount_msat self_pay;
    struct amount_msat other_pay;
    u32 obscured_update_number;
    /* struct wally_tx_output direct_outputs[NUM_SIDES]; Can't figure out how it's used */
    struct bitcoin_tx *tx;
    struct privkey alice_funding_privkey, bob_funding_privkey, alice_settle_privkey, bob_settle_privkey;
    int ok;
    char *tx_hex;
    char *psbt_b64;
    const struct htlc **htlc_map;

    /* Test settlement tx with no HTLCs */
    const struct htlc **htlcs = tal_arr(tmpctx, const struct htlc *, 3);


    update_output.txid = txid_from_hex("8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be");
    update_output.n = 0;
    update_output_sats.satoshis = 69420;

    alice_funding_privkey.secret = secret_from_hex("30ff4956bbdd3222d44cc5e8a1261dab1e07957bdac5ae88fe3261ef321f374901");
    bob_funding_privkey.secret = secret_from_hex("1552dfba4f6cf29a62a0af13c8d6981d36d0ef8d61ba10fb0fe90da7634d7e1301");

    ok = pubkey_from_privkey(&alice_funding_privkey,
             &eltoo_keyset.self_funding_key);
    ok = pubkey_from_privkey(&bob_funding_privkey,
             &eltoo_keyset.other_funding_key);

    shared_delay = 42;

    alice_settle_privkey.secret = secret_from_hex("1111111111111111111111111111111111111111111111111111111111111111");
    bob_settle_privkey.secret = secret_from_hex("2222222222222222222222222222222222222222222222222222222222222222");

    ok = pubkey_from_privkey(&alice_settle_privkey,
             &eltoo_keyset.self_settle_key);
    ok = pubkey_from_privkey(&bob_settle_privkey,
             &eltoo_keyset.other_settle_key);
    assert(ok);

    dust_limit.satoshis = 294;
    self_pay.millisatoshis = (update_output_sats.satoshis - 10000)*1000;
    other_pay.millisatoshis = (update_output_sats.satoshis*1000) - self_pay.millisatoshis;
    assert(other_pay.millisatoshis < self_pay.millisatoshis);
    obscured_update_number = 0;

    tx = settle_tx(tmpctx,
                     &update_output,
                     update_output_sats,
                     shared_delay,
                     &eltoo_keyset,
                     dust_limit,
                     self_pay,
                     other_pay,
                     /* htlcs */ NULL,
                     &htlc_map,
                     /* direct_outputs FIXME Cannot figure out how this is used. */ NULL,
                     obscured_update_number);

    tx_hex = fmt_bitcoin_tx(tmpctx, tx);
    printf("Settlement tx: %s\n", tx_hex);
    psbt_b64 = psbt_to_b64(tmpctx, tx->psbt);
    printf("Settlement psbt: %s\n", psbt_b64);

    assert(tx->wtx->locktime == obscured_update_number + 500000000);

    obscured_update_number = 1234;

    tal_free(tx);
    tx = settle_tx(tmpctx,
                     &update_output,
                     update_output_sats,
                     shared_delay,
                     &eltoo_keyset,
                     dust_limit,
                     self_pay,
                     other_pay,
                     /* htlcs */ NULL,
                     &htlc_map,
                     /* direct_outputs FIXME Cannot figure out how this is used. */ NULL,
                     obscured_update_number);

    assert(tx->wtx->locktime == obscured_update_number + 500000000);
    assert(tx->wtx->num_outputs == 3);

    /* Just above trimming level */
    dust_limit.satoshis = (other_pay.millisatoshis/1000);
    tal_free(tx);
    tx = settle_tx(tmpctx,
                     &update_output,
                     update_output_sats,
                     shared_delay,
                     &eltoo_keyset,
                     dust_limit,
                     self_pay,
                     other_pay,
                     /* htlcs */ NULL,
                     &htlc_map,
                     /* direct_outputs FIXME Cannot figure out how this is used. */ NULL,
                     obscured_update_number);

    assert(tx->wtx->num_outputs == 3);

    /* Smallest should be trimmed */
    dust_limit.satoshis = (other_pay.millisatoshis/1000) + 1;
    tal_free(tx);
    tx = settle_tx(tmpctx,
                     &update_output,
                     update_output_sats,
                     shared_delay,
                     &eltoo_keyset,
                     dust_limit,
                     self_pay,
                     other_pay,
                     /* htlcs */ NULL,
                     &htlc_map,
                     /* direct_outputs FIXME Cannot figure out how this is used. */ NULL,
                     obscured_update_number);
    assert(tx->wtx->num_outputs == 2);

    /* Next we test with htlcs */
    dust_limit.satoshis = 0;
    htlcs = setup_htlcs_0_to_4(tmpctx);

    tal_free(tx);
    tx = settle_tx(tmpctx,
                     &update_output,
                     update_output_sats,
                     shared_delay,
                     &eltoo_keyset,
                     dust_limit,
                     self_pay,
                     other_pay,
                     htlcs,
                     &htlc_map,
                     /* direct_outputs FIXME Cannot figure out how this is used. */ NULL,
                     obscured_update_number);

    assert(tx->wtx->num_outputs == 3 + tal_count(htlcs));

    /* All outputs survive */
    dust_limit.satoshis = htlcs[0]->amount.millisatoshis/1000;
    tal_free(tx);
    tx = settle_tx(tmpctx,
                     &update_output,
                     update_output_sats,
                     shared_delay,
                     &eltoo_keyset,
                     dust_limit,
                     self_pay,
                     other_pay,
                     htlcs,
                     &htlc_map,
                     /* direct_outputs FIXME Cannot figure out how this is used. */ NULL,
                     obscured_update_number);

    assert(tx->wtx->num_outputs == 3 + tal_count(htlcs));

    /* Smallest HTLC trimmed */
    dust_limit.satoshis = (htlcs[0]->amount.millisatoshis/1000)+1;
    tal_free(tx);
    tx = settle_tx(tmpctx,
                     &update_output,
                     update_output_sats,
                     shared_delay,
                     &eltoo_keyset,
                     dust_limit,
                     self_pay,
                     other_pay,
                     htlcs,
                     &htlc_map,
                     /* direct_outputs FIXME Cannot figure out how this is used. */ NULL,
                     obscured_update_number);

    assert(tx->wtx->num_outputs == 3 + tal_count(htlcs) - 1);

    /* Do some more interesting testing */
    htlcs = setup_htlcs_1_5_and_6(tmpctx);
    assert(htlcs);

    return 0;
}

static int test_invalid_update_tx(void)
{
    /* Exercise the code when >1 state
     * update is authorized, and an invalidated
     * update tx is posted.
     */

    struct bitcoin_outpoint update_output;
    struct amount_sat update_output_sats;
    u32 shared_delay;
    struct eltoo_keyset eltoo_keyset;
    struct amount_sat dust_limit;
    struct amount_msat self_pay;
    struct amount_msat other_pay;
    u32 obscured_update_number;
    /* struct wally_tx_output direct_outputs[NUM_SIDES]; Can't figure out how it's used */
    struct bitcoin_tx *tx, *tx_cmp, *update_tx, *settle_tx_1, *update_tx_1_A;
    struct privkey alice_funding_privkey, bob_funding_privkey, alice_settle_privkey, bob_settle_privkey;
    int ok;
    char *psbt_b64;
    const struct htlc **htlc_map;

    /* Aggregation stuff */
    secp256k1_musig_keyagg_cache keyagg_cache[2];
    struct pubkey inner_pubkey;
    const struct pubkey *pubkey_ptrs[2];
    int i;

    /* MuSig signing stuff */
    u8 *annex_0, *annex_1;
    struct bip340sig sig;

    /* Test initial settlement tx */

    update_output.txid = txid_from_hex("8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be");
    update_output.n = 0;
    update_output_sats.satoshis = 69420;

    alice_funding_privkey.secret = secret_from_hex("30ff4956bbdd3222d44cc5e8a1261dab1e07957bdac5ae88fe3261ef321f374901");
    bob_funding_privkey.secret = secret_from_hex("1552dfba4f6cf29a62a0af13c8d6981d36d0ef8d61ba10fb0fe90da7634d7e1301");

    ok = pubkey_from_privkey(&alice_funding_privkey,
             &eltoo_keyset.self_funding_key);
    ok = pubkey_from_privkey(&bob_funding_privkey,
             &eltoo_keyset.other_funding_key);

    shared_delay = 42;

    alice_settle_privkey.secret = secret_from_hex("1111111111111111111111111111111111111111111111111111111111111111");
    bob_settle_privkey.secret = secret_from_hex("2222222222222222222222222222222222222222222222222222222222222222");

    ok = pubkey_from_privkey(&alice_settle_privkey,
             &eltoo_keyset.self_settle_key);
    ok = pubkey_from_privkey(&bob_settle_privkey,
             &eltoo_keyset.other_settle_key);
    assert(ok);

    pubkey_ptrs[0] = &eltoo_keyset.self_funding_key;
    pubkey_ptrs[1] = &eltoo_keyset.other_funding_key;

    dust_limit.satoshis = 294;
    self_pay.millisatoshis = (update_output_sats.satoshis - 10000)*1000;
    other_pay.millisatoshis = (update_output_sats.satoshis*1000) - self_pay.millisatoshis;
    obscured_update_number = 0; /* non-0 mask not allowed currently, this should always be 0 */

    tx = initial_settlement_tx(tmpctx,
                     update_output_sats,
                     shared_delay,
                     &eltoo_keyset,
                     dust_limit,
                     self_pay,
                     other_pay,
                     obscured_update_number,
                     /* direct_outputs FIXME Cannot figure out how this is used. */ NULL);

    psbt_b64 = psbt_to_b64(tmpctx, tx->psbt);
    printf("Settlement psbt 0: %s\n", psbt_b64);

    /* Regression test vector for now */
    tx_cmp = bitcoin_tx_from_hex(tmpctx, regression_tx_hex, sizeof(regression_tx_hex)-1);
    tx_must_be_eq(tx, tx_cmp);

    /* Calculate inner pubkey, caches reused at end for tapscript signing */
    for (i=0; i<2; ++i) {
        bipmusig_inner_pubkey(&inner_pubkey,
               &keyagg_cache[i],
               pubkey_ptrs,
               /* n_pubkeys */ 2);
    }

    /* Will be bound later */
    update_tx = unbound_update_tx(tmpctx,
                     tx,
                     update_output_sats,
                     &inner_pubkey);

    /* Signing happens next */
    annex_0 = make_eltoo_annex(tmpctx, tx);
    sig = musig_sign(update_tx, annex_0, &alice_funding_privkey, &bob_funding_privkey, &inner_pubkey, keyagg_cache);

    /* Re-bind, add final script/tapscript info into PSBT */
    bind_tx_to_funding_outpoint(update_tx,
                    tx,
                    &update_output,
                    &eltoo_keyset,
                    &inner_pubkey,
                    &sig);

    psbt_b64 = psbt_to_b64(tmpctx, update_tx->psbt);
    printf("Update transaction 0: %s\n", psbt_b64);

    /* Go to second update, Bob gets paid */
    obscured_update_number++;
    self_pay.millisatoshis -= 1000;
    other_pay.millisatoshis += 1000;

    settle_tx_1 = settle_tx(tmpctx,
                     &update_output,
                     update_output_sats,
                     shared_delay,
                     &eltoo_keyset,
                     dust_limit,
                     self_pay,
                     other_pay,
                     /* htlcs */ NULL,
                     &htlc_map,
                     /* direct_outputs FIXME Cannot figure out how this is used. */ NULL,
                     obscured_update_number);

    assert(settle_tx_1);

    psbt_b64 = psbt_to_b64(tmpctx, settle_tx_1->psbt);
    printf("Settlement psbt 1: %s\n", psbt_b64);

    /* Will be bound to funding output */
    update_tx_1_A = unbound_update_tx(tmpctx,
                     settle_tx_1,
                     update_output_sats,
                     &inner_pubkey);

    /* Authorize this next state update */
    annex_1 = make_eltoo_annex(tmpctx, settle_tx_1);
    sig = musig_sign(update_tx_1_A, annex_1, &alice_funding_privkey, &bob_funding_privkey, &inner_pubkey, keyagg_cache);

    /* This can RBF the first update tx */
    bind_tx_to_funding_outpoint(update_tx_1_A,
                    settle_tx_1,
                    &update_output,
                    &eltoo_keyset,
                    &inner_pubkey,
                    &sig);

    psbt_b64 = psbt_to_b64(tmpctx, update_tx_1_A->psbt);
    printf("Update transaction 1A(funding output): %s\n", psbt_b64);

    /* Re-bind same transaction and signature to non-funding output? */
    bind_update_tx_to_update_outpoint(update_tx_1_A,
                    settle_tx_1,
                    &update_output, /* FIXME should be update_tx's first output */
                    &eltoo_keyset,
                    annex_0, /* annex you see on chain */
                    obscured_update_number - 1, /* locktime you see on old update tx */
                    &inner_pubkey,
                    &sig);

    psbt_b64 = psbt_to_b64(tmpctx, update_tx_1_A->psbt);
    printf("Update transaction 1B(update output): %s\n", psbt_b64);

	return 0;
}


static int test_initial_settlement_tx(void)
{
    struct bitcoin_outpoint update_output;
    struct amount_sat update_output_sats;
    u32 shared_delay;
    struct eltoo_keyset eltoo_keyset;
    struct amount_sat dust_limit;
    struct amount_msat self_pay;
    struct amount_msat other_pay;
    u32 obscured_update_number;
    /* struct wally_tx_output direct_outputs[NUM_SIDES]; Can't figure out how it's used */
    struct bitcoin_tx *tx, *tx_cmp, *update_tx;
    struct privkey alice_funding_privkey, bob_funding_privkey, alice_settle_privkey, bob_settle_privkey;
    int ok;
    char *psbt_b64;

    /* Aggregation stuff */
    secp256k1_musig_keyagg_cache keyagg_cache[2];
    const struct pubkey *pubkey_ptrs[2];
    int i;

    /* MuSig signing stuff */
    struct pubkey inner_pubkey;
    u8 *annex;
    struct bip340sig sig;

    /* Test initial settlement tx */

    update_output.txid = txid_from_hex("8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be");
    update_output.n = 0;
    update_output_sats.satoshis = 69420;

    alice_funding_privkey.secret = secret_from_hex("30ff4956bbdd3222d44cc5e8a1261dab1e07957bdac5ae88fe3261ef321f374901");
    bob_funding_privkey.secret = secret_from_hex("1552dfba4f6cf29a62a0af13c8d6981d36d0ef8d61ba10fb0fe90da7634d7e1301");

    ok = pubkey_from_privkey(&alice_funding_privkey,
             &eltoo_keyset.self_funding_key);
    ok = pubkey_from_privkey(&bob_funding_privkey,
             &eltoo_keyset.other_funding_key);

    shared_delay = 42;

    alice_settle_privkey.secret = secret_from_hex("1111111111111111111111111111111111111111111111111111111111111111");
    bob_settle_privkey.secret = secret_from_hex("2222222222222222222222222222222222222222222222222222222222222222");

    ok = pubkey_from_privkey(&alice_settle_privkey,
             &eltoo_keyset.self_settle_key);
    ok = pubkey_from_privkey(&bob_settle_privkey,
             &eltoo_keyset.other_settle_key);
    assert(ok);

    pubkey_ptrs[0] = &eltoo_keyset.self_funding_key;
    pubkey_ptrs[1] = &eltoo_keyset.other_funding_key;

    dust_limit.satoshis = 294;
    self_pay.millisatoshis = (update_output_sats.satoshis - 10000)*1000;
    other_pay.millisatoshis = (update_output_sats.satoshis*1000) - self_pay.millisatoshis;
    obscured_update_number = 0; /* non-0 mask not allowed currently, this should always be 0 */

    tx = initial_settlement_tx(tmpctx,
                     update_output_sats,
                     shared_delay,
                     &eltoo_keyset,
                     dust_limit,
                     self_pay,
                     other_pay,
                     obscured_update_number,
                     /* direct_outputs FIXME Cannot figure out how this is used. */ NULL);

    psbt_b64 = psbt_to_b64(tmpctx, tx->psbt);
    printf("Initial Settlement psbt: %s\n", psbt_b64);

    /* Regression test vector for now */
    tx_cmp = bitcoin_tx_from_hex(tmpctx, regression_tx_hex, sizeof(regression_tx_hex)-1);
    tx_must_be_eq(tx, tx_cmp);

    /* Calculate inner pubkey, caches reused at end for tapscript signing */
    for (i=0; i<2; ++i) {
        bipmusig_inner_pubkey(&inner_pubkey,
               &keyagg_cache[i],
               pubkey_ptrs,
               /* n_pubkeys */ 2);
    }

    /* Will be bound later */
    update_tx = unbound_update_tx(tmpctx,
                     tx,
                     update_output_sats,
                     &inner_pubkey);

    psbt_b64 = psbt_to_b64(tmpctx, update_tx->psbt);
    printf("Unbound update psbt: %s\n", psbt_b64);

    /* Signing happens next */
    annex = make_eltoo_annex(tmpctx, tx);
    sig = musig_sign(update_tx, annex, &alice_funding_privkey, &bob_funding_privkey, &inner_pubkey, keyagg_cache);

    /* We want to close the channel without cooperation... time to rebind and finalize */

    /* Re-bind, add final script/tapscript info into PSBT */
    bind_tx_to_funding_outpoint(update_tx,
                    tx,
                    &update_output,
                    &eltoo_keyset,
                    &inner_pubkey,
                    &sig);

    psbt_b64 = psbt_to_b64(tmpctx, update_tx->psbt);
    printf("Initial update psbt with finalized witness for input: %s\n", psbt_b64);

	return 0;
}

static int test_htlc_output_creation(void)
{
    struct privkey settlement_privkey;
    struct pubkey settlement_pubkey, agg_pubkey;
    const struct pubkey * pubkey_ptrs[1];
    u8 *htlc_success_script;
    u8 *htlc_timeout_script;
    u8 *tapleaf_scripts[2];
    u8 *taproot_script;
    /* 0-value hash image */
    unsigned char *invoice_hash = tal_arr(tmpctx, u8, 20);
    struct sha256 tap_merkle_root;
    struct pubkey inner_pubkey;
    secp256k1_xonly_pubkey xonly_inner_pubkey;
    unsigned char inner_pubkey_bytes[32];
    secp256k1_musig_keyagg_cache keyagg_cache;
    unsigned char tap_tweak_out[32];
    int ok;
    char *tap_hex;
    /* Ground truth generated elsewhere */
    char hex_script[] = "51201886a9f50222b126b010a811bb156cbd6572ba92282808f384e9af4a0849028d";

    settlement_privkey.secret = secret_from_hex("1552dfba4f6cf29a62a0af13c8d6981d36d0ef8d61ba10fb0fe90da7634d7e1301");

    ok = pubkey_from_privkey(&settlement_privkey,
             &settlement_pubkey);
    assert(ok);

    pubkey_ptrs[0] = &settlement_pubkey;

    /* Calculate inner pubkey */
    bipmusig_inner_pubkey(&inner_pubkey,
           &keyagg_cache,
           pubkey_ptrs,
           /* n_pubkeys */ 1);

    ok = secp256k1_xonly_pubkey_from_pubkey(secp256k1_ctx,
        &xonly_inner_pubkey,
        NULL /* pk_parity */,
        &inner_pubkey.pubkey);

    ok = secp256k1_xonly_pubkey_serialize(secp256k1_ctx, inner_pubkey_bytes, &xonly_inner_pubkey);
    assert(ok);

    htlc_success_script = make_eltoo_htlc_success_script(tmpctx, &settlement_pubkey, invoice_hash);
    htlc_timeout_script = make_eltoo_htlc_timeout_script(tmpctx, &settlement_pubkey, 420);
    tapleaf_scripts[0] = htlc_success_script;
    tapleaf_scripts[1] = htlc_timeout_script;
    compute_taptree_merkle_root(&tap_merkle_root, tapleaf_scripts, /* num_scripts */ 2);
    bipmusig_finalize_keys(&agg_pubkey, &keyagg_cache, pubkey_ptrs, /* n_pubkeys */ 1,
           &tap_merkle_root, tap_tweak_out);
    taproot_script = scriptpubkey_p2tr(tmpctx, &agg_pubkey);
    /* Size of OP_1 <tap key> script in hex output*/
    assert(tal_count(taproot_script) == 1+1+32);
    tap_hex = tal_hexstr(tmpctx, taproot_script, tal_count(taproot_script));
    assert(tal_count(tap_hex) == (1+1+32)*2 + 1);
    assert(!memcmp(tap_hex, hex_script, tal_count(tap_hex)));
    return 0;
}

int main(int argc, const char *argv[])
{
    int err = 0;

	common_setup(argv[0]);

    chainparams = chainparams_for_network("bitcoin");

    err |= test_initial_settlement_tx();
    assert(!err);

    err |= test_htlc_output_creation();
    assert(!err);

    err |= test_settlement_tx();
    assert(!err);

    err |= test_invalid_update_tx();
    assert(!err);

	common_shutdown();

    return err;
}

