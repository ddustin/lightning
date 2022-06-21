#ifndef LIGHTNING_BITCOIN_SIGNATURE_H
#define LIGHTNING_BITCOIN_SIGNATURE_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_musig.h>

struct sha256_double;
struct sha256_ctx;
struct bitcoin_tx;
struct pubkey;
struct point32;
struct privkey;
struct bitcoin_tx_output;

enum sighash_type {
    SIGHASH_ALL = 1,
    SIGHASH_NONE = 2,
    SIGHASH_SINGLE = 3,
    SIGHASH_ANYONECANPAY = 0x80
};

/* Schnorr */
struct bip340sig {
	u8 u8[64];
};

#define SIGHASH_MASK 0x7F

static inline bool sighash_single(enum sighash_type sighash_type)
{
	return (sighash_type & SIGHASH_MASK) == SIGHASH_SINGLE;
}

static inline bool sighash_anyonecanpay(enum sighash_type sighash_type)
{
	return (sighash_type & SIGHASH_ANYONECANPAY) == SIGHASH_ANYONECANPAY;
}

/* We only support a limited range of sighash_type */
static inline bool sighash_type_valid(const enum sighash_type sighash_type)
{
	return sighash_type == SIGHASH_ALL
		|| sighash_type == (SIGHASH_SINGLE|SIGHASH_ANYONECANPAY);
}

/**
 * bitcoin_signature - signature with a sighash type.
 *
 * sighash_type is SIGHASH_ALL unless you're being tricky. */
struct bitcoin_signature {
	secp256k1_ecdsa_signature s;
	enum sighash_type sighash_type;
};

/**
 * bitcoin_tx_hash_for_sig - produce hash for a transaction
 *
 * @tx - tx to hash
 * @in - index that this 'hash' is for
 * @script - script for the index that's being 'hashed for'
 * @sighash_type - sighash_type to hash for
 * @dest - hash result
 */
void bitcoin_tx_hash_for_sig(const struct bitcoin_tx *tx, unsigned int in,
			     const u8 *script,
			     enum sighash_type sighash_type,
			     struct sha256_double *dest);

/**
 * bitcoin_tx_taproot_hash_for_sig - produce hash for a taproot spend
 *
 * @tx - tx to hash
 * @input_index - index that this 'hash' is for
 * @sighash_type - sighash_type to hash for
 * @tapleaf_script - tapscript leaf for the index that's being 'hashed for', NULL if keyspend
 * @dest - hash result
 */
void bitcoin_tx_taproot_hash_for_sig(const struct bitcoin_tx *tx,
                 unsigned int input_index,
                 enum sighash_type sighash_type,
                 const unsigned char *tapleaf_script,
			     struct sha256_double *dest);

/**
 * sign_hash - produce a raw secp256k1 signature (with low R value).
 * @p: secret key
 * @h: hash to sign.
 * @sig: signature to fill in and return.
 */
void sign_hash(const struct privkey *p,
	       const struct sha256_double *h,
	       secp256k1_ecdsa_signature *sig);

/**
 * bip340_sign_hash - produce a raw BIP340 signature
 * @privkey: secret key
 * @hash: hash to sign.
 * @sig: signature to fill and return
 */
void bip340_sign_hash(const struct privkey *privkey,
           const struct sha256_double *hash,
           struct bip340sig *sig);

/**
 * bipmusig_partial_sign - produce a partial BIP340 signature.
 * This assumed an already existing session with pubkeys aggregated
 * and nonces collected, aggregated, and processed.
 * This is called after _____ FIXME.
 * @privkey: secret key
 * @secnonce: secret nonce used *once* to partially sign
 * @session: session information for signing attempt
 * @p_sig: partial signature to fill and return
 */
void bipmusig_partial_sign(const struct privkey *privkey,
           secp256k1_musig_secnonce *secnonce,
           secp256k1_musig_keyagg_cache *cache,
           secp256k1_musig_session *session,
           secp256k1_musig_partial_sig *p_sig);

/**
 * bipmusig_partial_sigs_combine_verify - combine and verify partial MuSig signatures
 * @p_sigs: partial signatures to combine and validate
 * @num_signers: number of partial signatures to combine
 * @agg_pk: aggregated public key signature is validated against
 * @hash: hash to validate signature against
 * @sig: final BIP340 signature to output
 */
bool bipmusig_partial_sigs_combine_verify(const secp256k1_musig_partial_sig * const *p_sigs,
           size_t num_signers,
           const secp256k1_xonly_pubkey *agg_pk,
           secp256k1_musig_session *session,
           const struct sha256_double *hash,
           struct bip340sig *sig);

/**
 * check_signed_hash - check a raw secp256k1 signature.
 * @h: hash which was signed.
 * @signature: signature.
 * @key: public key corresponding to private key used to sign.
 *
 * Returns true if the key, hash and signature are correct.  Changing any
 * one of these will make it fail.
 */
bool check_signed_hash(const struct sha256_double *hash,
		       const secp256k1_ecdsa_signature *signature,
		       const struct pubkey *key);

/**
 * check_signed_bip340_hash - check a raw BIP340 signature.
 * @hash: hash which was signed.
 * @signature: BIP340 signature.
 * @key: x-only public key corresponding to private key used to sign.
 *
 * Returns true if the key, hash and signature are correct.  Changing any
 * one of these will make it fail.
 */
bool check_signed_bip340_hash(const struct sha256_double *hash,
               const struct bip340sig *signature,
		       const struct point32 *key);

/**
 * sign_tx_input - produce a bitcoin signature for a transaction input
 * @tx: the bitcoin transaction we're signing.
 * @in: the input number to sign.
 * @subscript: NULL (pure segwit) or a tal_arr of the signing subscript
 * @witness: NULL (non-segwit) or the witness script.
 * @privkey: the secret key to use for signing.
 * @pubkey: the public key corresonding to @privkey.
 * @sighash_type: a valid sighash type.
 * @sig: (in) sighash_type indicates what type of signature make in (out) s.
 */
void sign_tx_input(const struct bitcoin_tx *tx,
		   unsigned int in,
		   const u8 *subscript,
		   const u8 *witness,
		   const struct privkey *privkey, const struct pubkey *pubkey,
		   enum sighash_type sighash_type,
		   struct bitcoin_signature *sig);

/**
 * sign_tx_taproot_input - produce a bitcoin signature for a taproot transaction input
 * @tx: the bitcoin transaction we're signing.
 * @input_index: the input number to sign.
 * @sighash_type: a valid sighash type.
 * @tapleaf_script: tapscript leaf script to hash.
 * @key_pair: the BIP340 keypair to use for signing and verification.
 * @sig: (in) sighash_type indicates what type of signature make.
 */
void sign_tx_taproot_input(const struct bitcoin_tx *tx,
           unsigned int input_index,
           enum sighash_type sighash_type,
           const u8 *tapleaf_script,
           const secp256k1_keypair *key_pair,
           struct bip340sig *sig);

/**
 * check_tx_sig - produce a bitcoin signature for a transaction input
 * @tx: the bitcoin transaction which has been signed.
 * @in: the input number to which @sig should apply.
 * @subscript: NULL (pure segwit) or a tal_arr of the signing subscript
 * @witness: NULL (non-segwit) or the witness script.
 * @pubkey: the public key corresonding to @privkey used for signing.
 * @sig: the signature to check.
 *
 * Returns true if this signature was created by @privkey and this tx
 * and sighash_type, otherwise false.
 */
bool check_tx_sig(const struct bitcoin_tx *tx, size_t input_num,
		  const u8 *subscript,
		  const u8 *witness,
		  const struct pubkey *key,
		  const struct bitcoin_signature *sig);

/**
 * check_tx_taproot_sig - check a bitcoin signature for a transaction input
 * @tx: the bitcoin transaction which has been signed.
 * @input_num: the input number to which @sig should apply.
 * @tapleaf_script: NULL(keyspend) or the tapscript leaf script to hash.
 * @key: the x-only public key corresonding to the signature.
 * @sighash_type: sighash type for @sig.
 * @sig: the signature to check.
 *
 * Returns true if this signature was created by @privkey and this tx
 * and sighash_type, otherwise false.
 */
bool check_tx_taproot_sig(const struct bitcoin_tx *tx, size_t input_num,
		  const u8 *tapleaf_script,
          const struct point32 *x_key,
          enum sighash_type sighash_type,
          const struct bip340sig *sig);

/* Give DER encoding of signature: returns length used (<= 73). */
size_t signature_to_der(u8 der[73], const struct bitcoin_signature *sig);

/* Parse DER encoding into signature sig */
bool signature_from_der(const u8 *der, size_t len, struct bitcoin_signature *sig);

/* Wire marshalling and unmarshalling */
void towire_bitcoin_signature(u8 **pptr, const struct bitcoin_signature *sig);
void fromwire_bitcoin_signature(const u8 **cursor, size_t *max,
				struct bitcoin_signature *sig);

void towire_bip340sig(u8 **pptr, const struct bip340sig *bip340sig);
void fromwire_bip340sig(const u8 **cursor, size_t *max,
			struct bip340sig *bip340sig);

/* Get a hex string sig */
char *fmt_signature(const tal_t *ctx, const secp256k1_ecdsa_signature *sig);
char *fmt_bip340sig(const tal_t *ctx, const struct bip340sig *bip340sig);

/* For caller convenience, we hand in tag in parts (any can be "") */
void bip340_sighash_init(struct sha256_ctx *sctx,
			 const char *tag1,
			 const char *tag2,
			 const char *tag3);

#endif /* LIGHTNING_BITCOIN_SIGNATURE_H */
