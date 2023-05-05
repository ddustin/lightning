#include "config.h"
#include "../amount.c"
#include "../bigsize.c"
#include "../bolt12_merkle.c"
#include "../json_parse.c"
#include "../json_parse_simple.c"
#include "../../wire/fromwire.c"
#include "../../wire/tlvstream.c"
#if EXPERIMENTAL_FEATURES
  #include "../../wire/peer_exp_wiregen.c"
  #include "../../wire/bolt12_exp_wiregen.c"
#else
  #include "../../wire/peer_wiregen.c"
  #include "../../wire/bolt12_wiregen.c"
#endif
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/path/path.h>
#include <common/channel_type.h>
#include <common/setup.h>

/* AUTOGENERATED MOCKS START */
/* Generated stub for fromwire_blinded_path */
struct blinded_path *fromwire_blinded_path(const tal_t *ctx UNNEEDED, const u8 **cursor UNNEEDED, size_t *plen UNNEEDED)
{ fprintf(stderr, "fromwire_blinded_path called!\n"); abort(); }
/* Generated stub for fromwire_channel_id */
bool fromwire_channel_id(const u8 **cursor UNNEEDED, size_t *max UNNEEDED,
			 struct channel_id *channel_id UNNEEDED)
{ fprintf(stderr, "fromwire_channel_id called!\n"); abort(); }
/* Generated stub for fromwire_node_id */
void fromwire_node_id(const u8 **cursor UNNEEDED, size_t *max UNNEEDED, struct node_id *id UNNEEDED)
{ fprintf(stderr, "fromwire_node_id called!\n"); abort(); }
/* Generated stub for mvt_tag_str */
const char *mvt_tag_str(enum mvt_tag tag UNNEEDED)
{ fprintf(stderr, "mvt_tag_str called!\n"); abort(); }
/* Generated stub for node_id_from_hexstr */
bool node_id_from_hexstr(const char *str UNNEEDED, size_t slen UNNEEDED, struct node_id *id UNNEEDED)
{ fprintf(stderr, "node_id_from_hexstr called!\n"); abort(); }
/* Generated stub for towire */
void towire(u8 **pptr UNNEEDED, const void *data UNNEEDED, size_t len UNNEEDED)
{ fprintf(stderr, "towire called!\n"); abort(); }
/* Generated stub for towire_blinded_path */
void towire_blinded_path(u8 **p UNNEEDED, const struct blinded_path *blinded_path UNNEEDED)
{ fprintf(stderr, "towire_blinded_path called!\n"); abort(); }
/* Generated stub for towire_bool */
void towire_bool(u8 **pptr UNNEEDED, bool v UNNEEDED)
{ fprintf(stderr, "towire_bool called!\n"); abort(); }
/* Generated stub for towire_channel_id */
void towire_channel_id(u8 **pptr UNNEEDED, const struct channel_id *channel_id UNNEEDED)
{ fprintf(stderr, "towire_channel_id called!\n"); abort(); }
/* Generated stub for towire_node_id */
void towire_node_id(u8 **pptr UNNEEDED, const struct node_id *id UNNEEDED)
{ fprintf(stderr, "towire_node_id called!\n"); abort(); }
/* Generated stub for towire_secp256k1_ecdsa_signature */
void towire_secp256k1_ecdsa_signature(u8 **pptr UNNEEDED,
			      const secp256k1_ecdsa_signature *signature UNNEEDED)
{ fprintf(stderr, "towire_secp256k1_ecdsa_signature called!\n"); abort(); }
/* Generated stub for towire_sha256 */
void towire_sha256(u8 **pptr UNNEEDED, const struct sha256 *sha256 UNNEEDED)
{ fprintf(stderr, "towire_sha256 called!\n"); abort(); }
/* Generated stub for towire_tu32 */
void towire_tu32(u8 **pptr UNNEEDED, u32 v UNNEEDED)
{ fprintf(stderr, "towire_tu32 called!\n"); abort(); }
/* Generated stub for towire_tu64 */
void towire_tu64(u8 **pptr UNNEEDED, u64 v UNNEEDED)
{ fprintf(stderr, "towire_tu64 called!\n"); abort(); }
/* Generated stub for towire_u16 */
void towire_u16(u8 **pptr UNNEEDED, u16 v UNNEEDED)
{ fprintf(stderr, "towire_u16 called!\n"); abort(); }
/* Generated stub for towire_u32 */
void towire_u32(u8 **pptr UNNEEDED, u32 v UNNEEDED)
{ fprintf(stderr, "towire_u32 called!\n"); abort(); }
/* Generated stub for towire_u64 */
void towire_u64(u8 **pptr UNNEEDED, u64 v UNNEEDED)
{ fprintf(stderr, "towire_u64 called!\n"); abort(); }
/* Generated stub for towire_s64 */
void towire_s64(u8 **pptr UNNEEDED, s64 v UNNEEDED)
{ fprintf(stderr, "towire_s64 called!\n"); abort(); }
/* Generated stub for towire_u8 */
void towire_u8(u8 **pptr UNNEEDED, u8 v UNNEEDED)
{ fprintf(stderr, "towire_u8 called!\n"); abort(); }
/* Generated stub for towire_u8_array */
void towire_u8_array(u8 **pptr UNNEEDED, const u8 *arr UNNEEDED, size_t num UNNEEDED)
{ fprintf(stderr, "towire_u8_array called!\n"); abort(); }
/* Generated stub for towire_utf8_array */
void towire_utf8_array(u8 **pptr UNNEEDED, const char *arr UNNEEDED, size_t num UNNEEDED)
{ fprintf(stderr, "towire_utf8_array called!\n"); abort(); }
/* AUTOGENERATED MOCKS END */

static const struct tlv_field *tlv_to_fields(const tal_t *ctx, const u8 *tlv)
{
	struct tlv_field *fields = tal_arr(ctx, struct tlv_field, 0);
	size_t len = tal_bytelen(tlv);

	/* Dumb parser, assuming it's valid! */
	while (len) {
		struct tlv_field f;
		f.numtype = fromwire_bigsize(&tlv, &len);
		f.length = fromwire_bigsize(&tlv, &len);
		f.value = (u8 *)tlv;
		fromwire(&tlv, &len, NULL, f.length);
		tal_arr_expand(&fields, f);
	}
	return fields;
}

int main(int argc, char *argv[])
{
	char *json;
	size_t i;
	jsmn_parser parser;
	jsmntok_t toks[5000];
	const jsmntok_t *t;

	common_setup(argv[0]);

	if (argv[1])
		json = grab_file(tmpctx, argv[1]);
	else {
		char *dir = getenv("BOLTDIR");
		json = grab_file(tmpctx,
				 path_join(tmpctx,
					   dir ? dir : "../bolts",
					   "bolt12/merkle-test.json"));
		if (!json) {
			printf("test file not found, skipping\n");
			goto out;
		}
	}

	jsmn_init(&parser);
	if (jsmn_parse(&parser, json, strlen(json), toks, ARRAY_SIZE(toks)) < 0)
		abort();

	json_for_each_arr(i, t, toks) {
		const char *tlvtype;
		const u8 *tlv;
		const struct tlv_field *fields;
		struct sha256 merkle, expected_merkle;

		tlvtype = json_strdup(tmpctx, json,
				      json_get_member(json, t, "tlv"));
		tlv = json_tok_bin_from_hex(tmpctx, json,
					    json_get_member(json, t, "all-tlvs"));
		json_to_sha256(json, json_get_member(json, t, "merkle"),
			       &expected_merkle);

		printf("%s:\n", json_strdup(tmpctx, json,
					     json_get_member(json, t, "comment")));

		/* First do it raw. */
		fields = tlv_to_fields(tmpctx, tlv);
		merkle_tlv(fields, &merkle);
		assert(sha256_eq(&merkle, &expected_merkle));
		printf(" - RAW OK\n");

		/* Now do it via type-specific fromwire. */
		if (streq(tlvtype, "n1")) {
			struct tlv_n1 *n1;
			size_t len = tal_bytelen(tlv);
			n1 = fromwire_tlv_n1(tmpctx, &tlv, &len);
			assert(n1);
			assert(len == 0);
			merkle_tlv(n1->fields, &merkle);
			assert(sha256_eq(&merkle, &expected_merkle));
		} else if (streq(tlvtype, "offer")) {
			struct tlv_offer *offer;
			size_t len = tal_bytelen(tlv);
			offer = fromwire_tlv_offer(tmpctx, &tlv, &len);
			assert(offer);
			assert(len == 0);
			merkle_tlv(offer->fields, &merkle);
			assert(sha256_eq(&merkle, &expected_merkle));
		} else
			abort();
		printf(" - WRAPPED OK\n");
	}

out:
	common_shutdown();
	return 0;
}
