#include "config.h"
#include "../hmac.c"
#include "../onion_decode.c"
#include "../onion_encode.c"
#include "../onionreply.c"
#include "../sphinx.c"
#include <ccan/str/hex/hex.h>
#include <common/setup.h>
#include <stdio.h>

/* AUTOGENERATED MOCKS START */
/* Generated stub for amount_asset_is_main */
bool amount_asset_is_main(struct amount_asset *asset UNNEEDED)
{ fprintf(stderr, "amount_asset_is_main called!\n"); abort(); }
/* Generated stub for amount_asset_to_sat */
struct amount_sat amount_asset_to_sat(struct amount_asset *asset UNNEEDED)
{ fprintf(stderr, "amount_asset_to_sat called!\n"); abort(); }
/* Generated stub for amount_msat */
struct amount_msat amount_msat(u64 millisatoshis UNNEEDED)
{ fprintf(stderr, "amount_msat called!\n"); abort(); }
/* Generated stub for amount_msat_eq */
bool amount_msat_eq(struct amount_msat a UNNEEDED, struct amount_msat b UNNEEDED)
{ fprintf(stderr, "amount_msat_eq called!\n"); abort(); }
/* Generated stub for amount_msat_less */
bool amount_msat_less(struct amount_msat a UNNEEDED, struct amount_msat b UNNEEDED)
{ fprintf(stderr, "amount_msat_less called!\n"); abort(); }
/* Generated stub for amount_sat */
struct amount_sat amount_sat(u64 satoshis UNNEEDED)
{ fprintf(stderr, "amount_sat called!\n"); abort(); }
/* Generated stub for amount_sat_add */
 bool amount_sat_add(struct amount_sat *val UNNEEDED,
				       struct amount_sat a UNNEEDED,
				       struct amount_sat b UNNEEDED)
{ fprintf(stderr, "amount_sat_add called!\n"); abort(); }
/* Generated stub for amount_sat_div */
struct amount_sat amount_sat_div(struct amount_sat sat UNNEEDED, u64 div UNNEEDED)
{ fprintf(stderr, "amount_sat_div called!\n"); abort(); }
/* Generated stub for amount_sat_eq */
bool amount_sat_eq(struct amount_sat a UNNEEDED, struct amount_sat b UNNEEDED)
{ fprintf(stderr, "amount_sat_eq called!\n"); abort(); }
/* Generated stub for amount_sat_greater_eq */
bool amount_sat_greater_eq(struct amount_sat a UNNEEDED, struct amount_sat b UNNEEDED)
{ fprintf(stderr, "amount_sat_greater_eq called!\n"); abort(); }
/* Generated stub for amount_sat_mul */
bool amount_sat_mul(struct amount_sat *res UNNEEDED, struct amount_sat sat UNNEEDED, u64 mul UNNEEDED)
{ fprintf(stderr, "amount_sat_mul called!\n"); abort(); }
/* Generated stub for amount_sat_sub */
 bool amount_sat_sub(struct amount_sat *val UNNEEDED,
				       struct amount_sat a UNNEEDED,
				       struct amount_sat b UNNEEDED)
{ fprintf(stderr, "amount_sat_sub called!\n"); abort(); }
/* Generated stub for amount_sat_to_asset */
struct amount_asset amount_sat_to_asset(struct amount_sat *sat UNNEEDED, const u8 *asset UNNEEDED)
{ fprintf(stderr, "amount_sat_to_asset called!\n"); abort(); }
/* Generated stub for amount_tx_fee */
struct amount_sat amount_tx_fee(u32 fee_per_kw UNNEEDED, size_t weight UNNEEDED)
{ fprintf(stderr, "amount_tx_fee called!\n"); abort(); }
/* Generated stub for bigsize_get */
size_t bigsize_get(const u8 *p UNNEEDED, size_t max UNNEEDED, bigsize_t *val UNNEEDED)
{ fprintf(stderr, "bigsize_get called!\n"); abort(); }
/* Generated stub for bigsize_put */
size_t bigsize_put(u8 buf[BIGSIZE_MAX_LEN] UNNEEDED, bigsize_t v UNNEEDED)
{ fprintf(stderr, "bigsize_put called!\n"); abort(); }
/* Generated stub for decrypt_encrypted_data */
struct tlv_encrypted_data_tlv *decrypt_encrypted_data(const tal_t *ctx UNNEEDED,
						      const struct pubkey *blinding UNNEEDED,
						      const struct secret *ss UNNEEDED,
						      const u8 *enctlv)

{ fprintf(stderr, "decrypt_encrypted_data called!\n"); abort(); }
/* Generated stub for ecdh */
void ecdh(const struct pubkey *point UNNEEDED, struct secret *ss UNNEEDED)
{ fprintf(stderr, "ecdh called!\n"); abort(); }
/* Generated stub for fromwire_amount_msat */
struct amount_msat fromwire_amount_msat(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_amount_msat called!\n"); abort(); }
/* Generated stub for fromwire_bigsize */
bigsize_t fromwire_bigsize(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_bigsize called!\n"); abort(); }
/* Generated stub for fromwire_tlv */
bool fromwire_tlv(const u8 **cursor UNNEEDED, size_t *max UNNEEDED,
		  const struct tlv_record_type *types UNNEEDED, size_t num_types UNNEEDED,
		  void *record UNNEEDED, struct tlv_field **fields UNNEEDED,
		  const u64 *extra_types UNNEEDED, size_t *err_off UNNEEDED, u64 *err_type UNNEEDED)
{ fprintf(stderr, "fromwire_tlv called!\n"); abort(); }
/* Generated stub for pubkey_from_node_id */
bool pubkey_from_node_id(struct pubkey *key UNNEEDED, const struct node_id *id UNNEEDED)
{ fprintf(stderr, "pubkey_from_node_id called!\n"); abort(); }
/* Generated stub for tlv_field_offset */
size_t tlv_field_offset(const u8 *tlvstream UNNEEDED, size_t tlvlen UNNEEDED, u64 fieldtype UNNEEDED)
{ fprintf(stderr, "tlv_field_offset called!\n"); abort(); }
/* Generated stub for towire_amount_msat */
void towire_amount_msat(u8 **pptr UNNEEDED, const struct amount_msat msat UNNEEDED)
{ fprintf(stderr, "towire_amount_msat called!\n"); abort(); }
/* Generated stub for towire_bigsize */
void towire_bigsize(u8 **pptr UNNEEDED, const bigsize_t val UNNEEDED)
{ fprintf(stderr, "towire_bigsize called!\n"); abort(); }
/* Generated stub for towire_tlv */
void towire_tlv(u8 **pptr UNNEEDED,
		const struct tlv_record_type *types UNNEEDED, size_t num_types UNNEEDED,
		const void *record UNNEEDED)
{ fprintf(stderr, "towire_tlv called!\n"); abort(); }
/* AUTOGENERATED MOCKS END */

extern secp256k1_context *secp256k1_ctx;

static struct secret secret_from_hex(const char *hex)
{
	struct secret s;
	if (!hex_decode(hex, strlen(hex), &s, sizeof(s)))
		abort();
	return s;
}

/* Create an onionreply with the test vector parameters and check that
 * we match the test vectors and that we can also unwrap it. */
static void run_unit_tests(void)
{
	u8 *oreply;
	struct onionreply *reply;
	int origin_index;
	u8 *raw = tal_hexdata(tmpctx, "2002", 4);

	/* Shared secrets we already have from the forward path */
	char *secrets[] = {
	    "53eb63ea8a3fec3b3cd433b85cd62a4b145e1dda09391b348c4e1cd36a03ea66",
	    "a6519e98832a0b179f62123b3567c106db99ee37bef036e783263602f3488fae",
	    "3a6b412548762f0dbccce5c7ae7bb8147d1caf9b5471c34120b30bc9c04891cc",
	    "21e13c2d7cfe7e18836df50872466117a295783ab8aab0e7ecc8c725503ad02d",
	    "b5756b9b542727dbafc6765a49488b023a725d631af688fc031217e90770c328",
	};
	struct secret ss[] = {
		secret_from_hex(secrets[0]),
		secret_from_hex(secrets[1]),
		secret_from_hex(secrets[2]),
		secret_from_hex(secrets[3]),
		secret_from_hex(secrets[4])
	};

	int replylen = 292 * 2;

	u8 *intermediates[] = {
	    tal_hexdata(tmpctx, "9c5add3963fc7f6ed7f148623c84134b5647e1306419db"
				"e2174e523fa9e2fbed3a06a19f899145610741c83ad40b"
				"7712aefaddec8c6baf7325d92ea4ca4d1df8bce517f7e5"
				"4554608bf2bd8071a4f52a7a2f7ffbb1413edad81eeea5"
				"785aa9d990f2865dc23b4bc3c301a94eec4eabebca66be"
				"5cf638f693ec256aec514620cc28ee4a94bd9565bc4d49"
				"62b9d3641d4278fb319ed2b84de5b665f307a2db0f7fbb"
				"757366067d88c50f7e829138fde4f78d39b5b5802f1b92"
				"a8a820865af5cc79f9f30bc3f461c66af95d13e5e1f038"
				"1c184572a91dee1c849048a647a1158cf884064deddbf1"
				"b0b88dfe2f791428d0ba0f6fb2f04e14081f69165ae66d"
				"9297c118f0907705c9c4954a199bae0bb96fad763d690e"
				"7daa6cfda59ba7f2c8d11448b604d12d",
			replylen),
	    tal_hexdata(tmpctx, "aac3200c4968f56b21f53e5e374e3a2383ad2b1b6501bb"
				"cc45abc31e59b26881b7dfadbb56ec8dae8857add94e67"
				"02fb4c3a4de22e2e669e1ed926b04447fc73034bb730f4"
				"932acd62727b75348a648a1128744657ca6a4e713b9b64"
				"6c3ca66cac02cdab44dd3439890ef3aaf61708714f7375"
				"349b8da541b2548d452d84de7084bb95b3ac2345201d62"
				"4d31f4d52078aa0fa05a88b4e20202bd2b86ac5b52919e"
				"a305a8949de95e935eed0319cf3cf19ebea61d76ba9253"
				"2497fcdc9411d06bcd4275094d0a4a3c5d3a945e43305a"
				"5a9256e333e1f64dbca5fcd4e03a39b9012d197506e06f"
				"29339dfee3331995b21615337ae060233d39befea925cc"
				"262873e0530408e6990f1cbd233a150ef7b004ff6166c7"
				"0c68d9f8c853c1abca640b8660db2921",
			replylen),
	    tal_hexdata(tmpctx, "a5d3e8634cfe78b2307d87c6d90be6fe7855b4f2cc9b1d"
				"fb19e92e4b79103f61ff9ac25f412ddfb7466e74f81b3e"
				"545563cdd8f5524dae873de61d7bdfccd496af2584930d"
				"2b566b4f8d3881f8c043df92224f38cf094cfc09d92655"
				"989531524593ec6d6caec1863bdfaa79229b5020acc034"
				"cd6deeea1021c50586947b9b8e6faa83b81fbfa6133c0a"
				"f5d6b07c017f7158fa94f0d206baf12dda6b68f785b773"
				"b360fd0497e16cc402d779c8d48d0fa6315536ef0660f3"
				"f4e1865f5b38ea49c7da4fd959de4e83ff3ab686f059a4"
				"5c65ba2af4a6a79166aa0f496bf04d06987b6d2ea205bd"
				"b0d347718b9aeff5b61dfff344993a275b79717cd815b6"
				"ad4c0beb568c4ac9c36ff1c315ec1119a1993c4b61e6ea"
				"a0375e0aaf738ac691abd3263bf937e3",
			replylen),
	    tal_hexdata(tmpctx, "c49a1ce81680f78f5f2000cda36268de34a3f0a0662f55"
				"b4e837c83a8773c22aa081bab1616a0011585323930fa5"
				"b9fae0c85770a2279ff59ec427ad1bbff9001c0cd14970"
				"04bd2a0f68b50704cf6d6a4bf3c8b6a0833399a24b3456"
				"961ba00736785112594f65b6b2d44d9f5ea4e49b5e1ec2"
				"af978cbe31c67114440ac51a62081df0ed46d4a3df295d"
				"a0b0fe25c0115019f03f15ec86fabb4c852f83449e812f"
				"141a9395b3f70b766ebbd4ec2fae2b6955bd8f32684c15"
				"abfe8fd3a6261e52650e8807a92158d9f1463261a925e4"
				"bfba44bd20b166d532f0017185c3a6ac7957adefe45559"
				"e3072c8dc35abeba835a8cb01a71a15c736911126f27d4"
				"6a36168ca5ef7dccd4e2886212602b181463e0dd30185c"
				"96348f9743a02aca8ec27c0b90dca270",
			replylen),
	    tal_hexdata(tmpctx, "a5e6bd0c74cb347f10cce367f949098f2457d14c046fd8"
				"a22cb96efb30b0fdcda8cb9168b50f2fd45edd73c1b0c8"
				"b33002df376801ff58aaa94000bf8a86f92620f343baef"
				"38a580102395ae3abf9128d1047a0736ff9b83d456740e"
				"bbb4aeb3aa9737f18fb4afb4aa074fb26c4d702f429688"
				"88550a3bded8c05247e045b866baef0499f079fdaeef65"
				"38f31d44deafffdfd3afa2fb4ca9082b8f1c465371a989"
				"4dd8c243fb4847e004f5256b3e90e2edde4c9fb3082ddf"
				"e4d1e734cacd96ef0706bf63c9984e22dc98851bcccd1c"
				"3494351feb458c9c6af41c0044bea3c47552b1d992ae54"
				"2b17a2d0bba1a096c78d169034ecb55b6e3a7263c26017"
				"f033031228833c1daefc0dedb8cf7c3e37c9c37ebfe42f"
				"3225c326e8bcfd338804c145b16e34e4",
			replylen),
	};

	reply = create_onionreply(tmpctx, &ss[4], raw);
	for (int i = 4; i >= 0; i--) {
		printf("input_packet %s\n", tal_hex(tmpctx, reply->contents));
		reply = wrap_onionreply(tmpctx, &ss[i], reply);
		printf("obfuscated_packet %s\n", tal_hex(tmpctx, reply->contents));
		assert(memcmp(reply->contents, intermediates[i], tal_count(reply->contents)) == 0);
	}

	oreply = unwrap_onionreply(tmpctx, ss, 5, reply, &origin_index);
	printf("unwrapped %s\n", tal_hex(tmpctx, oreply));
	assert(memeq(raw, tal_bytelen(raw), oreply, tal_bytelen(oreply)));
	assert(origin_index == 4);
}

int main(int argc, char **argv)
{
	common_setup(argv[0]);
	run_unit_tests();

	common_shutdown();
	return 0;
}
