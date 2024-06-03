#include "config.h"
#include "../version.c"
#include <assert.h>
#include <bitcoin/chainparams.h>
#include <ccan/str/hex/hex.h>
#include <common/addr.h>
#include <common/json_command.h>
#include <common/setup.h>
#include <common/utils.h>

struct command_result *command_fail(struct command *cmd, enum jsonrpc_errcode code, const char *fmt, ...)
{ fprintf(stderr, "command_fail called!\n"); abort(); }

struct json_filter **command_filter_ptr(struct command *cmd)
{ fprintf(stderr, "command_filter_ptr called!\n"); abort(); }

const char *mvt_tag_str(enum mvt_tag tag UNNEEDED)
{ fprintf(stderr, "mvt_tag_str called!\n"); abort(); }

struct test_case {
	const char *scriptpubkey;
	const char *address;
};

struct test_case test_case[] =
{
	/* Segwit BIP 173 */
	{ "0014751e76e8199196d454941c45d1b3a323f1433bd6", "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", },
	{ "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262", "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", },
	{ "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6", "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx", },
	{ "6002751e", "BC1SW50QA3JX3S", },
	{ "5210751e76e8199196d454941c45d1b3a323", "bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj", },
	{ "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433", "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy", },
	/* Taproot BIP 341 */
	{ "512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343", "bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5", },
	{ "5120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3", "bc1pz37fc4cn9ah8anwm4xqqhvxygjf9rjf2resrw8h8w4tmvcs0863sa2e586", },
	{ "5120e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e", "bc1punvppl2stp38f7kwv2u2spltjuvuaayuqsthe34hd2dyy5w4g58qqfuag5", },
	{ "5120712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5", "bc1pwyjywgrd0ffr3tx8laflh6228dj98xkjj8rum0zfpd6h0e930h6saqxrrm", },
	{ "512077e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220", "bc1pwl3s54fzmk0cjnpl3w9af39je7pv5ldg504x5guk2hpecpg2kgsqaqstjq", },
	{ "512091b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605", "bc1pjxmy65eywgafs5tsunw95ruycpqcqnev6ynxp7jaasylcgtcxczs6n332e", },
	{ "512075169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831", "bc1pw5tf7sqp4f50zka7629jrr036znzew70zxyvvej3zrpf8jg8hqcssyuewe", },
};

int main(int argc, char *argv[])
{
	common_setup(argv[0]);

	chainparams = chainparams_for_network("bitcoin");

	(void)test_case;

	/* DTODO: Build out test case */

	common_shutdown();

	return 0;
}
