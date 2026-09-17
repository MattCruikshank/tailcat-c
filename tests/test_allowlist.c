/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Which clients a server will talk to.
 *
 * Small enough to read in one sitting, and worth testing carefully anyway:
 * every mistake here fails *open*. A list that silently admits more than the
 * user wrote looks exactly like a list that works.
 */

#include "tc/allowlist.h"

#include "tctest.h"

static const char kA[] =
    "nodekey:0000000000000000000000000000000000000000000000000000000000000001";
static const char kB[] =
    "nodekey:0000000000000000000000000000000000000000000000000000000000000002";

static void key_of(uint8_t out[32], uint8_t last)
{
	memset(out, 0, 32);
	out[31] = last;
}

static void test_no_list_allows_everyone(void)
{
	TCT_CASE("with no list, every client is allowed");
	/* The pre-4.x behaviour, and still the default: the address is the
	 * credential. */
	tc_allowlist l;
	memset(&l, 0, sizeof l);
	uint8_t k[32];
	key_of(k, 1);
	TCT_TRUE(tc_allow_permits(&l, k));
	key_of(k, 99);
	TCT_TRUE(tc_allow_permits(&l, k));
	TCT_TRUE(tc_allow_permits(NULL, k));
}

static void test_a_list_admits_only_what_is_on_it(void)
{
	TCT_CASE("a list admits the keys on it and nothing else");
	tc_allowlist l;
	memset(&l, 0, sizeof l);
	TCT_EQ_INT(tc_allow_parse(&l, kA), TC_OK);
	TCT_EQ_INT((int)l.num, 1);
	TCT_TRUE(l.active);

	uint8_t k[32];
	key_of(k, 1);
	TCT_TRUE(tc_allow_permits(&l, k));
	key_of(k, 2);
	TCT_TRUE(!tc_allow_permits(&l, k));
	memset(k, 0, sizeof k);
	TCT_TRUE(!tc_allow_permits(&l, k));

	TCT_CASE("several, comma separated, with whitespace tolerated");
	memset(&l, 0, sizeof l);
	char both[200];
	snprintf(both, sizeof both, "%s , %s", kA, kB);
	TCT_EQ_INT(tc_allow_parse(&l, both), TC_OK);
	TCT_EQ_INT((int)l.num, 2);
	key_of(k, 1);
	TCT_TRUE(tc_allow_permits(&l, k));
	key_of(k, 2);
	TCT_TRUE(tc_allow_permits(&l, k));
	key_of(k, 3);
	TCT_TRUE(!tc_allow_permits(&l, k));

	TCT_CASE("a duplicate does not consume a slot");
	memset(&l, 0, sizeof l);
	char thrice[300];
	snprintf(thrice, sizeof thrice, "%s,%s,%s", kA, kA, kA);
	TCT_EQ_INT(tc_allow_parse(&l, thrice), TC_OK);
	TCT_EQ_INT((int)l.num, 1);

	TCT_CASE("upper and lower case hex are the same key");
	memset(&l, 0, sizeof l);
	char upper[200];
	snprintf(upper, sizeof upper, "nodekey:%064X", 1);
	TCT_EQ_INT(tc_allow_parse(&l, upper), TC_OK);
	key_of(k, 1);
	TCT_TRUE(tc_allow_permits(&l, k));

	TCT_CASE("folding a second spec onto the same list adds to it");
	/* So the flag can be given more than once, which is what anyone
	 * assembling a list from a script will do. */
	memset(&l, 0, sizeof l);
	TCT_EQ_INT(tc_allow_parse(&l, kA), TC_OK);
	TCT_EQ_INT(tc_allow_parse(&l, kB), TC_OK);
	TCT_EQ_INT((int)l.num, 2);
	key_of(k, 2);
	TCT_TRUE(tc_allow_permits(&l, k));
}

static void test_none(void)
{
	TCT_CASE("\"none\" admits nobody");
	/* Spelled as upstream spells it. The subtlety is that it must leave the
	 * list *active* with nothing on it -- "allow nobody" quietly meaning
	 * "allow everybody" is the failure that would look like success. */
	tc_allowlist l;
	memset(&l, 0, sizeof l);
	TCT_EQ_INT(tc_allow_parse(&l, "none"), TC_OK);
	TCT_TRUE(l.active);
	TCT_EQ_INT((int)l.num, 0);

	uint8_t k[32];
	for (int i = 0; i < 256; i++) {
		key_of(k, (uint8_t)i);
		if (tc_allow_permits(&l, k))
			TCT_FAILF("\"none\" admitted a client");
		tct_checks++;
	}

	TCT_CASE("the all-zero key is refused even when it is on the list");
	/* No real client holds it -- it is the X25519 identity element, with no
	 * private key behind it -- but "no client can" is weaker than "we do not
	 * accept it". Put it on the list explicitly and it is still refused. */
	memset(k, 0, sizeof k);
	TCT_TRUE(!tc_allow_permits(&l, k));

	tc_allowlist z;
	memset(&z, 0, sizeof z);
	char zspec[200];
	snprintf(zspec, sizeof zspec, "nodekey:%064x", 0);
	TCT_EQ_INT(tc_allow_parse(&z, zspec), TC_OK);
	TCT_EQ_INT((int)z.num, 1);
	TCT_TRUE(!tc_allow_permits(&z, k));

	TCT_CASE("and with no list at all, which is the permissive case");
	/* The one place it matters most: "allow everyone" must still not mean
	 * "allow a client that cannot exist". */
	tc_allowlist open;
	memset(&open, 0, sizeof open);
	TCT_TRUE(!tc_allow_permits(&open, k));

	TCT_CASE("\"none\" alongside real keys keeps the real ones working");
	memset(&l, 0, sizeof l);
	char spec[200];
	snprintf(spec, sizeof spec, "none,%s", kA);
	TCT_EQ_INT(tc_allow_parse(&l, spec), TC_OK);
	key_of(k, 1);
	TCT_TRUE(tc_allow_permits(&l, k));
	memset(k, 0, sizeof k);
	TCT_TRUE(!tc_allow_permits(&l, k));
}

static void test_rejects(void)
{
	TCT_CASE("an empty --allow is refused rather than guessed at");
	/* Omitting the flag means everyone; `--allow=` is the same thing typed
	 * differently. Making it mean "nobody" would be a trap with no way to
	 * tell from the command line which reading applied. */
	tc_allowlist l;
	memset(&l, 0, sizeof l);
	TCT_EQ_INT(tc_allow_parse(&l, ""), TC_ERR_INVAL);
	TCT_TRUE(!l.active);

	TCT_CASE("malformed entries");
	static const char *const bad[] = {
		",",
		"nodekey:",
		"nodekey:00",
		"0000000000000000000000000000000000000000000000000000000000000001",
		"discokey:0000000000000000000000000000000000000000000000000000000000000001",
		"nodekey:000000000000000000000000000000000000000000000000000000000000000g",
		"nodekey:00000000000000000000000000000000000000000000000000000000000000001",
		"NONE",
		"none ,",
		"nodekey:0000000000000000000000000000000000000000000000000000000000000001,",
		",nodekey:0000000000000000000000000000000000000000000000000000000000000001",
	};
	for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
		tc_allowlist t;
		memset(&t, 0, sizeof t);
		if (tc_allow_parse(&t, bad[i]) == TC_OK)
			TCT_FAILF("accepted \"%s\"", bad[i]);
		tct_checks++;
		TCT_TRUE(tc_allow_error_string()[0] != '\0');
	}

	TCT_CASE("a bare hex key is refused, and the message says why");
	/* The same 32 bytes are a node key, a disco key or a PSK depending on
	 * the prefix. Accepting a bare string would mean accepting a disco key
	 * where a node key belongs. */
	tc_allowlist bare;
	memset(&bare, 0, sizeof bare);
	TCT_EQ_INT(tc_allow_parse(&bare, kA + 8), TC_ERR_INVAL);
	TCT_TRUE(strstr(tc_allow_error_string(), "nodekey") != NULL);

	TCT_CASE("a failed parse does not leave a half-built list");
	/* The dangerous case: if entry three is malformed and entries one and
	 * two stayed, a typo would produce a *shorter* list that still looks
	 * like it works. The caller is told it failed, and must not use it. */
	memset(&l, 0, sizeof l);
	char spec[300];
	snprintf(spec, sizeof spec, "%s,%s,garbage", kA, kB);
	TCT_EQ_INT(tc_allow_parse(&l, spec), TC_ERR_INVAL);
	TCT_TRUE(!l.active);
	uint8_t k[32];
	key_of(k, 1);
	/* Not active, so permits() says yes -- which is why the caller must
	 * treat a parse failure as fatal rather than carrying on. */
	TCT_TRUE(tc_allow_permits(&l, k));

	TCT_CASE("more keys than the table holds is refused, not truncated");
	memset(&l, 0, sizeof l);
	char big[TC_ALLOW_MAX * 80 + 200];
	size_t off = 0;
	for (int i = 0; i < TC_ALLOW_MAX + 1; i++)
		off += (size_t)snprintf(big + off, sizeof big - off,
		                        "%snodekey:%064x", i ? "," : "", i + 1);
	TCT_EQ_INT(tc_allow_parse(&l, big), TC_ERR_TOOMANY);

	TCT_CASE("exactly as many as it holds is fine");
	memset(&l, 0, sizeof l);
	off = 0;
	for (int i = 0; i < TC_ALLOW_MAX; i++)
		off += (size_t)snprintf(big + off, sizeof big - off,
		                        "%snodekey:%064x", i ? "," : "", i + 1);
	TCT_EQ_INT(tc_allow_parse(&l, big), TC_OK);
	TCT_EQ_INT((int)l.num, TC_ALLOW_MAX);

	TCT_CASE("null arguments");
	TCT_EQ_INT(tc_allow_parse(NULL, kA), TC_ERR_INVAL);
	TCT_EQ_INT(tc_allow_parse(&l, NULL), TC_ERR_INVAL);
	TCT_TRUE(!tc_allow_permits(&l, NULL));
}

int main(void)
{
	test_no_list_allows_everyone();
	test_a_list_admits_only_what_is_on_it();
	test_none();
	test_rejects();
	return tct_report("allowlist");
}
