/* SPDX-License-Identifier: BSD-3-Clause
 *
 * ProxyCommand quoting.
 *
 * This assembles a command line that OpenSSH hands to a shell, from arguments
 * including a filesystem path this program did not choose. Getting it wrong is
 * a shell injection, so the tests here are adversarial rather than
 * illustrative: the interesting cases are the ones where a naive
 * implementation produces something that *runs*.
 */

#include "tc/shquote.h"

#include "tctest.h"

static void test_posix_basic(void)
{
	TCT_CASE("ordinary arguments are single-quoted");
	char out[512];
	const char *args[] = { "/usr/bin/tailcat-c", "tcABC", "22" };
	TCT_EQ_INT(tc_proxycmd_join(out, sizeof out, args, 3, false), TC_OK);
	TCT_EQ_STR(out, "'/usr/bin/tailcat-c' 'tcABC' '22'");

	TCT_CASE("an empty argument survives as an empty quoted string");
	/* Dropping it would shift every argument after it by one. */
	const char *empty[] = { "a", "", "b" };
	TCT_EQ_INT(tc_proxycmd_join(out, sizeof out, empty, 3, false), TC_OK);
	TCT_EQ_STR(out, "'a' '' 'b'");

	TCT_CASE("no arguments gives an empty string");
	TCT_EQ_INT(tc_proxycmd_join(out, sizeof out, args, 0, false), TC_OK);
	TCT_EQ_STR(out, "");
}

static void test_posix_hostile(void)
{
	char out[512];

	TCT_CASE("shell metacharacters are neutralised, not escaped piecemeal");
	/* Inside single quotes none of these mean anything, which is why single
	 * quoting is the right tool: there is no list of characters to remember. */
	const char *meta[] = { "/tmp/a b; rm -rf /", "$(id)", "`id`", "a|b&c" };
	TCT_EQ_INT(tc_proxycmd_join(out, sizeof out, meta, 4, false), TC_OK);
	TCT_EQ_STR(out, "'/tmp/a b; rm -rf /' '$(id)' '`id`' 'a|b&c'");

	TCT_CASE("a single quote is closed, escaped and reopened");
	/* The one character single quoting cannot contain. A naive
	 * implementation that just wraps the argument produces a command that
	 * runs, with the rest of the argument outside the quotes. */
	const char *q[] = { "it's", "a'; id; echo '" };
	TCT_EQ_INT(tc_proxycmd_join(out, sizeof out, q, 2, false), TC_OK);
	TCT_EQ_STR(out, "'it'\"'\"'s' 'a'\"'\"'; id; echo '\"'\"''");

	TCT_CASE("percent signs are doubled for OpenSSH's token expansion");
	/* OpenSSH expands %h, %p and friends before the shell sees anything, and
	 * turns %% back into a single %. An undoubled percent in a path would be
	 * silently replaced by something else. */
	const char *pct[] = { "/tmp/100%/x", "%h" };
	TCT_EQ_INT(tc_proxycmd_join(out, sizeof out, pct, 2, false), TC_OK);
	TCT_EQ_STR(out, "'/tmp/100%%/x' '%%h'");

	TCT_CASE("control characters are refused rather than quoted");
	/* A newline ends the command wherever it appears; no quoting helps. */
	static const char *const bad[] = {
		"a\nb", "a\rb", "a\tb", "\x01", "x\x7f",
	};
	for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
		const char *one[] = { bad[i] };
		TCT_EQ_INT(tc_proxycmd_join(out, sizeof out, one, 1, false),
		           TC_ERR_INVAL);
	}
}

static void test_windows(void)
{
	char out[512];

	TCT_CASE("windows arguments are double-quoted");
	const char *args[] = { "C:\\Program Files\\tailcat-c.exe", "tcABC" };
	TCT_EQ_INT(tc_proxycmd_join(out, sizeof out, args, 2, true), TC_OK);
	TCT_EQ_STR(out, "\"C:\\Program Files\\tailcat-c.exe\" \"tcABC\"");

	TCT_CASE("a trailing backslash is doubled");
	/* Otherwise it escapes the closing quote for the Windows argv parser and
	 * the next argument is swallowed into this one. */
	const char *bs[] = { "C:\\dir\\", "x" };
	TCT_EQ_INT(tc_proxycmd_join(out, sizeof out, bs, 2, true), TC_OK);
	TCT_EQ_STR(out, "\"C:\\dir\\\\\" \"x\"");

	const char *bs2[] = { "C:\\dir\\\\" };
	TCT_EQ_INT(tc_proxycmd_join(out, sizeof out, bs2, 1, true), TC_OK);
	TCT_EQ_STR(out, "\"C:\\dir\\\\\\\\\"");

	TCT_CASE("cmd.exe expansion characters are refused, not escaped");
	/* cmd.exe expands %VAR% and sometimes !VAR! even inside double quotes,
	 * and a double quote means different things to cmd.exe and to the argv
	 * parser on the other side. Claiming to escape them would be a lie. */
	static const char *const bad[] = { "a%PATH%b", "a!x!b", "a\"b" };
	for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
		const char *one[] = { bad[i] };
		TCT_EQ_INT(tc_proxycmd_join(out, sizeof out, one, 1, true),
		           TC_ERR_INVAL);
	}

	TCT_CASE("but those same characters are fine on POSIX");
	const char *ok[] = { "a%PATH%b", "a!x!b", "a\"b" };
	TCT_EQ_INT(tc_proxycmd_join(out, sizeof out, ok, 3, false), TC_OK);
	TCT_EQ_STR(out, "'a%%PATH%%b' 'a!x!b' 'a\"b'");
}

static void test_bounds(void)
{
	TCT_CASE("a buffer too small is refused rather than overrun");
	char tiny[8];
	const char *args[] = { "/a/reasonably/long/path", "tcABCDEF" };
	TCT_EQ_INT(tc_proxycmd_join(tiny, sizeof tiny, args, 2, false),
	           TC_ERR_NOSPACE);
	TCT_EQ_INT(tc_proxycmd_join(tiny, sizeof tiny, args, 2, true),
	           TC_ERR_NOSPACE);

	TCT_CASE("null arguments are refused");
	char out[64];
	const char *withnull[] = { "a", NULL };
	TCT_EQ_INT(tc_proxycmd_join(out, sizeof out, withnull, 2, false),
	           TC_ERR_INVAL);
	TCT_EQ_INT(tc_proxycmd_join(NULL, 10, args, 1, false), TC_ERR_INVAL);
	TCT_EQ_INT(tc_proxycmd_join(out, 0, args, 1, false), TC_ERR_INVAL);
	TCT_EQ_INT(tc_proxycmd_join(out, sizeof out, NULL, 1, false),
	           TC_ERR_INVAL);
}

static void test_dest_host(void)
{
	TCT_CASE("the ssh destination is short, prefixed and hex");
	char a[64], b[64];
	TCT_EQ_INT(tc_ssh_dest_host(a, sizeof a, "tcSOMEADDRESS"), TC_OK);
	TCT_EQ_INT((int)strlen(a), 24);
	TCT_TRUE(strncmp(a, "tailcat-", 8) == 0);
	for (const char *p = a + 8; *p; p++)
		TCT_TRUE((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f'));

	TCT_CASE("it is stable for the same address");
	/* ssh keys its ControlPath on this, so an address that hashed
	 * differently between runs would silently stop reusing the right
	 * multiplexed connection. */
	TCT_EQ_INT(tc_ssh_dest_host(b, sizeof b, "tcSOMEADDRESS"), TC_OK);
	TCT_EQ_STR(a, b);

	TCT_CASE("and differs for a different address");
	TCT_EQ_INT(tc_ssh_dest_host(b, sizeof b, "tcOTHERADDRESS"), TC_OK);
	TCT_TRUE(strcmp(a, b) != 0);

	TCT_CASE("it fits an AF_UNIX ControlPath with room to spare");
	/* The reason it exists: ~/.ssh/master-%r@%n:%p has to stay under about
	 * a hundred bytes, and a tailcat address alone can exceed that. */
	TCT_TRUE(strlen(a) < 32);

	TCT_CASE("a short buffer is refused");
	char tiny[8];
	TCT_EQ_INT(tc_ssh_dest_host(tiny, sizeof tiny, "tcX"), TC_ERR_NOSPACE);
	TCT_EQ_INT(tc_ssh_dest_host(NULL, 64, "tcX"), TC_ERR_NOSPACE);
	TCT_EQ_INT(tc_ssh_dest_host(a, sizeof a, NULL), TC_ERR_NOSPACE);
}

int main(void)
{
	test_posix_basic();
	test_posix_hostile();
	test_windows();
	test_bounds();
	test_dest_host();
	return tct_report("shquote");
}
