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

/* ---- finding the destination among ssh's arguments --------------------- */

/* Each case is an argument vector and the index the destination should be
 * found at, written the way it would be typed. The destination is always
 * spelled "HOST" so a wrong answer names what was picked instead. */
static void at(size_t want, const char *const *args, size_t n,
               const char *why)
{
	tct_checks++;
	size_t got = tc_ssh_dest_index(args, n);
	if (got != want) {
		const char *picked = got < n ? args[got] : "(none)";
		TCT_FAILF("%s: picked [%zu] \"%s\", wanted [%zu] \"%s\"", why, got,
		          picked, want, want < n ? args[want] : "(none)");
	}
}

#define AT(want, why, ...)                                                    \
	do {                                                                      \
		static const char *const a_[] = { __VA_ARGS__ };                      \
		at((want), a_, sizeof a_ / sizeof a_[0], (why));                      \
	} while (0)

static void test_dest_index(void)
{
	TCT_CASE("the ordinary shapes");
	AT(0, "just a host", "HOST");
	AT(0, "a host and a command", "HOST", "uptime");
	AT(0, "a command that looks like a flag", "HOST", "-l");
	AT(0, "a user@host", "user@HOST");

	TCT_CASE("flags before the destination");
	AT(1, "a boolean", "-v", "HOST");
	AT(3, "several booleans", "-v", "-4", "-C", "HOST");
	AT(1, "clustered booleans", "-vvv", "HOST");
	AT(1, "-tt, the one everyone types", "-tt", "HOST");
	AT(2, "a separated value", "-i", "key", "HOST");
	AT(1, "an attached value", "-ikey", "HOST");
	AT(2, "-o with a value", "-o", "Foo=bar", "HOST");
	AT(4, "two options", "-o", "A=1", "-o", "B=2", "HOST");
	AT(2, "-p with a port", "-p", "2222", "HOST");
	AT(1, "-p2222 attached", "-p2222", "HOST");
	AT(2, "-l with a user", "-l", "alice", "HOST");
	AT(5, "the lot", "-v", "-i", "key", "-o", "Foo=bar", "HOST", "uptime");

	TCT_CASE("a value attached to a cluster");
	/* -vi key: the v is boolean, the i takes the next argument. Getting the
	 * cluster wrong here reads "key" as the destination. */
	AT(2, "a boolean then a value flag", "-vi", "key", "HOST");
	/* -vikey: the value is attached to the cluster, so nothing is skipped. */
	AT(1, "a boolean then an attached value", "-vikey", "HOST");

	TCT_CASE("the edges");
	AT(0, "a bare dash is not a flag", "-", "HOST");
	AT(1, "after a --", "--", "HOST");
	AT(0, "nothing at all", "HOST");
	{
		static const char *const none[] = { "-v" };
		at(1, none, 1, "a flag and no destination");
		static const char *const dangling[] = { "-i" };
		at(1, dangling, 1, "a value flag with nothing after it");
		at(0, NULL, 0, "no arguments");
	}

	TCT_CASE("scp's flags are not ssh's");
	/* The reason there are two tables. `-p` preserves timestamps for scp and
	 * is the port for ssh, so scanning an scp command line with ssh's table
	 * swallows the first operand -- which is the file being copied. */
	{
		static const char *const a[] = { "-p", "src", "dst" };
		tct_checks++;
		if (tc_flag_scan(a, 3, TC_SCP_VALUE_FLAGS) != 1)
			TCT_FAILF("scp -p ate an operand");
		tct_checks++;
		if (tc_flag_scan(a, 3, TC_SSH_VALUE_FLAGS) != 2)
			TCT_FAILF("ssh -p did not take its value");
	}
	{
		/* And the other way: scp's -P is the port and takes one. */
		static const char *const a[] = { "-P", "2222", "src", "dst" };
		tct_checks++;
		if (tc_flag_scan(a, 4, TC_SCP_VALUE_FLAGS) != 2)
			TCT_FAILF("scp -P did not take its port");
	}
	{
		/* The case from bug 44, which shipped broken. */
		static const char *const a[] = { "-r", "./tree", "tcABC:" };
		tct_checks++;
		if (tc_flag_scan(a, 3, TC_SCP_VALUE_FLAGS) != 1)
			TCT_FAILF("cp -r did not put -r before the operands");
	}
	{
		static const char *const a[] = { "-rv", "./tree", "tcABC:" };
		tct_checks++;
		if (tc_flag_scan(a, 3, TC_SCP_VALUE_FLAGS) != 1)
			TCT_FAILF("clustered scp booleans miscounted");
	}
	{
		static const char *const a[] = { "-i", "key", "-r", "src", "dst" };
		tct_checks++;
		if (tc_flag_scan(a, 5, TC_SCP_VALUE_FLAGS) != 3)
			TCT_FAILF("scp -i key -r miscounted");
	}
	{
		/* No flags at all is the ordinary case, and must not consume one. */
		static const char *const a[] = { "report.pdf", "tcABC:" };
		tct_checks++;
		if (tc_flag_scan(a, 2, TC_SCP_VALUE_FLAGS) != 0)
			TCT_FAILF("an operand was taken for a flag");
	}

	TCT_CASE("an unknown flag is assumed boolean");
	/* The safe way round. If it really took a value we pick that value as
	 * the destination and refuse with a message naming it -- wrong, but
	 * legible. The other way round we would silently dial whatever followed
	 * the real destination. */
	AT(1, "an unknown letter", "-Z", "HOST");
	AT(1, "a future long option", "-Zzz", "HOST");
}

int main(void)
{
	test_posix_basic();
	test_posix_hostile();
	test_windows();
	test_bounds();
	test_dest_host();
	test_dest_index();
	return tct_report("shquote");
}
