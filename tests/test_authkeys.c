/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Who gets in: the authorized_keys parser and the three source forms.
 *
 * This file decides who may open a shell on the serving machine, so the
 * tests are about the two ways it could be wrong, which are not symmetric:
 *
 *   - Letting in a key that should not be. The worst case, and the reason
 *     `command="..."` options are refused rather than dropped: a line whose
 *     restriction is silently discarded grants strictly more than the file
 *     says, and nothing about the running server looks wrong afterwards.
 *
 *   - Keeping out a key that should be let in. Much less bad, but it is how
 *     `serve ssh` becomes a server nobody can reach, and the failure is
 *     silent unless an empty list is treated as an error. So the "no usable
 *     keys" cases are tested as carefully as the malformed ones.
 *
 * The keys below are real ed25519 public keys in OpenSSH's own encoding,
 * generated for this test. They are public halves and there are no private
 * halves anywhere, so they authenticate nobody.
 */

#include "tc/authkeys.h"

#include "tctest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Three distinct keys, as ssh-keygen would write them. */
#define KEY_A "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ3n0Fh0VCpYRgLnDqFadXAJ" \
              "3MLVGqR3TqBOGm5t6eVj"
#define KEY_B "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE1YY255hI+apbC7xtHc5/L9" \
              "CBMeKTQ/SlVga3aBjJei"
#define KEY_C "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHJ9iJOeqbS/ytXg6/YBDBci" \
              "LThDTllkb3qFkJumsbzH"

static void ok_line(const char *line, const char *why)
{
	uint8_t key[32];
	tct_checks++;
	int rc = tc_authkeys_parse_line(line, key);
	if (rc != TC_OK)
		TCT_FAILF("refused a good line (%s): %s", why,
		          tc_authkeys_error_string());
}

static void bad_line(const char *line, int want, const char *why)
{
	uint8_t key[32];
	tct_checks++;
	int rc = tc_authkeys_parse_line(line, key);
	if (rc != want)
		TCT_FAILF("\"%.40s\" (%s): got %d, want %d [%s]", line, why, rc, want,
		          tc_authkeys_error_string());
}

static void test_good_lines(void)
{
	TCT_CASE("lines a real file contains");
	ok_line(KEY_A, "a plain key");
	ok_line(KEY_A " alice@laptop", "a key with a comment");
	ok_line(KEY_A " a comment with spaces in it", "a comment with spaces");
	ok_line("  " KEY_A, "leading whitespace");
	ok_line("\t" KEY_A, "a leading tab");
	ok_line(KEY_A "\r", "a CRLF file read line by line");
	ok_line(KEY_A "   ", "trailing whitespace");

	/* The key really is the 32 bytes inside the blob, not something near
	 * them: two different lines must give two different keys, and the same
	 * line twice must give the same one. */
	TCT_CASE("the bytes are the key");
	uint8_t a1[32], a2[32], b[32];
	TCT_EQ_INT(tc_authkeys_parse_line(KEY_A, a1), TC_OK);
	TCT_EQ_INT(tc_authkeys_parse_line(KEY_A " different comment", a2), TC_OK);
	TCT_EQ_INT(tc_authkeys_parse_line(KEY_B, b), TC_OK);
	TCT_EQ_MEM(a1, a2, 32);
	TCT_TRUE(memcmp(a1, b, 32) != 0);
}

static void test_blank_and_comment(void)
{
	TCT_CASE("blank and comment lines are not keys and not errors");
	bad_line("", TC_ERR_NOTFOUND, "empty");
	bad_line("   ", TC_ERR_NOTFOUND, "whitespace");
	bad_line("\t\t", TC_ERR_NOTFOUND, "tabs");
	bad_line("# a comment", TC_ERR_NOTFOUND, "a comment");
	bad_line("   # indented comment", TC_ERR_NOTFOUND, "an indented comment");
	bad_line("\r", TC_ERR_NOTFOUND, "a bare CR");
}

static void test_other_algorithms_are_skipped(void)
{
	TCT_CASE("other algorithms are skipped, not refused");
	/* Skipped rather than refused because a real authorized_keys has RSA in
	 * it, and refusing the whole file over a key we cannot verify would make
	 * the common case fail. The caller turns "every line was skipped" into
	 * an error of its own. */
	bad_line("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7 bob@host",
	         TC_ERR_UNSUPPORTED, "rsa");
	bad_line("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY=",
	         TC_ERR_UNSUPPORTED, "ecdsa");
	bad_line("sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2",
	         TC_ERR_UNSUPPORTED, "a security key");
	bad_line("ssh-dss AAAAB3NzaC1kc3M=", TC_ERR_UNSUPPORTED, "dsa");
}

static void test_options_are_refused(void)
{
	TCT_CASE("key options are refused, never dropped");
	/* The important one. Each of these restricts the key, and a server that
	 * read the key while discarding the restriction would grant strictly
	 * more than the line asks for -- silently, and for as long as it runs. */
	bad_line("command=\"/usr/bin/backup\" " KEY_A, TC_ERR_INVAL,
	         "a forced command");
	bad_line("no-pty " KEY_A, TC_ERR_INVAL, "no-pty");
	bad_line("from=\"10.0.0.0/8\" " KEY_A, TC_ERR_INVAL,
	         "a source restriction");
	bad_line("restrict " KEY_A, TC_ERR_INVAL, "restrict");
	bad_line("no-port-forwarding,no-agent-forwarding " KEY_A, TC_ERR_INVAL,
	         "several options");
	bad_line("expiry-time=\"20300101\" " KEY_A, TC_ERR_INVAL, "an expiry");

	/* And the refusal must not be silently upgraded to "skipped", which
	 * would drop the line instead of failing. */
	tc_authkeys ks;
	tc_authkeys_init(&ks);
	TCT_TRUE(tc_authkeys_add_text(&ks, "no-pty " KEY_A "\n") != TC_OK);
	TCT_EQ_INT(ks.count, 0);
}

static void test_malformed(void)
{
	TCT_CASE("malformed lines");
	bad_line("ssh-ed25519", TC_ERR_INVAL, "no key at all");
	bad_line("ssh-ed25519 ", TC_ERR_INVAL, "a trailing space and nothing");
	bad_line("ssh-ed25519 not-base64!!!", TC_ERR_INVAL, "not base64");
	bad_line("ssh-ed25519 AAAA", TC_ERR_INVAL, "a truncated blob");

	/* The line says ed25519, the blob says otherwise. OpenSSH requires the
	 * two to agree, and a parser that only read the first token would take
	 * an RSA key here. */
	bad_line("ssh-ed25519 AAAAB3NzaC1yc2EAAAADAQABAAABgQC7", TC_ERR_INVAL,
	         "an rsa blob under an ed25519 name");

	/* A blob of the right shape with a 31-byte key inside it. */
	bad_line("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAHwECAwQFBgcICQoLDA0ODxARE"
	         "hMUFRYXGBkaGxwdHg==",
	         TC_ERR_INVAL, "a 31-byte key");

	TCT_EQ_INT(tc_authkeys_parse_line(NULL, NULL), TC_ERR_INVAL);
}

static void test_text_and_dedup(void)
{
	TCT_CASE("a whole file");
	tc_authkeys ks;
	tc_authkeys_init(&ks);
	static const char file[] =
	    "# my authorized_keys\n"
	    "\n"
	    KEY_A " alice@laptop\n"
	    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7 bob@host\n"
	    KEY_B " carol@desktop\n"
	    "\n"
	    "   \n"
	    KEY_C "\n";
	TCT_EQ_INT(tc_authkeys_add_text(&ks, file), TC_OK);
	TCT_EQ_INT(ks.count, 3);
	TCT_EQ_INT(ks.skipped, 1); /* the RSA line, reported rather than lost */

	TCT_CASE("a file with no trailing newline");
	tc_authkeys_init(&ks);
	TCT_EQ_INT(tc_authkeys_add_text(&ks, KEY_A), TC_OK);
	TCT_EQ_INT(ks.count, 1);

	TCT_CASE("the same key twice is one key");
	/* Two sources naming the same person is ordinary and must not be an
	 * error, but it must not take two slots either. */
	tc_authkeys_init(&ks);
	TCT_EQ_INT(tc_authkeys_add_text(&ks, KEY_A "\n" KEY_A " other comment\n"),
	           TC_OK);
	TCT_EQ_INT(ks.count, 1);

	TCT_CASE("a file of nothing but unsupported keys yields nothing");
	tc_authkeys_init(&ks);
	TCT_EQ_INT(tc_authkeys_add_text(
	               &ks, "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7 a@b\n"
	                    "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHA=\n"),
	           TC_OK);
	TCT_EQ_INT(ks.count, 0);
	TCT_EQ_INT(ks.skipped, 2);

	TCT_CASE("a bad line names its line number");
	tc_authkeys_init(&ks);
	TCT_TRUE(tc_authkeys_add_text(&ks, "# one\n"
	                                   "\n"
	                                   "no-pty " KEY_A "\n") != TC_OK);
	TCT_TRUE(strstr(tc_authkeys_error_string(), "line 3") != NULL);

	TCT_CASE("the list has a bound");
	tc_authkeys_init(&ks);
	ks.count = TC_AUTHKEYS_MAX;
	TCT_EQ_INT(tc_authkeys_add_text(&ks, KEY_A "\n"), TC_ERR_TOOMANY);

	TCT_EQ_INT(tc_authkeys_add_text(NULL, "x"), TC_ERR_INVAL);
	TCT_EQ_INT(tc_authkeys_add_text(&ks, NULL), TC_ERR_INVAL);
}

/* ---- the three source forms -------------------------------------------- */

static char g_fetch_url[256];
static const char *g_fetch_body;
static int g_fetch_rc;

static int fake_fetch(void *ctx, const char *url, char *out, size_t cap)
{
	(void)ctx;
	/* Copied, not kept: `url` points into tc_authkeys_add_spec's stack and
	 * is gone by the time the test looks at it. The first version of this
	 * test stored the pointer and compared garbage. */
	(void)snprintf(g_fetch_url, sizeof g_fetch_url, "%s", url);
	if (g_fetch_rc != TC_OK)
		return g_fetch_rc;
	(void)snprintf(out, cap, "%s", g_fetch_body != NULL ? g_fetch_body : "");
	return TC_OK;
}

static void test_github_urls(void)
{
	TCT_CASE("github usernames");
	char url[128];
	TCT_EQ_INT(tc_authkeys_github_url(url, sizeof url, "alice"), TC_OK);
	TCT_EQ_STR(url, "https://github.com/alice.keys");
	TCT_EQ_INT(tc_authkeys_github_url(url, sizeof url, "a-b-c9"), TC_OK);
	TCT_EQ_STR(url, "https://github.com/a-b-c9.keys");

	/* This string goes into a URL, so anything that could steer the request
	 * somewhere else has to be refused here rather than by the server. */
	static const char *const bad[] = {
		"",        "alice/bob",  "../etc",    "alice.keys",
		"a b",     "-alice",     "alice-",    "alice@example.com",
		"alice?x", "alice#frag", "alice%2f",  "alice:8080",
		"aliceaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", /* over 39 */
	};
	for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
		tct_checks++;
		if (tc_authkeys_github_url(url, sizeof url, bad[i]) == TC_OK)
			TCT_FAILF("accepted \"%s\" as a username, giving %s", bad[i],
			          url);
	}
}

static void test_specs(void)
{
	tc_authkeys ks;

	TCT_CASE("a literal key on the command line");
	tc_authkeys_init(&ks);
	TCT_EQ_INT(tc_authkeys_add_spec(&ks, KEY_A, NULL, NULL), TC_OK);
	TCT_EQ_INT(ks.count, 1);

	TCT_CASE("a file");
	char path[256];
	snprintf(path, sizeof path, "/tmp/tc_authkeys_%d.txt", (int)getpid());
	FILE *f = fopen(path, "w");
	TCT_TRUE(f != NULL);
	if (f != NULL) {
		fprintf(f, "# keys\n%s alice\n%s bob\n", KEY_A, KEY_B);
		(void)fclose(f);
	}
	tc_authkeys_init(&ks);
	TCT_EQ_INT(tc_authkeys_add_spec(&ks, path, NULL, NULL), TC_OK);
	TCT_EQ_INT(ks.count, 2);

	TCT_CASE("a file that is not there says so");
	tc_authkeys_init(&ks);
	TCT_EQ_INT(tc_authkeys_add_spec(&ks, "/tmp/tc_authkeys_absent_xyz", NULL,
	                                NULL),
	           TC_ERR_NOTFOUND);

	TCT_CASE("a file with a bad line names the file and the line");
	f = fopen(path, "w");
	if (f != NULL) {
		fprintf(f, "%s alice\nno-pty %s\n", KEY_A, KEY_B);
		(void)fclose(f);
	}
	tc_authkeys_init(&ks);
	TCT_TRUE(tc_authkeys_add_spec(&ks, path, NULL, NULL) != TC_OK);
	TCT_TRUE(strstr(tc_authkeys_error_string(), "line 2") != NULL);
	TCT_TRUE(strstr(tc_authkeys_error_string(), path) != NULL);
	(void)remove(path);

	TCT_CASE("user@github fetches the right URL");
	tc_authkeys_init(&ks);
	g_fetch_url[0] = 0;
	g_fetch_rc = TC_OK;
	g_fetch_body = KEY_A "\n" KEY_B "\n";
	TCT_EQ_INT(tc_authkeys_add_spec(&ks, "alice@github", fake_fetch, NULL),
	           TC_OK);
	TCT_EQ_STR(g_fetch_url, "https://github.com/alice.keys");
	TCT_EQ_INT(ks.count, 2);

	TCT_CASE("a github account with no usable key is an error");
	/* A 200 with nothing in it must not leave an empty list behind: an
	 * empty list is a server nobody can log into, and the operator would
	 * have no idea why. */
	tc_authkeys_init(&ks);
	g_fetch_body = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7 alice\n";
	TCT_EQ_INT(tc_authkeys_add_spec(&ks, "alice@github", fake_fetch, NULL),
	           TC_ERR_NOTFOUND);
	TCT_EQ_INT(ks.count, 0);

	TCT_CASE("a failed fetch is a failure, not an empty list");
	tc_authkeys_init(&ks);
	g_fetch_rc = TC_ERR_TIMEOUT;
	TCT_EQ_INT(tc_authkeys_add_spec(&ks, "alice@github", fake_fetch, NULL),
	           TC_ERR_TIMEOUT);
	g_fetch_rc = TC_OK;

	TCT_CASE("without a fetcher the network form is refused, not attempted");
	tc_authkeys_init(&ks);
	TCT_EQ_INT(tc_authkeys_add_spec(&ks, "alice@github", NULL, NULL),
	           TC_ERR_UNSUPPORTED);

	TCT_CASE("@github.com is not @github");
	/* The suffix is exact. Treating alice@github.com as the GitHub form
	 * would fetch a URL the user did not ask for; it is a path that does
	 * not exist, and saying so is the right answer. */
	tc_authkeys_init(&ks);
	g_fetch_url[0] = 0;
	TCT_EQ_INT(
	    tc_authkeys_add_spec(&ks, "alice@github.com", fake_fetch, NULL),
	    TC_ERR_NOTFOUND);
	TCT_EQ_STR(g_fetch_url, ""); /* not fetched at all */

	TCT_CASE("a bare @github has no username");
	tc_authkeys_init(&ks);
	TCT_TRUE(tc_authkeys_add_spec(&ks, "@github", fake_fetch, NULL) != TC_OK);

	TCT_EQ_INT(tc_authkeys_add_spec(NULL, "x", NULL, NULL), TC_ERR_INVAL);
	TCT_EQ_INT(tc_authkeys_add_spec(&ks, NULL, NULL, NULL), TC_ERR_INVAL);
}

int main(void)
{
	test_good_lines();
	test_blank_and_comment();
	test_other_algorithms_are_skipped();
	test_options_are_refused();
	test_malformed();
	test_text_and_dedup();
	test_github_urls();
	test_specs();
	return tct_report("authkeys");
}
