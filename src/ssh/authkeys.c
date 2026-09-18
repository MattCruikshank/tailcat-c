/* SPDX-License-Identifier: BSD-3-Clause
 *
 * See include/tc/authkeys.h.
 */
#include "tc/authkeys.h"

#include "tc/sshwire.h"

#include <mbedtls/base64.h>

#include <stdio.h>
#include <string.h>

/* Room for a wrapped message: a line-number or filename prefix in front of
 * a message that is itself up to WHY_MAX. */
#define WHY_MAX 256
static _Thread_local char g_err[WHY_MAX + 256];

const char *tc_authkeys_error_string(void)
{
	return g_err;
}

#define FAILF(...) (void)snprintf(g_err, sizeof g_err, __VA_ARGS__)

void tc_authkeys_init(tc_authkeys *ks)
{
	if (ks != NULL)
		memset(ks, 0, sizeof *ks);
}

/* The algorithm names a real authorized_keys file contains.
 *
 * The list exists to tell an algorithm from an options field, which is the
 * one ambiguity in the format: both are just the first token on the line. A
 * token that is not one of these is options, and options are refused -- see
 * the header for why discarding them would be worse than failing. */
static bool is_algorithm(const char *tok)
{
	static const char *const kAlgos[] = {
		"ssh-ed25519",
		"ssh-rsa",
		"ssh-dss",
		"rsa-sha2-256",
		"rsa-sha2-512",
		"ecdsa-sha2-nistp256",
		"ecdsa-sha2-nistp384",
		"ecdsa-sha2-nistp521",
		"sk-ssh-ed25519@openssh.com",
		"sk-ecdsa-sha2-nistp256@openssh.com",
	};
	for (size_t i = 0; i < sizeof kAlgos / sizeof kAlgos[0]; i++) {
		if (strcmp(tok, kAlgos[i]) == 0)
			return true;
	}
	return false;
}

/* next_token copies the next whitespace-delimited token and advances p.
 * Returns false at the end of the line or if the token does not fit. */
static bool is_space(char c)
{
	/* CR and LF count. A file written on Windows, or fetched over HTTP,
	 * arrives with CRLF line endings, and a caller that split on '\n' hands
	 * us a line still carrying its '\r'. Without this the trailing CR ends
	 * up inside the base64 and every key in the file is rejected -- which is
	 * exactly what the test for it found. */
	return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static bool next_token(const char **p, char *out, size_t cap)
{
	const char *s = *p;
	while (is_space(*s))
		s++;
	if (*s == '\0')
		return false;
	const char *start = s;
	while (*s != '\0' && !is_space(*s))
		s++;
	size_t n = (size_t)(s - start);
	if (n >= cap)
		return false;
	memcpy(out, start, n);
	out[n] = '\0';
	*p = s;
	return true;
}

int tc_authkeys_parse_line(const char *line, uint8_t out[32])
{
	if (line == NULL || out == NULL)
		return TC_ERR_INVAL;
	g_err[0] = '\0';

	const char *p = line;
	while (is_space(*p))
		p++;
	if (*p == '\0' || *p == '#')
		return TC_ERR_NOTFOUND;

	char algo[64];
	if (!next_token(&p, algo, sizeof algo)) {
		FAILF("no key on the line");
		return TC_ERR_INVAL;
	}
	if (!is_algorithm(algo)) {
		/* An options field. Refused rather than skipped past, because every
		 * option is a restriction and reading the key while dropping
		 * `command=` grants more than the file says. */
		FAILF("key options are not supported here, and ignoring them would "
		      "grant more than the line asks for");
		return TC_ERR_INVAL;
	}
	if (strcmp(algo, "ssh-ed25519") != 0) {
		FAILF("%s keys cannot be verified by this server; only ed25519",
		      algo);
		return TC_ERR_UNSUPPORTED;
	}

	char b64[1024];
	if (!next_token(&p, b64, sizeof b64)) {
		FAILF("ssh-ed25519 with no key after it");
		return TC_ERR_INVAL;
	}

	uint8_t blob[128];
	size_t blob_len = 0;
	if (mbedtls_base64_decode(blob, sizeof blob, &blob_len,
	                          (const unsigned char *)b64,
	                          strlen(b64)) != 0) {
		FAILF("the key is not valid base64");
		return TC_ERR_INVAL;
	}

	/* The blob repeats the algorithm inside itself, and the two must agree:
	 * a line that says ssh-ed25519 while carrying an RSA blob is either
	 * corrupt or an attempt to get a key past a check that only read the
	 * first token. OpenSSH requires the same agreement. */
	tc_ssh_rbuf r;
	tc_ssh_rbuf_init(&r, blob, blob_len);
	if (!tc_ssh_get_string_eq(&r, "ssh-ed25519")) {
		FAILF("the line says ssh-ed25519 but the key does not");
		return TC_ERR_INVAL;
	}
	size_t klen = 0;
	const uint8_t *k = tc_ssh_get_string(&r, 32, &klen);
	if (k == NULL || klen != 32 || !tc_ssh_rbuf_ok(&r)) {
		FAILF("the key is not 32 bytes");
		return TC_ERR_INVAL;
	}
	/* Trailing bytes inside the blob mean it is not the structure it claims
	 * to be, whatever else it may decode to. */
	if (tc_ssh_rbuf_remaining(&r) != 0) {
		FAILF("the key has %zu bytes after it",
		      tc_ssh_rbuf_remaining(&r));
		return TC_ERR_INVAL;
	}

	memcpy(out, k, 32);
	return TC_OK;
}

int tc_authkeys_add_text(tc_authkeys *ks, const char *text)
{
	if (ks == NULL || text == NULL)
		return TC_ERR_INVAL;
	g_err[0] = '\0';

	const char *p = text;
	size_t lineno = 0;
	while (*p != '\0') {
		const char *end = strchr(p, '\n');
		size_t n = (end != NULL) ? (size_t)(end - p) : strlen(p);
		lineno++;

		char line[2048];
		if (n >= sizeof line) {
			FAILF("line %zu is too long to be a key", lineno);
			return TC_ERR_INVAL;
		}
		memcpy(line, p, n);
		line[n] = '\0';

		uint8_t key[32];
		int rc = tc_authkeys_parse_line(line, key);
		if (rc == TC_ERR_UNSUPPORTED) {
			ks->skipped++;
		} else if (rc == TC_OK) {
			if (ks->count >= TC_AUTHKEYS_MAX) {
				FAILF("more than %d keys", TC_AUTHKEYS_MAX);
				return TC_ERR_TOOMANY;
			}
			/* A key listed twice is one key. Not an error -- two sources
			 * naming the same person is an ordinary thing to do -- but it
			 * must not take two slots. */
			bool dup = false;
			for (size_t i = 0; i < ks->count; i++) {
				if (memcmp(ks->key[i], key, 32) == 0) {
					dup = true;
					break;
				}
			}
			if (!dup)
				memcpy(ks->key[ks->count++], key, 32);
		} else if (rc != TC_ERR_NOTFOUND) {
			/* Prefix the line number: "bad key" against a forty-line file
			 * is not a diagnostic anyone can act on. */
			char why[WHY_MAX];
			(void)snprintf(why, sizeof why, "%.*s", (int)(sizeof why - 1), g_err);
			FAILF("line %zu: %s", lineno, why);
			return rc;
		}

		if (end == NULL)
			break;
		p = end + 1;
	}
	return TC_OK;
}

int tc_authkeys_github_url(char *out, size_t cap, const char *user)
{
	if (out == NULL || user == NULL)
		return TC_ERR_INVAL;
	g_err[0] = '\0';

	/* GitHub usernames are alphanumerics and hyphens, at most 39 characters,
	 * and cannot start or end with a hyphen. Checked here rather than left
	 * to the server because this string goes into a URL: a username
	 * containing a slash or a dot would fetch something else entirely, and
	 * "alice/../../foo" must not become a path. */
	size_t n = strlen(user);
	if (n == 0 || n > 39) {
		FAILF("\"%s\" is not a GitHub username", user);
		return TC_ERR_INVAL;
	}
	if (user[0] == '-' || user[n - 1] == '-') {
		FAILF("a GitHub username cannot start or end with a hyphen");
		return TC_ERR_INVAL;
	}
	for (size_t i = 0; i < n; i++) {
		char c = user[i];
		bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		          (c >= '0' && c <= '9') || c == '-';
		if (!ok) {
			FAILF("\"%s\" is not a GitHub username", user);
			return TC_ERR_INVAL;
		}
	}

	if ((size_t)snprintf(out, cap, "https://github.com/%s.keys", user) >= cap)
		return TC_ERR_NOSPACE;
	return TC_OK;
}

int tc_authkeys_add_spec(tc_authkeys *ks, const char *spec,
                         tc_authkeys_fetch_fn fetch, void *ctx)
{
	if (ks == NULL || spec == NULL)
		return TC_ERR_INVAL;
	g_err[0] = '\0';

	/* A literal key. Recognised by its first token being an algorithm name,
	 * which is the same test the line parser uses -- and which no path and
	 * no `user@github` can collide with, since both of those would have to
	 * be literally named "ssh-ed25519". */
	char first[64];
	const char *p = spec;
	if (next_token(&p, first, sizeof first) && is_algorithm(first))
		return tc_authkeys_add_text(ks, spec);

	/* `<user>@github`. The suffix is exact: `alice@github.com` is not this
	 * form, and treating it as one would fetch a URL the user did not ask
	 * for. */
	size_t n = strlen(spec);
	static const char kSuffix[] = "@github";
	size_t slen = sizeof kSuffix - 1;
	if (n > slen && strcmp(spec + n - slen, kSuffix) == 0) {
		char user[64];
		size_t ulen = n - slen;
		if (ulen >= sizeof user) {
			FAILF("that GitHub username is too long");
			return TC_ERR_INVAL;
		}
		memcpy(user, spec, ulen);
		user[ulen] = '\0';

		char url[128];
		int rc = tc_authkeys_github_url(url, sizeof url, user);
		if (rc != TC_OK)
			return rc;
		if (fetch == NULL) {
			FAILF("fetching keys over the network is not available here");
			return TC_ERR_UNSUPPORTED;
		}
		/* 64 keys at roughly 100 bytes a line, with room to spare. A
		 * response larger than this is not an authorized_keys file. */
		static char body[16384];
		rc = fetch(ctx, url, body, sizeof body);
		if (rc != TC_OK)
			return rc;
		size_t before = ks->count;
		rc = tc_authkeys_add_text(ks, body);
		if (rc != TC_OK)
			return rc;
		if (ks->count == before) {
			/* A 200 with nothing usable in it. Distinct from a failed
			 * fetch, and worth saying so: the likely cause is an account
			 * with no ed25519 key, not a network problem. */
			FAILF("%s has no ed25519 keys", url);
			return TC_ERR_NOTFOUND;
		}
		return TC_OK;
	}

	/* Otherwise a file. */
	FILE *f = fopen(spec, "rb");
	if (f == NULL) {
		FAILF("cannot read %s", spec);
		return TC_ERR_NOTFOUND;
	}
	static char buf[65536];
	size_t got = fread(buf, 1, sizeof buf - 1, f);
	bool too_big = !feof(f);
	(void)fclose(f);
	if (too_big) {
		FAILF("%s is too large to be an authorized_keys file", spec);
		return TC_ERR_TOOMANY;
	}
	buf[got] = '\0';
	int rc = tc_authkeys_add_text(ks, buf);
	if (rc != TC_OK) {
		char why[WHY_MAX];
		(void)snprintf(why, sizeof why, "%.*s", (int)(sizeof why - 1), g_err);
		FAILF("%.200s: %s", spec, why);
	}
	return rc;
}
