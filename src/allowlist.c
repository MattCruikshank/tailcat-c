/* SPDX-License-Identifier: BSD-3-Clause
 *
 * See allowlist.h.
 */

#include "tc/allowlist.h"

#include "tc/crypto.h"

#include <stdio.h>
#include <string.h>

static _Thread_local char g_err[160];

#define FAILF(...)                                                            \
	do {                                                                      \
		(void)snprintf(g_err, sizeof g_err, __VA_ARGS__);                     \
	} while (0)

const char *tc_allow_error_string(void)
{
	return g_err;
}

static int hexval(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/* add adds one key, ignoring a duplicate rather than spending a slot on it. */
static int add(tc_allowlist *l, const uint8_t key[32])
{
	for (size_t i = 0; i < l->num; i++) {
		if (memcmp(l->keys[i], key, TC_NODE_KEY_LEN) == 0)
			return TC_OK;
	}
	if (l->num >= TC_ALLOW_MAX) {
		FAILF("more than %d keys in --allow", TC_ALLOW_MAX);
		return TC_ERR_TOOMANY;
	}
	memcpy(l->keys[l->num++], key, TC_NODE_KEY_LEN);
	return TC_OK;
}

/* one parses a single entry, which is "nodekey:<64 hex>" or "none". */
static int one(tc_allowlist *l, const char *s, size_t len)
{
	/* Trim, so "a, b" works the way anyone would expect from a shell. */
	while (len > 0 && (s[0] == ' ' || s[0] == '\t')) {
		s++;
		len--;
	}
	while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t'))
		len--;

	if (len == 0) {
		/* "a,,b" is far more likely a quoting accident than an intention,
		 * and silently skipping it would mean a list that admits more than
		 * the user thinks it does. */
		FAILF("empty entry in --allow");
		return TC_ERR_INVAL;
	}

	if (len == 4 && memcmp(s, "none", 4) == 0) {
		/* Nothing to add: an active list with no entries admits nobody. See
		 * the header for why we do not use upstream's sentinel key. */
		return TC_OK;
	}

	static const char kPrefix[] = "nodekey:";
	const size_t plen = sizeof kPrefix - 1;
	if (len != plen + 64 || memcmp(s, kPrefix, plen) != 0) {
		FAILF("--allow wants \"nodekey:<64 hex>\" or \"none\", got \"%.40s\"",
		      s);
		return TC_ERR_INVAL;
	}

	uint8_t key[TC_NODE_KEY_LEN];
	const char *hex = s + plen;
	for (size_t i = 0; i < TC_NODE_KEY_LEN; i++) {
		int hi = hexval(hex[2 * i]);
		int lo = hexval(hex[2 * i + 1]);
		if (hi < 0 || lo < 0) {
			FAILF("--allow key is not hexadecimal: \"%.40s\"", s);
			return TC_ERR_INVAL;
		}
		key[i] = (uint8_t)((hi << 4) | lo);
	}
	return add(l, key);
}

int tc_allow_parse(tc_allowlist *l, const char *spec)
{
	if (l == NULL || spec == NULL)
		return TC_ERR_INVAL;
	g_err[0] = '\0';

	/* An empty string is not an empty list. Upstream treats an unset --allow
	 * as "everyone", and `--allow=` is the same thing spelled differently;
	 * making it mean "nobody" would be a trap with no way to tell from the
	 * command line which reading applied. */
	if (spec[0] == '\0') {
		FAILF("--allow is empty; omit it to allow everyone, or use \"none\"");
		return TC_ERR_INVAL;
	}

	const char *p = spec;
	for (;;) {
		const char *comma = strchr(p, ',');
		size_t len = (comma != NULL) ? (size_t)(comma - p) : strlen(p);
		int rc = one(l, p, len);
		if (rc != TC_OK)
			return rc;
		/* Driven by the commas rather than by what is left, so a trailing
		 * one is an empty entry and gets refused instead of ignored. */
		if (comma == NULL)
			break;
		p = comma + 1;
	}

	l->active = true;
	return TC_OK;
}

bool tc_allow_permits(const tc_allowlist *l, const uint8_t key[32])
{
	if (key == NULL)
		return false;

	/* Refused first, before the question of whether a list exists. The
	 * X25519 identity element has no private key behind it, so a client
	 * presenting it cannot be who it claims -- and "allow everyone" should
	 * not quietly include a client that cannot exist. Checking after the
	 * no-list shortcut would have admitted it in exactly the permissive case
	 * where nobody is looking. */
	uint8_t zero[TC_NODE_KEY_LEN];
	memset(zero, 0, sizeof zero);
	if (tc_ct_equal(key, zero, TC_NODE_KEY_LEN))
		return false;

	if (l == NULL || !l->active)
		return true; /* no list: the address is the only credential */

	/* Every entry is compared, and the loop does not stop early. There is no
	 * secret here to protect -- an attacker knows their own key -- so this is
	 * a habit rather than a defence, but it is the right habit. */
	bool ok = false;
	for (size_t i = 0; i < l->num; i++) {
		if (tc_ct_equal(l->keys[i], key, TC_NODE_KEY_LEN))
			ok = true;
	}
	return ok;
}
