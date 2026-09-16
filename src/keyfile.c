/* SPDX-License-Identifier: BSD-3-Clause
 *
 * See keyfile.h. Reading and writing a saved identity.
 */

#include "tc/keyfile.h"

#include "tc/crypto.h"
#include "tc/json.h"
#include "tc/noise.h"
#include "tc/tailcat.h"

#include <stdio.h>
#include <string.h>

static _Thread_local char g_err[192];

const char *tc_keyfile_error_string(void)
{
	return g_err;
}

#define FAILF(...)                                                            \
	do {                                                                      \
		(void)snprintf(g_err, sizeof g_err, __VA_ARGS__);                     \
	} while (0)

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

/* parse_prefixed_key reads "<prefix>:<64 hex>" into 32 bytes.
 *
 * The prefix is required rather than tolerated. Tailscale's key types marshal
 * with it, and accepting a bare hex string would mean accepting a disco key
 * where a node key belongs -- the same 32 bytes meaning something different. */
static int parse_prefixed_key(const char *s, const char *prefix,
                              uint8_t out[32])
{
	size_t plen = strlen(prefix);
	if (strncmp(s, prefix, plen) != 0 || s[plen] != ':') {
		FAILF("expected a \"%s:\" key, got \"%.32s\"", prefix, s);
		return TC_ERR_INVAL;
	}
	const char *hex = s + plen + 1;
	if (strlen(hex) != 64) {
		FAILF("\"%s:\" key is not 64 hex digits", prefix);
		return TC_ERR_INVAL;
	}
	for (size_t i = 0; i < 32; i++) {
		int hi = hexval(hex[2 * i]);
		int lo = hexval(hex[2 * i + 1]);
		if (hi < 0 || lo < 0) {
			FAILF("\"%s:\" key is not hexadecimal", prefix);
			return TC_ERR_INVAL;
		}
		out[i] = (uint8_t)((hi << 4) | lo);
	}
	return TC_OK;
}

int tc_key_format_hex(char *out, size_t cap, const char *prefix,
                      const uint8_t key[32])
{
	if (out == NULL || prefix == NULL || key == NULL)
		return TC_ERR_INVAL;
	size_t plen = strlen(prefix);
	if (cap < plen + 1 + 64 + 1)
		return TC_ERR_NOSPACE;

	static const char kHex[] = "0123456789abcdef";
	memcpy(out, prefix, plen);
	out[plen] = ':';
	for (size_t i = 0; i < 32; i++) {
		out[plen + 1 + 2 * i] = kHex[key[i] >> 4];
		out[plen + 2 + 2 * i] = kHex[key[i] & 0x0f];
	}
	out[plen + 65] = '\0';
	return TC_OK;
}

/* ---- parsing ----------------------------------------------------------- */

/* parse_public reads the "Public" object. */
static int parse_public(tc_json_reader *r, tc_conn_info *ci)
{
	tc_json_event ev;
	for (;;) {
		if (tc_json_next(r, &ev) != TC_OK)
			return TC_ERR_INVAL;
		if (ev.type == TC_JSON_OBJECT_END)
			return TC_OK;
		if (ev.type != TC_JSON_KEY)
			return TC_ERR_INVAL;

		bool is_pub = tc_json_key_is(&ev, "ServerPublic");
		bool is_disco = tc_json_key_is(&ev, "ServerDiscoPublic");
		bool is_psk = tc_json_key_is(&ev, "PresharedKey");
		bool is_region = tc_json_key_is(&ev, "RegionID");

		if (!is_pub && !is_disco && !is_psk && !is_region) {
			/* Unknown members are skipped, so a file that gains a field
			 * later still loads. */
			if (tc_json_skip_value(r) != TC_OK)
				return TC_ERR_INVAL;
			continue;
		}

		if (tc_json_next(r, &ev) != TC_OK)
			return TC_ERR_INVAL;

		if (is_region) {
			if (ev.type != TC_JSON_NUMBER || !ev.is_integer) {
				FAILF("RegionID is not a number");
				return TC_ERR_INVAL;
			}
			ci->region_id = ev.num;
			continue;
		}

		if (ev.type != TC_JSON_STRING) {
			FAILF("a key field is not a string");
			return TC_ERR_INVAL;
		}
		char buf[128];
		if (tc_json_string_copy(&ev, buf, sizeof buf) != TC_OK) {
			FAILF("a key field is too long");
			return TC_ERR_INVAL;
		}
		int rc;
		if (is_pub) {
			rc = parse_prefixed_key(buf, "nodekey", ci->server_public);
		} else if (is_disco) {
			rc = parse_prefixed_key(buf, "discokey",
			                        ci->server_disco_public);
			ci->has_disco_public = (rc == TC_OK);
		} else {
			rc = parse_prefixed_key(buf, "psk", ci->preshared_key);
			ci->has_preshared_key = (rc == TC_OK);
		}
		if (rc != TC_OK)
			return rc;
	}
}

int tc_keyfile_parse(tc_keyfile *k, const char *json, size_t len)
{
	if (k == NULL || json == NULL)
		return TC_ERR_INVAL;
	g_err[0] = '\0';
	memset(k, 0, sizeof *k);

	tc_json_reader r;
	tc_json_event ev;
	tc_json_reader_init(&r, json, len);

	if (tc_json_next(&r, &ev) != TC_OK || ev.type != TC_JSON_OBJECT_BEGIN) {
		FAILF("not a JSON object");
		return TC_ERR_INVAL;
	}

	bool seen_public = false;
	for (;;) {
		if (tc_json_next(&r, &ev) != TC_OK) {
			FAILF("malformed JSON");
			return TC_ERR_INVAL;
		}
		if (ev.type == TC_JSON_OBJECT_END)
			break;
		if (ev.type != TC_JSON_KEY) {
			FAILF("malformed JSON");
			return TC_ERR_INVAL;
		}

		if (tc_json_key_is(&ev, "Private")) {
			if (tc_json_next(&r, &ev) != TC_OK ||
			    ev.type != TC_JSON_STRING) {
				FAILF("Private is not a string");
				return TC_ERR_INVAL;
			}
			char buf[128];
			if (tc_json_string_copy(&ev, buf, sizeof buf) != TC_OK) {
				FAILF("Private is too long");
				return TC_ERR_INVAL;
			}
			if (parse_prefixed_key(buf, "privkey", k->private_key) != TC_OK)
				return TC_ERR_INVAL;
			k->has_private = true;
		} else if (tc_json_key_is(&ev, "Public")) {
			if (tc_json_next(&r, &ev) != TC_OK ||
			    ev.type != TC_JSON_OBJECT_BEGIN) {
				FAILF("Public is not an object");
				return TC_ERR_INVAL;
			}
			if (parse_public(&r, &k->pub) != TC_OK)
				return TC_ERR_INVAL;
			seen_public = true;
		} else if (tc_json_skip_value(&r) != TC_OK) {
			FAILF("malformed JSON");
			return TC_ERR_INVAL;
		}
	}

	if (!k->has_private) {
		FAILF("no Private key in the file");
		return TC_ERR_INVAL;
	}
	if (!seen_public) {
		FAILF("no Public section in the file");
		return TC_ERR_INVAL;
	}

	/* The public and disco keys are both derived from the private one, so a
	 * file claiming different values is corrupt or lying. Recomputing beats
	 * trusting: a mismatched public key would produce an address nobody can
	 * reach, failing much later and much less clearly. */
	tc_wg_identity id;
	if (tc_wg_identity_from_private(&id, k->private_key) != TC_OK) {
		FAILF("the private key is not usable");
		return TC_ERR_INVAL;
	}
	if (memcmp(id.public_key, k->pub.server_public, 32) != 0) {
		FAILF("ServerPublic does not match Private");
		return TC_ERR_INVAL;
	}
	if (k->pub.has_disco_public) {
		uint8_t disco[32];
		if (tc_disco_key_for_node(NULL, disco, k->private_key) != TC_OK) {
			FAILF("could not derive the disco key");
			return TC_ERR_INVAL;
		}
		if (memcmp(disco, k->pub.server_disco_public, 32) != 0) {
			FAILF("ServerDiscoPublic does not match Private");
			return TC_ERR_INVAL;
		}
	}
	return TC_OK;
}

/* ---- writing ----------------------------------------------------------- */

int tc_keyfile_format(char *out, size_t cap, size_t *out_len,
                      const tc_keyfile *k)
{
	if (out == NULL || k == NULL || out_len == NULL)
		return TC_ERR_INVAL;
	g_err[0] = '\0';

	char priv[96], pub[96], disco[96], psk[96];
	if (tc_key_format_hex(priv, sizeof priv, "privkey", k->private_key) !=
	        TC_OK ||
	    tc_key_format_hex(pub, sizeof pub, "nodekey", k->pub.server_public) !=
	        TC_OK)
		return TC_ERR_INVAL;

	/* Tabs and this field order are upstream's, so a file we write and one it
	 * writes differ only in their keys. */
	int n = snprintf(out, cap,
	                 "{\n"
	                 "\t\"Private\": \"%s\",\n"
	                 "\t\"Public\": {\n"
	                 "\t\t\"ServerPublic\": \"%s\"",
	                 priv, pub);
	if (n < 0 || (size_t)n >= cap)
		return TC_ERR_NOSPACE;
	size_t off = (size_t)n;

	if (k->pub.has_disco_public) {
		if (tc_key_format_hex(disco, sizeof disco, "discokey",
		                      k->pub.server_disco_public) != TC_OK)
			return TC_ERR_INVAL;
		n = snprintf(out + off, cap - off,
		             ",\n\t\t\"ServerDiscoPublic\": \"%s\"", disco);
		if (n < 0 || (size_t)n >= cap - off)
			return TC_ERR_NOSPACE;
		off += (size_t)n;
	}
	if (k->pub.has_preshared_key) {
		if (tc_key_format_hex(psk, sizeof psk, "psk",
		                      k->pub.preshared_key) != TC_OK)
			return TC_ERR_INVAL;
		n = snprintf(out + off, cap - off, ",\n\t\t\"PresharedKey\": \"%s\"",
		             psk);
		if (n < 0 || (size_t)n >= cap - off)
			return TC_ERR_NOSPACE;
		off += (size_t)n;
	}
	if (k->pub.region_id != 0) {
		n = snprintf(out + off, cap - off, ",\n\t\t\"RegionID\": %lld",
		             (long long)k->pub.region_id);
		if (n < 0 || (size_t)n >= cap - off)
			return TC_ERR_NOSPACE;
		off += (size_t)n;
	}

	n = snprintf(out + off, cap - off, "\n\t}\n}\n");
	if (n < 0 || (size_t)n >= cap - off)
		return TC_ERR_NOSPACE;
	off += (size_t)n;

	*out_len = off;
	return TC_OK;
}

int tc_keyfile_generate(tc_keyfile *k, bool psk, int64_t region_id)
{
	if (k == NULL)
		return TC_ERR_INVAL;
	g_err[0] = '\0';
	memset(k, 0, sizeof *k);

	tc_wg_identity id;
	if (tc_wg_identity_generate(&id) != TC_OK) {
		FAILF("could not generate a key");
		return TC_ERR_INVAL;
	}
	memcpy(k->private_key, id.private_key, 32);
	memcpy(k->pub.server_public, id.public_key, 32);
	k->has_private = true;

	if (tc_disco_key_for_node(NULL, k->pub.server_disco_public,
	                          k->private_key) != TC_OK) {
		FAILF("could not derive the disco key");
		return TC_ERR_INVAL;
	}
	k->pub.has_disco_public = true;

	if (psk) {
		if (tc_random_bytes(k->pub.preshared_key, TC_PSK_LEN) != TC_OK) {
			FAILF("could not generate a pre-shared key");
			return TC_ERR_INVAL;
		}
		k->pub.has_preshared_key = true;
	}
	k->pub.region_id = region_id;
	return TC_OK;
}
