/* SPDX-License-Identifier: BSD-3-Clause
 *
 * The meow introduction exchange, disco key derivation and tunnel
 * addressing. See tailcat.h for what meow is for.
 */

#include "tc/tailcat.h"

#include "tc/crypto.h"

#include "mbedtls/md.h"

#include <stdio.h>
#include <string.h>

/* The label that separates tailcat's disco key derivation from any other use
 * of the same node key. Changing it changes every derived disco key. */
static const char kDiscoLabel[] =
	"github.com/tailscale/tailcat disco key v1";

bool tc_meow_is_packet(const uint8_t *pkt, size_t len)
{
	return pkt != NULL && len >= TC_MEOW_MAGIC_LEN &&
	       memcmp(pkt, TC_MEOW_MAGIC, TC_MEOW_MAGIC_LEN) == 0;
}

bool tc_meow_is_meowed(const uint8_t *pkt, size_t len)
{
	return tc_meow_is_packet(pkt, len) && len >= TC_MEOW_MAGIC_LEN + 1 &&
	       pkt[TC_MEOW_MAGIC_LEN] == TC_MEOW_TYPE_MEOWED;
}

int tc_meow_encode_ping(uint8_t *out, size_t cap, size_t *out_len,
                        const uint8_t node_pub[32],
                        const uint8_t disco_pub[32])
{
	if (out == NULL || node_pub == NULL || disco_pub == NULL)
		return TC_ERR_INVAL;
	if (cap < TC_MEOW_PING_LEN)
		return TC_ERR_NOSPACE;

	memcpy(out, TC_MEOW_MAGIC, TC_MEOW_MAGIC_LEN);
	out[TC_MEOW_MAGIC_LEN] = (uint8_t)TC_MEOW_TYPE_PING;
	memcpy(out + TC_MEOW_MAGIC_LEN + 1, node_pub, 32);
	memcpy(out + TC_MEOW_MAGIC_LEN + 1 + 32, disco_pub, 32);

	if (out_len != NULL)
		*out_len = TC_MEOW_PING_LEN;
	return TC_OK;
}

int tc_meow_encode_meowed(uint8_t *out, size_t cap, size_t *out_len)
{
	if (out == NULL)
		return TC_ERR_INVAL;
	if (cap < TC_MEOW_MEOWED_LEN)
		return TC_ERR_NOSPACE;

	memcpy(out, TC_MEOW_MAGIC, TC_MEOW_MAGIC_LEN);
	out[TC_MEOW_MAGIC_LEN] = (uint8_t)TC_MEOW_TYPE_MEOWED;

	if (out_len != NULL)
		*out_len = TC_MEOW_MEOWED_LEN;
	return TC_OK;
}

int tc_meow_parse_ping(const uint8_t *pkt, size_t len, uint8_t out_node[32],
                       uint8_t out_disco[32])
{
	if (pkt == NULL)
		return TC_ERR_INVAL;
	if (!tc_meow_is_packet(pkt, len))
		return TC_ERR_INVAL;
	if (len < TC_MEOW_PING_LEN)
		return TC_ERR_TRUNC;
	if (pkt[TC_MEOW_MAGIC_LEN] != TC_MEOW_TYPE_PING)
		return TC_ERR_INVAL;

	const uint8_t *node = pkt + TC_MEOW_MAGIC_LEN + 1;
	const uint8_t *disco = node + 32;

	/* Upstream treats an all-zero disco key as malformed rather than as
	 * "none", so a peer recorded from this ping always has a usable one. */
	if (tc_ct_is_zero(disco, 32))
		return TC_ERR_INVAL;

	if (out_node != NULL)
		memcpy(out_node, node, 32);
	if (out_disco != NULL)
		memcpy(out_disco, disco, 32);
	return TC_OK;
}

int tc_disco_key_for_node(uint8_t out_private[32], uint8_t out_public[32],
                          const uint8_t node_private[32])
{
	if (node_private == NULL)
		return TC_ERR_INVAL;

	const mbedtls_md_info_t *info =
	    mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	if (info == NULL)
		return TC_ERR_UNSUPPORTED;

	uint8_t raw[32];
	if (mbedtls_md_hmac(info, node_private, 32, (const unsigned char *)kDiscoLabel,
	                    sizeof kDiscoLabel - 1, raw) != 0) {
		tc_memzero_explicit(raw, sizeof raw);
		return TC_ERR_INVAL;
	}

	/* Canonicalise as a Curve25519 scalar, matching key.NewDisco. */
	tc_x25519_clamp(raw);

	int rc = TC_OK;
	if (out_public != NULL)
		rc = tc_x25519_base(out_public, raw);
	if (rc == TC_OK && out_private != NULL)
		memcpy(out_private, raw, 32);

	tc_memzero_explicit(raw, sizeof raw);
	return rc;
}

void tc_tunnel_addr_for_key(uint8_t out[TC_TUNNEL_ADDR_LEN],
                            const uint8_t node_pub[32])
{
	/* Tailscale's ULA range fd7a:115c:a1e0::/48, with the remaining 80 bits
	 * taken from the node key. */
	out[0] = 0xfd;
	out[1] = 0x7a;
	out[2] = 0x11;
	out[3] = 0x5c;
	out[4] = 0xa1;
	out[5] = 0xe0;
	memcpy(out + 6, node_pub, 10);
}

int tc_tunnel_addr_format(char *out, size_t cap,
                          const uint8_t addr[TC_TUNNEL_ADDR_LEN])
{
	if (out == NULL || addr == NULL)
		return TC_ERR_INVAL;
	if (cap < 40)
		return TC_ERR_NOSPACE;

	uint16_t g[8];
	for (size_t i = 0; i < 8; i++)
		g[i] = (uint16_t)((uint16_t)addr[2 * i] << 8 | addr[2 * i + 1]);

	/* Find the longest run of zero groups to compress, preferring the
	 * leftmost on a tie, as RFC 5952 requires. A run of one is not
	 * compressed. */
	int best_start = -1, best_len = 0;
	int run_start = -1, run_len = 0;
	for (int i = 0; i < 8; i++) {
		if (g[i] == 0) {
			if (run_start < 0) {
				run_start = i;
				run_len = 1;
			} else {
				run_len++;
			}
			if (run_len > best_len) {
				best_len = run_len;
				best_start = run_start;
			}
		} else {
			run_start = -1;
			run_len = 0;
		}
	}
	if (best_len < 2) {
		best_start = -1;
		best_len = 0;
	}

	/* Emit "::" for the compressed run and a ":" before any other group that
	 * does not already follow one. Letting the trailing colon of "::" stand
	 * in as the next separator is what makes the start-of-string and
	 * end-of-string cases fall out without being special-cased. */
	size_t n = 0;
	int i = 0;
	while (i < 8) {
		if (i == best_start) {
			if (n + 2 >= cap)
				return TC_ERR_NOSPACE;
			out[n++] = ':';
			out[n++] = ':';
			i += best_len;
			continue;
		}
		if (n > 0 && out[n - 1] != ':') {
			if (n + 1 >= cap)
				return TC_ERR_NOSPACE;
			out[n++] = ':';
		}
		int w = snprintf(out + n, cap - n, "%x", g[i]);
		if (w < 0 || (size_t)w >= cap - n)
			return TC_ERR_NOSPACE;
		n += (size_t)w;
		i++;
	}
	out[n] = '\0';
	return TC_OK;
}
