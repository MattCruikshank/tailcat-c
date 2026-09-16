/* SPDX-License-Identifier: BSD-3-Clause
 *
 * See disco.h.
 *
 * These packets arrive on an open UDP port from anywhere, so the parser is
 * written the way the CBOR and JSON readers are: nothing is read without
 * first checking it is there.
 */

#include "tc/disco.h"

#include "tc/crypto.h"

#include <string.h>

static const uint8_t kMagic[TC_DISCO_MAGIC_LEN] = { 'T',  'S',  0xf0,
	                                                0x9f, 0x92, 0xac };

static uint16_t rd16(const uint8_t *p)
{
	return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}

static void wr16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

bool tc_disco_looks_like(const uint8_t *pkt, size_t len)
{
	if (pkt == NULL || len < TC_DISCO_HEADER_LEN)
		return false;
	return memcmp(pkt, kMagic, TC_DISCO_MAGIC_LEN) == 0;
}

int tc_disco_source(const uint8_t *pkt, size_t len, uint8_t out_pub[32])
{
	if (out_pub == NULL || !tc_disco_looks_like(pkt, len))
		return TC_ERR_INVAL;
	memcpy(out_pub, pkt + TC_DISCO_MAGIC_LEN, 32);
	return TC_OK;
}

/* ---- building ---------------------------------------------------------- */

/* build_payload writes the inner, unencrypted message. */
static int build_payload(uint8_t *out, size_t cap, size_t *out_len,
                         const tc_disco_msg *msg)
{
	if (cap < 2)
		return TC_ERR_NOSPACE;
	out[1] = 0; /* version */

	switch (msg->type) {
	case TC_DISCO_PING: {
		size_t n = 2 + TC_DISCO_TXID_LEN;
		if (msg->ping.has_node_key)
			n += 32;
		if (n + msg->ping.padding > cap)
			return TC_ERR_NOSPACE;
		out[0] = TC_DISCO_PING;
		memcpy(out + 2, msg->ping.txid, TC_DISCO_TXID_LEN);
		if (msg->ping.has_node_key)
			memcpy(out + 2 + TC_DISCO_TXID_LEN, msg->ping.node_key, 32);
		/* Padding is zero bytes at the end, there to make the packet a
		 * chosen size for MTU probing. A parser must not read them as a
		 * node key, which is why an all-zero key is treated as absent. */
		if (msg->ping.padding > 0)
			memset(out + n, 0, msg->ping.padding);
		*out_len = n + msg->ping.padding;
		return TC_OK;
	}
	case TC_DISCO_PONG: {
		size_t n = 2 + TC_DISCO_TXID_LEN + 16 + 2;
		if (n > cap)
			return TC_ERR_NOSPACE;
		out[0] = TC_DISCO_PONG;
		memcpy(out + 2, msg->pong.txid, TC_DISCO_TXID_LEN);
		tc_endpoint_to16(&msg->pong.src, out + 2 + TC_DISCO_TXID_LEN);
		wr16(out + 2 + TC_DISCO_TXID_LEN + 16, msg->pong.src.port);
		*out_len = n;
		return TC_OK;
	}
	case TC_DISCO_CALL_ME_MAYBE: {
		if (msg->call_me_maybe.num > TC_DISCO_MAX_ENDPOINTS)
			return TC_ERR_TOOMANY;
		size_t n = 2 + msg->call_me_maybe.num * 18;
		if (n > cap)
			return TC_ERR_NOSPACE;
		out[0] = TC_DISCO_CALL_ME_MAYBE;
		uint8_t *p = out + 2;
		for (size_t i = 0; i < msg->call_me_maybe.num; i++) {
			tc_endpoint_to16(&msg->call_me_maybe.eps[i], p);
			wr16(p + 16, msg->call_me_maybe.eps[i].port);
			p += 18;
		}
		*out_len = n;
		return TC_OK;
	}
	default:
		return TC_ERR_UNSUPPORTED;
	}
}

int tc_disco_seal(uint8_t *out, size_t cap, size_t *out_len,
                  const tc_disco_msg *msg, const uint8_t our_pub[32],
                  const uint8_t our_priv[32], const uint8_t peer_pub[32])
{
	if (out == NULL || out_len == NULL || msg == NULL || our_pub == NULL ||
	    our_priv == NULL || peer_pub == NULL)
		return TC_ERR_INVAL;

	uint8_t payload[TC_DISCO_MAX_PAYLOAD];
	size_t plen = 0;
	int rc = build_payload(payload, sizeof payload, &plen, msg);
	if (rc != TC_OK)
		return rc;

	size_t total = TC_DISCO_HEADER_LEN + plen + TC_BOX_TAG_LEN;
	if (cap < total)
		return TC_ERR_NOSPACE;

	memcpy(out, kMagic, TC_DISCO_MAGIC_LEN);
	memcpy(out + TC_DISCO_MAGIC_LEN, our_pub, 32);

	/* A fresh random nonce per message. These are one-shot and unordered, so
	 * there is no counter to keep and nothing to resynchronise; reusing one
	 * under the same key pair would leak the XOR of two payloads. */
	uint8_t *nonce = out + TC_DISCO_MAGIC_LEN + 32;
	if (tc_random_bytes(nonce, TC_DISCO_NONCE_LEN) != TC_OK)
		return TC_ERR_INVAL;

	rc = tc_box_seal(out + TC_DISCO_HEADER_LEN, nonce, payload, plen,
	                 peer_pub, our_priv);
	tc_memzero_explicit(payload, sizeof payload);
	if (rc != TC_OK)
		return rc;

	*out_len = total;
	return TC_OK;
}

/* ---- parsing ----------------------------------------------------------- */

static int parse_payload(tc_disco_msg *out, const uint8_t *p, size_t len)
{
	if (len < 2)
		return TC_ERR_INVAL;
	uint8_t type = p[0];
	uint8_t version = p[1];
	p += 2;
	len -= 2;

	memset(out, 0, sizeof *out);

	switch (type) {
	case TC_DISCO_PING: {
		if (len < TC_DISCO_TXID_LEN)
			return TC_ERR_INVAL;
		out->type = TC_DISCO_PING;
		memcpy(out->ping.txid, p, TC_DISCO_TXID_LEN);
		size_t rest = len - TC_DISCO_TXID_LEN;
		out->ping.padding = rest;
		if (rest >= 32) {
			/* An all-zero key is padding, not a key -- the sender omits the
			 * field entirely when it has none, so zeros there can only be
			 * the MTU padding. Reading them as a node key would invent a
			 * peer identity out of filler. */
			bool all_zero = true;
			for (size_t i = 0; i < 32; i++) {
				if (p[TC_DISCO_TXID_LEN + i] != 0) {
					all_zero = false;
					break;
				}
			}
			if (!all_zero) {
				memcpy(out->ping.node_key, p + TC_DISCO_TXID_LEN, 32);
				out->ping.has_node_key = true;
				out->ping.padding = rest - 32;
			}
		}
		return TC_OK;
	}
	case TC_DISCO_PONG: {
		if (len < TC_DISCO_TXID_LEN + 16 + 2)
			return TC_ERR_INVAL;
		out->type = TC_DISCO_PONG;
		memcpy(out->pong.txid, p, TC_DISCO_TXID_LEN);
		tc_endpoint_from16(&out->pong.src, p + TC_DISCO_TXID_LEN,
		                   rd16(p + TC_DISCO_TXID_LEN + 16));
		return TC_OK;
	}
	case TC_DISCO_CALL_ME_MAYBE: {
		out->type = TC_DISCO_CALL_ME_MAYBE;
		/* Upstream treats a ragged length or a non-zero version as "no
		 * endpoints" rather than as an error, and so do we: a peer that
		 * learns to send something new should not look broken to a peer
		 * that has not. */
		if (version != 0 || len == 0 || (len % 18) != 0)
			return TC_OK;
		size_t n = len / 18;
		if (n > TC_DISCO_MAX_ENDPOINTS)
			n = TC_DISCO_MAX_ENDPOINTS;
		for (size_t i = 0; i < n; i++) {
			tc_endpoint_from16(&out->call_me_maybe.eps[i], p + i * 18,
			                   rd16(p + i * 18 + 16));
		}
		out->call_me_maybe.num = n;
		return TC_OK;
	}
	default:
		/* A type from a newer peer. Not an attack and not a parse failure;
		 * the caller ignores it, which is what an older peer would do. */
		return TC_ERR_UNSUPPORTED;
	}
}

int tc_disco_open(tc_disco_msg *out, const uint8_t *pkt, size_t len,
                  const uint8_t our_priv[32], const uint8_t peer_pub[32])
{
	if (out == NULL || our_priv == NULL || peer_pub == NULL)
		return TC_ERR_INVAL;
	if (!tc_disco_looks_like(pkt, len))
		return TC_ERR_INVAL;

	/* The sender field must be the key we expect. Opening with whatever key
	 * the packet names would let anyone seal a valid message to us, which is
	 * exactly what sealing is for. */
	if (!tc_ct_equal(pkt + TC_DISCO_MAGIC_LEN, peer_pub, 32))
		return TC_ERR_INVAL;

	size_t box_len = len - TC_DISCO_HEADER_LEN;
	if (box_len < TC_BOX_TAG_LEN)
		return TC_ERR_INVAL;
	size_t plen = box_len - TC_BOX_TAG_LEN;
	if (plen > TC_DISCO_MAX_PAYLOAD)
		return TC_ERR_TOOMANY;

	uint8_t payload[TC_DISCO_MAX_PAYLOAD];
	const uint8_t *nonce = pkt + TC_DISCO_MAGIC_LEN + 32;
	if (tc_box_open(payload, nonce, pkt + TC_DISCO_HEADER_LEN, box_len,
	                peer_pub, our_priv) != TC_OK)
		return TC_ERR_INVAL;

	int rc = parse_payload(out, payload, plen);
	tc_memzero_explicit(payload, sizeof payload);
	return rc;
}
