/* SPDX-License-Identifier: BSD-3-Clause
 *
 * See stun.h.
 *
 * This parses packets from an unauthenticated UDP port, which puts it in the
 * same category as the CBOR and JSON readers: every length is checked against
 * what is actually there rather than against what the message claims.
 */

#include "tc/stun.h"

#include "tc/crypto.h"

#include <stdio.h>
#include <string.h>

static const uint8_t kMagic[4] = { 0x21, 0x12, 0xa4, 0x42 };
static const char kSoftware[] = "tailnode"; /* 8 bytes, so no padding */

enum {
	ATTR_MAPPED_ADDRESS = 0x0001,
	ATTR_XOR_MAPPED_ADDRESS = 0x0020,
	/* Not in the RFC, but the shift into the comprehension-optional range is
	 * an easy mistake for a server to make, and servers do send it. */
	ATTR_XOR_MAPPED_ADDRESS_ALT = 0x8020,
	ATTR_SOFTWARE = 0x8022,
	ATTR_FINGERPRINT = 0x8028
};

static uint16_t rd16(const uint8_t *p)
{
	return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}

static void wr16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static void wr32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

/* crc32_ieee is the CRC-32 the FINGERPRINT attribute uses.
 *
 * Bitwise rather than table-driven: a STUN packet is forty bytes and this runs
 * a handful of times per session, so a 1 KB table would cost more cache than
 * it saves cycles. */
static uint32_t crc32_ieee(const uint8_t *p, size_t n)
{
	uint32_t crc = 0xffffffffu;
	for (size_t i = 0; i < n; i++) {
		crc ^= p[i];
		for (int k = 0; k < 8; k++) {
			uint32_t mask = (uint32_t)-(int32_t)(crc & 1u);
			crc = (crc >> 1) ^ (0xedb88320u & mask);
		}
	}
	return ~crc;
}

int tc_stun_build_request(uint8_t out[TC_STUN_REQUEST_LEN],
                          uint8_t txid[TC_STUN_TXID_LEN])
{
	if (out == NULL || txid == NULL)
		return TC_ERR_INVAL;
	/* On an unauthenticated UDP exchange the transaction ID is the only thing
	 * tying a response to a request, so it comes from the CSPRNG. A counter
	 * would let anyone who can reach the socket forge a plausible reply. */
	if (tc_random_bytes(txid, TC_STUN_TXID_LEN) != TC_OK)
		return TC_ERR_INVAL;
	return tc_stun_build_request_with_txid(out, txid);
}

int tc_stun_build_request_with_txid(uint8_t out[TC_STUN_REQUEST_LEN],
                                    const uint8_t txid[TC_STUN_TXID_LEN])
{
	if (out == NULL || txid == NULL)
		return TC_ERR_INVAL;

	wr16(out + 0, 0x0001); /* binding request */
	wr16(out + 2, 12 + 8); /* SOFTWARE (4+8) and FINGERPRINT (4+4) */
	memcpy(out + 4, kMagic, 4);
	memcpy(out + 8, txid, TC_STUN_TXID_LEN);

	wr16(out + 20, ATTR_SOFTWARE);
	wr16(out + 22, (uint16_t)(sizeof kSoftware - 1));
	memcpy(out + 24, kSoftware, sizeof kSoftware - 1);

	/* The fingerprint covers everything before its own attribute, with the
	 * length field already counting it -- which is why it is written last
	 * and computed over exactly 32 bytes. */
	uint32_t fp = crc32_ieee(out, 32) ^ 0x5354554eu;
	wr16(out + 32, ATTR_FINGERPRINT);
	wr16(out + 34, 4);
	wr32(out + 36, fp);
	return TC_OK;
}

bool tc_stun_is(const uint8_t *msg, size_t len)
{
	if (msg == NULL || len < TC_STUN_HEADER_LEN)
		return false;
	/* The two most significant bits of a STUN message are zero, which is what
	 * lets STUN share a port with other protocols. */
	if ((msg[0] & 0xc0) != 0)
		return false;
	if (memcmp(msg + 4, kMagic, 4) != 0)
		return false;
	/* The length counts only the attributes, and must be a multiple of four
	 * because every attribute is padded to a word. */
	size_t attr_len = rd16(msg + 2);
	if ((attr_len & 3u) != 0)
		return false;
	return TC_STUN_HEADER_LEN + attr_len == len;
}

/* read_addr decodes a MAPPED-ADDRESS or XOR-MAPPED-ADDRESS value. */
static int read_addr(const uint8_t *v, size_t vlen, const uint8_t *txid,
                     bool xored, tc_endpoint *out)
{
	if (vlen < 4)
		return TC_ERR_INVAL;
	uint8_t family = v[1];
	size_t ip_len = (family == 1) ? 4 : (family == 2) ? 16 : 0;
	if (ip_len == 0 || vlen < 4 + ip_len)
		return TC_ERR_INVAL;

	uint16_t port = rd16(v + 2);
	uint8_t ip[16];
	memcpy(ip, v + 4, ip_len);

	if (xored) {
		/* The port is XORed with the top half of the magic cookie, the first
		 * four address bytes with the whole cookie, and -- for IPv6 -- the
		 * rest with the transaction ID. */
		port ^= 0x2112u;
		for (size_t i = 0; i < ip_len; i++)
			ip[i] ^= (i < 4) ? kMagic[i] : txid[i - 4];
	}

	memset(out, 0, sizeof *out);
	memcpy(out->ip, ip, ip_len);
	out->ip_len = (uint8_t)ip_len;
	out->port = port;
	return TC_OK;
}

int tc_stun_parse_response(const uint8_t *msg, size_t len,
                           uint8_t out_txid[TC_STUN_TXID_LEN],
                           tc_endpoint *out)
{
	if (msg == NULL || out == NULL)
		return TC_ERR_INVAL;
	if (!tc_stun_is(msg, len))
		return TC_ERR_INVAL;
	if (msg[0] != 0x01 || msg[1] != 0x01)
		return TC_ERR_INVAL; /* not a binding success response */

	if (out_txid != NULL)
		memcpy(out_txid, msg + 8, TC_STUN_TXID_LEN);

	tc_endpoint fallback;
	bool have_fallback = false;
	memset(out, 0, sizeof *out);

	const uint8_t *p = msg + TC_STUN_HEADER_LEN;
	size_t remaining = len - TC_STUN_HEADER_LEN;
	while (remaining > 0) {
		if (remaining < 4)
			return TC_ERR_INVAL;
		uint16_t type = rd16(p);
		size_t vlen = rd16(p + 2);
		/* Every attribute is padded out to a four-byte boundary, and the
		 * padding is not counted in its length. */
		size_t padded = (vlen + 3u) & ~(size_t)3u;
		p += 4;
		remaining -= 4;
		if (padded > remaining)
			return TC_ERR_INVAL;

		if (type == ATTR_XOR_MAPPED_ADDRESS ||
		    type == ATTR_XOR_MAPPED_ADDRESS_ALT) {
			if (read_addr(p, vlen, msg + 8, true, out) == TC_OK)
				return TC_OK; /* the preferred form; stop here */
		} else if (type == ATTR_MAPPED_ADDRESS && !have_fallback) {
			/* Kept only in case no XOR form turns up. The plain form is the
			 * one NATs were observed rewriting, which is why XOR exists. */
			if (read_addr(p, vlen, msg + 8, false, &fallback) == TC_OK)
				have_fallback = true;
		}

		p += padded;
		remaining -= padded;
	}

	if (have_fallback) {
		*out = fallback;
		return TC_OK;
	}
	return TC_ERR_INVAL;
}

int tc_stun_build_response(uint8_t *out, size_t cap, size_t *out_len,
                           const uint8_t txid[TC_STUN_TXID_LEN],
                           const tc_endpoint *ep)
{
	if (out == NULL || out_len == NULL || txid == NULL || ep == NULL)
		return TC_ERR_INVAL;
	if (ep->ip_len != 4 && ep->ip_len != 16)
		return TC_ERR_INVAL;

	size_t attrs = 8 + ep->ip_len;
	if (cap < TC_STUN_HEADER_LEN + attrs)
		return TC_ERR_NOSPACE;

	wr16(out + 0, 0x0101); /* binding success response */
	wr16(out + 2, (uint16_t)attrs);
	memcpy(out + 4, kMagic, 4);
	memcpy(out + 8, txid, TC_STUN_TXID_LEN);

	wr16(out + 20, ATTR_XOR_MAPPED_ADDRESS);
	wr16(out + 22, (uint16_t)(4 + ep->ip_len));
	out[24] = 0;
	out[25] = (ep->ip_len == 4) ? 1 : 2;
	wr16(out + 26, (uint16_t)(ep->port ^ 0x2112u));
	for (size_t i = 0; i < ep->ip_len; i++)
		out[28 + i] = ep->ip[i] ^ ((i < 4) ? kMagic[i] : txid[i - 4]);

	*out_len = TC_STUN_HEADER_LEN + attrs;
	return TC_OK;
}
