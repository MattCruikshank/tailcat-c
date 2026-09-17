/* SPDX-License-Identifier: BSD-3-Clause
 *
 * See socks.h.
 */

#include "tc/socks.h"

#include <string.h>

static uint16_t rd16(const uint8_t *p)
{
	return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}

static void wr16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

int tc_socks_classify(tc_socks_target *out, uint8_t atyp, const uint8_t *addr,
                      size_t addr_len, uint16_t port)
{
	if (out == NULL || (addr == NULL && addr_len > 0))
		return TC_ERR_INVAL;
	memset(out, 0, sizeof *out);

	/* Port zero is the absence of a port, not a port. Passing it on would
	 * mean dialling something no service can be listening on. */
	if (port == 0)
		return TC_ERR_INVAL;
	out->port = port;

	switch (atyp) {
	case TC_SOCKS_ATYP_IPV4:
		if (addr_len != 4)
			return TC_ERR_INVAL;
		memcpy(out->dst.ip, addr, 4);
		out->dst.ip_len = 4;
		out->dst.port = port;
		out->kind = TC_SOCKS_TO_ADDRESS;
		return TC_OK;

	case TC_SOCKS_ATYP_IPV6:
		if (addr_len != 16)
			return TC_ERR_INVAL;
		/* Through from16, so a v4-mapped literal becomes the IPv4 address it
		 * stands for rather than a second spelling of it. */
		tc_endpoint_from16(&out->dst, addr, port);
		out->kind = TC_SOCKS_TO_ADDRESS;
		return TC_OK;

	case TC_SOCKS_ATYP_NAME: {
		/* An empty host, or upstream's name for the far end of the tunnel. */
		if (addr_len == 0) {
			out->kind = TC_SOCKS_TO_SERVER;
			return TC_OK;
		}
		const size_t slen = sizeof TC_SOCKS_SERVER_HOST - 1;
		if (addr_len == slen && memcmp(addr, TC_SOCKS_SERVER_HOST, slen) == 0) {
			out->kind = TC_SOCKS_TO_SERVER;
			return TC_OK;
		}
		/* Any other name needs DNS, which is a decision with consequences --
		 * resolving it here resolves it on the client's machine, not the
		 * server's. The caller makes that call; this function will not make
		 * it silently. */
		return TC_ERR_UNSUPPORTED;
	}

	default:
		return TC_ERR_UNSUPPORTED;
	}
}

int tc_socks_udp_parse(const uint8_t *pkt, size_t len, tc_socks_target *out,
                       const uint8_t **out_data, size_t *out_data_len)
{
	if (pkt == NULL || out == NULL || out_data == NULL || out_data_len == NULL)
		return TC_ERR_INVAL;
	*out_data = NULL;
	*out_data_len = 0;

	/* RSV(2) FRAG(1) ATYP(1), then the address. */
	if (len < 4)
		return TC_ERR_INVAL;
	if (pkt[0] != 0 || pkt[1] != 0)
		return TC_ERR_INVAL; /* reserved, and required to be zero */
	if (pkt[2] != 0) {
		/* Fragmented. RFC 1928 permits dropping these, and reassembling them
		 * would be a buffer to overflow in service of a feature nothing
		 * uses. */
		return TC_ERR_UNSUPPORTED;
	}

	uint8_t atyp = pkt[3];
	size_t off = 4;
	size_t addr_len = 0;

	switch (atyp) {
	case TC_SOCKS_ATYP_IPV4: addr_len = 4; break;
	case TC_SOCKS_ATYP_IPV6: addr_len = 16; break;
	case TC_SOCKS_ATYP_NAME:
		if (len < off + 1)
			return TC_ERR_INVAL;
		addr_len = pkt[off];
		off += 1;
		break;
	default:
		return TC_ERR_UNSUPPORTED;
	}

	/* Checked before either is read, and with the addition ordered so it
	 * cannot wrap: len is a size_t and addr_len is at most 255. */
	if (len < off + addr_len + 2)
		return TC_ERR_INVAL;

	uint16_t port = rd16(pkt + off + addr_len);
	int rc = tc_socks_classify(out, atyp, pkt + off, addr_len, port);
	if (rc != TC_OK)
		return rc;

	*out_data = pkt + off + addr_len + 2;
	*out_data_len = len - off - addr_len - 2;
	return TC_OK;
}

int tc_socks_udp_build(uint8_t *out, size_t cap, size_t *out_len,
                       const tc_endpoint *src, const void *data, size_t len)
{
	if (out == NULL || out_len == NULL || src == NULL ||
	    (data == NULL && len > 0))
		return TC_ERR_INVAL;
	if (src->ip_len != 4 && src->ip_len != 16)
		return TC_ERR_INVAL;

	size_t hdr = 4 + (size_t)src->ip_len + 2;
	if (cap < hdr + len)
		return TC_ERR_NOSPACE;

	out[0] = 0;
	out[1] = 0;
	out[2] = 0; /* never fragmented */
	out[3] = (src->ip_len == 4) ? TC_SOCKS_ATYP_IPV4 : TC_SOCKS_ATYP_IPV6;
	memcpy(out + 4, src->ip, src->ip_len);
	wr16(out + 4 + src->ip_len, src->port);
	if (len > 0)
		memcpy(out + hdr, data, len);

	*out_len = hdr + len;
	return TC_OK;
}
