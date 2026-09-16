/* SPDX-License-Identifier: BSD-3-Clause
 *
 * See endpoint.h.
 */

#include "tc/endpoint.h"

#include <stdio.h>
#include <string.h>

int tc_endpoint_format(char *out, size_t cap, const tc_endpoint *ep)
{
	if (out == NULL || ep == NULL || cap == 0)
		return TC_ERR_INVAL;
	out[0] = '\0';
	if (ep->ip_len == 4) {
		int n = snprintf(out, cap, "%u.%u.%u.%u:%u", ep->ip[0], ep->ip[1],
		                 ep->ip[2], ep->ip[3], (unsigned)ep->port);
		return (n > 0 && (size_t)n < cap) ? TC_OK : TC_ERR_NOSPACE;
	}
	if (ep->ip_len != 16)
		return TC_ERR_INVAL;

	/* Longest zero run wins, as RFC 5952 requires; a run of one is not
	 * compressed, because "::" there would be longer than the digit. */
	int best_start = -1, best_len = 0, cur_start = -1, cur_len = 0;
	for (int i = 0; i < 8; i++) {
		bool zero = ep->ip[2 * i] == 0 && ep->ip[2 * i + 1] == 0;
		if (zero) {
			if (cur_start < 0)
				cur_start = i;
			cur_len++;
			if (cur_len > best_len) {
				best_len = cur_len;
				best_start = cur_start;
			}
		} else {
			cur_start = -1;
			cur_len = 0;
		}
	}
	if (best_len < 2)
		best_start = -1;

	size_t off = 0;
	int n = snprintf(out, cap, "[");
	if (n < 0 || (size_t)n >= cap)
		return TC_ERR_NOSPACE;
	off = (size_t)n;

	for (int i = 0; i < 8;) {
		if (i == best_start) {
			n = snprintf(out + off, cap - off, ":");
			if (n < 0 || (size_t)n >= cap - off)
				return TC_ERR_NOSPACE;
			off += (size_t)n;
			i += best_len;
			if (i == 8) {
				n = snprintf(out + off, cap - off, ":");
				if (n < 0 || (size_t)n >= cap - off)
					return TC_ERR_NOSPACE;
				off += (size_t)n;
			}
			continue;
		}
		unsigned group =
		    (unsigned)ep->ip[2 * i] << 8 | (unsigned)ep->ip[2 * i + 1];
		n = snprintf(out + off, cap - off, "%s%x",
		             (i > 0 && i != best_start + best_len) ? ":" : "", group);
		if (n < 0 || (size_t)n >= cap - off)
			return TC_ERR_NOSPACE;
		off += (size_t)n;
		i++;
	}

	n = snprintf(out + off, cap - off, "]:%u", (unsigned)ep->port);
	return (n > 0 && (size_t)n < cap - off) ? TC_OK : TC_ERR_NOSPACE;
}

bool tc_endpoint_equal(const tc_endpoint *a, const tc_endpoint *b)
{
	if (a == NULL || b == NULL)
		return false;
	return a->ip_len == b->ip_len && a->port == b->port &&
	       (a->ip_len == 0 || memcmp(a->ip, b->ip, a->ip_len) == 0);
}

bool tc_endpoint_is_candidate(const tc_endpoint *ep)
{
	if (ep == NULL || ep->port == 0)
		return false;

	if (ep->ip_len == 4) {
		uint8_t a = ep->ip[0], b = ep->ip[1];
		if (a == 0)
			return false; /* 0.0.0.0/8: "this network" */
		if (a == 127)
			return false; /* loopback: a peer reaching it would reach itself */
		if (a == 169 && b == 254)
			return false; /* link-local, only meaningful on one segment */
		if (a >= 224)
			return false; /* multicast and reserved */
		/* 100.64/10 is carrier-grade NAT, and also the range Tailscale uses
		 * for its own nodes. Either way it is not somewhere a peer can reach
		 * us directly: behind a carrier NAT nobody can, and on a tailnet the
		 * address belongs to a different system entirely. */
		if (a == 100 && b >= 64 && b <= 127)
			return false;
		/* RFC 1918 addresses stay: two peers on the same LAN reach each other
		 * that way, which is the best path there is. */
		return true;
	}

	if (ep->ip_len != 16)
		return false;

	bool all_zero = true;
	for (size_t i = 0; i < 16; i++) {
		if (ep->ip[i] != 0) {
			all_zero = false;
			break;
		}
	}
	if (all_zero)
		return false; /* :: */
	if (ep->ip[15] == 1) {
		bool loopback = true;
		for (size_t i = 0; i < 15; i++) {
			if (ep->ip[i] != 0) {
				loopback = false;
				break;
			}
		}
		if (loopback)
			return false; /* ::1 */
	}
	if (ep->ip[0] == 0xfe && (ep->ip[1] & 0xc0) == 0x80)
		return false; /* fe80::/10, link-local: needs a scope id to use */
	if (ep->ip[0] == 0xff)
		return false; /* ff00::/8, multicast */

	/* ::ffff:0:0/96, an IPv4 address wearing an IPv6 costume. The same
	 * address is already offered in its own form, and sending the mapped
	 * spelling to a peer would have it probe a duplicate. */
	static const uint8_t kV4Mapped[12] = { 0, 0, 0, 0, 0, 0,
		                                   0, 0, 0, 0, 0xff, 0xff };
	if (memcmp(ep->ip, kV4Mapped, 12) == 0)
		return false;

	/* fd00::/8 unique-local stays, for the same reason RFC 1918 does. */
	return true;
}
