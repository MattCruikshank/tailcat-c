/* SPDX-License-Identifier: BSD-3-Clause
 *
 * IPv4 destinations over an IPv6-only tunnel.
 *
 * tailcat's tunnel carries IPv6 and nothing else: the addresses are ULAs
 * derived from node keys, and there is no IPv4 anywhere in it. An exit node
 * still has to be able to reach 192.168.1.10, so IPv4 destinations travel
 * inside an IPv6 address and are unwrapped at the far end.
 *
 * The prefix is 64:ff9b::/96, the "Well-Known Prefix" of RFC 6052 section
 * 2.1, which is what upstream uses. So 192.168.1.10 becomes
 * 64:ff9b::c0a8:10a.
 *
 * ---- why not ::ffff:0:0/96 ---------------------------------------------
 *
 * The v4-mapped prefix would be the obvious choice and is the wrong one. It
 * already means something else here -- tc_endpoint uses it as the *wire
 * encoding* for an address whose family is known separately, and
 * tc_endpoint_from16 unmaps it on sight. An address translated into it would
 * come back out as IPv4 at a layer that had no idea translation was
 * happening. RFC 4291 also forbids v4-mapped addresses on the wire at all.
 *
 * Two prefixes, two meanings, and they must not be confused: ::ffff:0:0/96
 * says "this IPv4 address, written as sixteen bytes", and 64:ff9b::/96 says
 * "send this through a translator to that IPv4 address".
 *
 * ---- what this does not do ---------------------------------------------
 *
 * RFC 6052 also defines /32, /40, /48, /56 and /64 prefixes, in which the
 * address is split around the `u` octet at byte 8 -- which must be zero, and
 * is not part of the address. None of that is implemented: upstream uses the
 * /96 well-known prefix and nothing else, and a translator that accepted the
 * other forms would be accepting addresses its peer can never send.
 */
#ifndef TC_NAT64_H_
#define TC_NAT64_H_

#include "tc/endpoint.h"

/* 64:ff9b::/96 */
#define TC_NAT64_PREFIX_LEN 12

/* tc_nat64_is reports whether a sixteen-byte address is inside the prefix. */
bool tc_nat64_is(const uint8_t ip[16]);

/* tc_nat64_wrap writes the IPv6 form of an IPv4 address.
 *
 * Returns TC_ERR_INVAL unless ep is IPv4: an IPv6 destination needs no
 * translation and wrapping one would produce a different address entirely. */
int tc_nat64_wrap(tc_endpoint *out, const tc_endpoint *ep);

/* tc_nat64_unwrap recovers the IPv4 address from a translated one.
 *
 * Returns TC_ERR_INVAL if the address is not in the prefix, so a caller can
 * use it to ask "is this for the translator?" and act on the answer in one
 * step. */
int tc_nat64_unwrap(tc_endpoint *out, const tc_endpoint *ep);

#endif /* TC_NAT64_H_ */
