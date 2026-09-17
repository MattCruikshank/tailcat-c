/* SPDX-License-Identifier: BSD-3-Clause
 *
 * See nat64.h.
 */

#include "tc/nat64.h"

#include <string.h>

/* 64:ff9b:: followed by 64 zero bits, leaving the last four bytes for the
 * IPv4 address. */
static const uint8_t kPrefix[TC_NAT64_PREFIX_LEN] = { 0x00, 0x64, 0xff, 0x9b,
	                                                  0,    0,    0,    0,
	                                                  0,    0,    0,    0 };

bool tc_nat64_is(const uint8_t ip[16])
{
	if (ip == NULL)
		return false;
	return memcmp(ip, kPrefix, TC_NAT64_PREFIX_LEN) == 0;
}

int tc_nat64_wrap(tc_endpoint *out, const tc_endpoint *ep)
{
	if (out == NULL || ep == NULL || ep->ip_len != 4)
		return TC_ERR_INVAL;

	tc_endpoint tmp;
	memset(&tmp, 0, sizeof tmp);
	memcpy(tmp.ip, kPrefix, TC_NAT64_PREFIX_LEN);
	memcpy(tmp.ip + TC_NAT64_PREFIX_LEN, ep->ip, 4);
	tmp.ip_len = 16;
	tmp.port = ep->port;
	*out = tmp;
	return TC_OK;
}

int tc_nat64_unwrap(tc_endpoint *out, const tc_endpoint *ep)
{
	if (out == NULL || ep == NULL || ep->ip_len != 16)
		return TC_ERR_INVAL;
	if (!tc_nat64_is(ep->ip))
		return TC_ERR_INVAL;

	tc_endpoint tmp;
	memset(&tmp, 0, sizeof tmp);
	memcpy(tmp.ip, ep->ip + TC_NAT64_PREFIX_LEN, 4);
	tmp.ip_len = 4;
	tmp.port = ep->port;
	*out = tmp;
	return TC_OK;
}
