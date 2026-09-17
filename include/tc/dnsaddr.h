/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Taking a tailcat address from a DNS TXT record.
 *
 * Anywhere upstream accepts a <tc-addr> it also accepts a DNS name whose
 * "tailcat=" TXT record holds one:
 *
 *     my-server.example.com. 300 IN TXT "tailcat=tc..."
 *     $ tailcat ssh my-server.example.com
 *
 * Which is convenient and, as upstream's own documentation says at length,
 * dangerous in one specific way: a tailcat address is normally a secret
 * because holding it is what lets you connect, and a DNS TXT record is
 * public, world-readable and actively scanned. Publishing one hands that
 * capability to the internet, so a server named in DNS has to authenticate
 * clients by something other than knowing its address -- `serve --allow` at
 * the tunnel layer, or SSH public keys above it.
 *
 * That warning belongs to whoever publishes a record. This file is about the
 * other side of it, and about a hazard that belongs to whoever *reads* one:
 *
 *   A DNS query is not private. It goes to a resolver, and usually to
 *   several more after that. So the classification below refuses to look up
 *   anything that has a valid tailcat address inside it -- because
 *   "tcABC...xyz.example.com", or an address pasted with a trailing dot,
 *   would otherwise be sent to a stranger's resolver in cleartext. The user
 *   would have leaked the very secret the address is, by making a typo.
 *
 * Upstream refuses the same case for the same reason. It is the sort of rule
 * nobody invents twice, which is why it is implemented here rather than
 * reasoned out from first principles.
 */
#ifndef TC_DNSADDR_H_
#define TC_DNSADDR_H_

#include "tc/tc.h"

/* The longest DNS name, per RFC 1035, plus room for a NUL. */
#define TC_DNS_NAME_LEN 254

typedef enum {
	/* The argument is a tailcat address; use it as it stands. */
	TC_DNSARG_ADDRESS = 0,
	/* The argument is a DNS name to look up. */
	TC_DNSARG_NAME
} tc_dnsarg_kind;

/* tc_dns_classify decides what a destination argument is, without touching
 * the network.
 *
 * On TC_DNSARG_NAME the name is copied to out, with any trailing dot
 * removed. On TC_DNSARG_ADDRESS out is set empty and the caller keeps using
 * the argument it already had.
 *
 * Returns TC_ERR_INVAL when the argument is neither -- including the case
 * that matters most, an argument with a valid tailcat address among its
 * labels, which is refused rather than resolved. tc_dns_error_string
 * describes the last failure in a form fit to print. */
int tc_dns_classify(tc_dnsarg_kind *kind, char *out, size_t cap,
                    const char *arg);

const char *tc_dns_error_string(void);

/* tc_dns_txt_find_tailcat pulls the address out of a DNS response.
 *
 * `msg` is a complete DNS message of `len` bytes as res_query returns it.
 * The first answer record that is a TXT record beginning "tailcat=" wins,
 * with surrounding whitespace trimmed, matching upstream's first-match rule.
 *
 * A TXT record is a sequence of length-prefixed strings, each at most 255
 * bytes, and a long address spans several of them -- so they are joined,
 * which is what every DNS client does and what a reader of the zone file
 * would expect. Returns TC_ERR_NOTFOUND when no such record is present.
 *
 * Separate from the query so that it can be tested against captured bytes
 * rather than against whatever the network says today. */
int tc_dns_txt_find_tailcat(char *out, size_t cap, const uint8_t *msg,
                            size_t len);

/* tc_dns_lookup_tailcat resolves a name and returns the address in it.
 *
 * Uses the system resolver, so it honours whatever the machine is configured
 * to use. Returns TC_ERR_NOTFOUND if the name resolves but carries no
 * "tailcat=" record, and TC_ERR_TIMEOUT if the lookup fails outright. */
int tc_dns_lookup_tailcat(char *out, size_t cap, const char *name);

#endif /* TC_DNSADDR_H_ */
