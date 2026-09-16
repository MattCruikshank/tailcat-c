/* SPDX-License-Identifier: BSD-3-Clause
 *
 * STUN binding requests (RFC 5389), for learning our own public address.
 *
 * This is the first piece of Phase 4: everything about direct peer-to-peer
 * paths starts with "what address does the rest of the world see me at?", and
 * a STUN server is the only thing that can answer.
 *
 * Only the binding exchange is here. No authentication, no TURN, no ICE --
 * a Tailscale DERP node answers unauthenticated binding requests on its STUN
 * port, which is the whole of what this needs.
 *
 * The request is byte-identical to the one tailscale.com/net/stun builds,
 * including the SOFTWARE attribute naming "tailnode" and the FINGERPRINT.
 * That is deliberate: the servers being asked are Tailscale's, and a request
 * that looks like every other one is one fewer thing for them to treat
 * differently.
 */
#ifndef TC_STUN_H_
#define TC_STUN_H_

#include "tc/endpoint.h"

#define TC_STUN_TXID_LEN 12
#define TC_STUN_HEADER_LEN 20

/* Request: 20 header + 12 SOFTWARE + 8 FINGERPRINT. */
#define TC_STUN_REQUEST_LEN 40

/* tc_stun_build_request writes a binding request and fills txid with fresh
 * random bytes.
 *
 * The transaction ID is what ties a response to a request, and on an
 * unauthenticated UDP exchange it is the *only* thing that does -- so it has
 * to come from the CSPRNG, not a counter. */
int tc_stun_build_request(uint8_t out[TC_STUN_REQUEST_LEN],
                          uint8_t txid[TC_STUN_TXID_LEN]);

/* tc_stun_build_request_with_txid builds one using a transaction ID the
 * caller supplies.
 *
 * It exists so a test can compare our bytes against another implementation's
 * for the same ID. That comparison is the only thing that checks the
 * FINGERPRINT's CRC-32, and it is worthless if the test computes the
 * fingerprint itself -- a shared misreading would agree with itself. Going
 * through the real code path is the point. */
int tc_stun_build_request_with_txid(uint8_t out[TC_STUN_REQUEST_LEN],
                                    const uint8_t txid[TC_STUN_TXID_LEN]);

/* tc_stun_is reports whether a packet looks like STUN at all: long enough,
 * with the magic cookie, and with a length field that agrees. Used to tell a
 * STUN reply apart from other traffic arriving on a shared socket. */
bool tc_stun_is(const uint8_t *msg, size_t len);

/* tc_stun_parse_response reads a binding success response.
 *
 * The caller must compare the returned transaction ID against the one it
 * sent; this reports it rather than checking, because a caller with several
 * requests in flight is matching against a set.
 *
 * Both XOR-MAPPED-ADDRESS (0x0020) and the comprehension-optional spelling
 * some servers use (0x8020) are accepted, as is the legacy plain
 * MAPPED-ADDRESS, which is preferred only when no XOR form is present. */
int tc_stun_parse_response(const uint8_t *msg, size_t len,
                           uint8_t out_txid[TC_STUN_TXID_LEN],
                           tc_endpoint *out);

/* tc_stun_build_response writes a binding success response.
 *
 * Nothing here serves STUN. It exists so the parser can be tested against
 * messages built independently of it, and so a test harness can stand in for
 * a server without a network. */
int tc_stun_build_response(uint8_t *out, size_t cap, size_t *out_len,
                           const uint8_t txid[TC_STUN_TXID_LEN],
                           const tc_endpoint *ep);

#endif /* TC_STUN_H_ */
