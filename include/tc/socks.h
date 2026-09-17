/* SPDX-License-Identifier: BSD-3-Clause
 *
 * The parts of SOCKS5 that are worth testing away from a socket.
 *
 * The handshake itself is a short read/write conversation and lives in the
 * CLI. What lives here is the two things that are pure functions over bytes
 * and easy to get subtly wrong: deciding where a destination points, and the
 * UDP relay header from RFC 1928 section 7.
 *
 * ---- where a destination points ----------------------------------------
 *
 * A SOCKS5 request names a host and a port, and with a tunnel in the way
 * there are two quite different things that can mean:
 *
 *   the tailcat server itself, on that port -- the ordinary case, and what
 *   `socks` did exclusively before exit nodes existed; or
 *
 *   somewhere beyond it, which only works if the server was started with
 *   `serve exit-node`.
 *
 * Upstream distinguishes them by the hostname: `server.tailcat` (or an empty
 * host) means the server, anything else is a destination to reach through it.
 * We use the same spelling, because a SOCKS client configured for one should
 * work against the other.
 *
 * ---- the UDP relay header ----------------------------------------------
 *
 * Datagrams to a SOCKS5 UDP relay carry their destination in front:
 *
 *     +-----+------+------+----------+----------+----------+
 *     | RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
 *     +-----+------+------+----------+----------+----------+
 *     |  2  |  1   |  1   | variable |    2     | variable |
 *
 * and replies come back with the same header naming where they came from. So
 * a UDP association is not a tunnel for datagrams, it is a tunnel for
 * *addressed* datagrams, and the addressing is the part that has to be right:
 * a header parsed one byte out sends the payload to the wrong place with no
 * error anywhere.
 *
 * FRAG is not supported. RFC 1928 allows an implementation to drop datagrams
 * with FRAG non-zero, and every implementation does -- reassembling
 * fragmented SOCKS datagrams is a feature with no users and a buffer to
 * overflow.
 */
#ifndef TC_SOCKS_H_
#define TC_SOCKS_H_

#include "tc/endpoint.h"

#define TC_SOCKS_VERSION 5

/* Address types, RFC 1928 section 4. */
#define TC_SOCKS_ATYP_IPV4 0x01
#define TC_SOCKS_ATYP_NAME 0x03
#define TC_SOCKS_ATYP_IPV6 0x04

/* The hostname upstream uses to mean "the server at the end of the tunnel". */
#define TC_SOCKS_SERVER_HOST "server.tailcat"

/* The largest UDP relay header: 2 + 1 + 1 + 256 + 2, for a maximal name. */
#define TC_SOCKS_UDP_HEADER_MAX 262

typedef enum {
	/* The tailcat server itself, on target.port. */
	TC_SOCKS_TO_SERVER = 0,
	/* target.dst, reachable only through an exit node. */
	TC_SOCKS_TO_ADDRESS = 1
} tc_socks_kind;

typedef struct {
	tc_socks_kind kind;
	uint16_t port;      /* always set */
	tc_endpoint dst;    /* set when kind is TC_SOCKS_TO_ADDRESS */
} tc_socks_target;

/* tc_socks_classify decides where a request points.
 *
 * addr is the raw address field: four or sixteen bytes for an IP, or the
 * name's bytes (without its length prefix) for TC_SOCKS_ATYP_NAME.
 *
 * Returns TC_ERR_UNSUPPORTED for a name that is not the server's, because
 * resolving it is the caller's decision and needs DNS. TC_ERR_INVAL for a
 * malformed request, including a zero port -- which is the absence of a port
 * rather than a port. */
int tc_socks_classify(tc_socks_target *out, uint8_t atyp, const uint8_t *addr,
                      size_t addr_len, uint16_t port);

/* tc_socks_udp_parse reads the relay header off a datagram from the client.
 *
 * *out_data points into pkt, so it stays valid only as long as pkt does.
 *
 * Returns TC_ERR_UNSUPPORTED for a fragmented datagram or a hostname
 * destination, and TC_ERR_INVAL for anything malformed. A zero-length payload
 * is legal and reported as such. */
int tc_socks_udp_parse(const uint8_t *pkt, size_t len, tc_socks_target *out,
                       const uint8_t **out_data, size_t *out_data_len);

/* tc_socks_udp_build writes a reply datagram: the header naming src, then
 * data.
 *
 * src is where the datagram came from, as the client needs to be told -- a
 * client that sent to several destinations on one association has no other
 * way to tell the answers apart. */
int tc_socks_udp_build(uint8_t *out, size_t cap, size_t *out_len,
                       const tc_endpoint *src, const void *data, size_t len);

#endif /* TC_SOCKS_H_ */
