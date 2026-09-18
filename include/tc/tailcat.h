/* SPDX-License-Identifier: BSD-3-Clause
 *
 * The tailcat layer: how two peers introduce themselves through a relay, and
 * how they address each other inside the tunnel.
 *
 * This is the piece that joins DERP and WireGuard together. DERP will relay a
 * packet to any node key, and WireGuard will complete a handshake with any
 * configured peer -- but a tailcat server does not know a client exists until
 * the client says so, and it will not answer a WireGuard handshake from a
 * peer it has never heard of. The "meow" exchange is that introduction:
 *
 *   client -> server   meow ping   "meow" 0x01 <node key> <disco key>
 *   server -> client   meowed      "meow" 0x02
 *
 * Both travel as raw DERP packets, not disco-framed, which is why they carry
 * a magic prefix: it distinguishes them from WireGuard message types (1..4)
 * and from disco's own "TS<speech balloon>" magic on the same channel.
 *
 * The server replies only once it has actually added the client as a
 * WireGuard peer, so "meowed" is the client's signal that a handshake will
 * now be answered. DERP delivery is best effort -- a relay drops packets
 * addressed to a key that is not connected yet -- so the ping is resent
 * periodically. The exchange is idempotent: the server acks every ping.
 */
#ifndef TC_TAILCAT_H_
#define TC_TAILCAT_H_

#include "tc/tc.h"

#define TC_MEOW_MAGIC "meow"
#define TC_MEOW_MAGIC_LEN 4

#define TC_MEOW_TYPE_PING 0x01u
#define TC_MEOW_TYPE_MEOWED 0x02u

/* 4 magic + 1 type + 32 node key + 32 disco key. */
#define TC_MEOW_PING_LEN (TC_MEOW_MAGIC_LEN + 1 + 32 + 32)
#define TC_MEOW_MEOWED_LEN (TC_MEOW_MAGIC_LEN + 1)

/* tc_meow_is_packet reports whether pkt carries the meow magic. A relayed
 * packet that is not a meow packet is WireGuard traffic and belongs to the
 * tunnel. */
bool tc_meow_is_packet(const uint8_t *pkt, size_t len);

/* tc_meow_is_meowed reports whether pkt is the acknowledgment. */
bool tc_meow_is_meowed(const uint8_t *pkt, size_t len);

/* tc_meow_encode_ping writes a meow ping carrying our node and disco public
 * keys. */
int tc_meow_encode_ping(uint8_t *out, size_t cap, size_t *out_len,
                        const uint8_t node_pub[32],
                        const uint8_t disco_pub[32]);

/* tc_meow_encode_meowed writes the acknowledgment. */
int tc_meow_encode_meowed(uint8_t *out, size_t cap, size_t *out_len);

/* tc_meow_parse_ping extracts the sender's keys from a meow ping.
 *
 * An all-zero disco key is rejected: upstream treats it as malformed rather
 * than as "no disco key", and accepting one would mean recording a peer we
 * could never do path discovery with. */
int tc_meow_parse_ping(const uint8_t *pkt, size_t len, uint8_t out_node[32],
                       uint8_t out_disco[32]);

/* ---- disco keys ------------------------------------------------------ */

/* tc_disco_key_for_node derives the path-discovery keypair from a node
 * private key.
 *
 * It is deterministic -- HMAC-SHA256 over a fixed label, keyed by the node
 * private key, then clamped as a Curve25519 scalar -- so a peer that knows
 * only its own node key can still produce the disco key its address must
 * advertise. The two keys are deliberately independent in what they reveal:
 * disco keys travel in cleartext on direct paths, whereas the node key is the
 * unguessable part of a tailcat address.
 *
 * Either output pointer may be NULL. */
int tc_disco_key_for_node(uint8_t out_private[32], uint8_t out_public[32],
                          const uint8_t node_private[32]);

/* ---- tunnel addressing ----------------------------------------------- */

#define TC_TUNNEL_ADDR_LEN 16

/* tc_tunnel_addr_for_key derives the IPv6 address a node uses inside the
 * tunnel: Tailscale's ULA prefix fd7a:115c:a1e0::/48 followed by the first
 * ten bytes of the node public key. */
void tc_tunnel_addr_for_key(uint8_t out[TC_TUNNEL_ADDR_LEN],
                            const uint8_t node_pub[32]);

/* tc_tunnel_addr_format writes the conventional text form of an IPv6
 * address, with the longest run of zero groups compressed to "::". cap must
 * be at least 40 bytes. */
int tc_tunnel_addr_format(char *out, size_t cap,
                          const uint8_t addr[TC_TUNNEL_ADDR_LEN]);


/* tc_usage_text is what `tailcat-c readme` prints: a short usage document,
 * generated from doc/usage.md by scripts/gen-usage.py.
 *
 * Deliberately not README.md, which upstream embeds for its equivalent
 * command. Ours is a fuller manual, and it opens with a section on what this
 * port does not do -- useful reading, and not what someone who typed `readme`
 * at a terminal is after. They want the examples. */
extern const char tc_usage_text[];

#endif /* TC_TAILCAT_H_ */
