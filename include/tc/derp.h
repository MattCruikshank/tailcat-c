/* SPDX-License-Identifier: BSD-3-Clause
 *
 * The DERP relay protocol, client side.
 *
 * DERP is Tailscale's relay. tailcat uses it to bootstrap: both peers connect
 * to the same relay, exchange WireGuard handshake packets through it, and (in
 * full tailcat) then try to upgrade to a direct path. In the DERP-relay-only
 * scope this implementation targets, DERP carries every packet.
 *
 * Wire format. Every frame is a 1-byte type, a 4-byte big-endian length, and
 * that many payload bytes:
 *
 *     +--------+------------------+--------------------+
 *     | type:1 | length:4 (BE)    | payload: length    |
 *     +--------+------------------+--------------------+
 *
 * Connection setup:
 *
 *   1. TCP, then TLS (DERP runs on HTTPS).
 *   2. HTTP GET /derp with "Upgrade: DERP" and "Connection: Upgrade";
 *      the server answers 101 Switching Protocols.
 *   3. Server sends FRAME_SERVER_KEY: 8-byte magic "DERP\xf0\x9f\x94\x91"
 *      followed by its 32-byte public key.
 *   4. Client sends FRAME_CLIENT_INFO: its own 32-byte public key, a 24-byte
 *      nonce, and a NaCl box of a small JSON document.
 *   5. Server sends FRAME_SERVER_INFO: a 24-byte nonce and a NaCl box.
 *
 * Steady state: the client sends FRAME_SEND_PACKET (32-byte destination key
 * followed by the packet) and receives FRAME_RECV_PACKET (32-byte source key
 * followed by the packet). The server sends FRAME_KEEP_ALIVE periodically and
 * may send FRAME_PING, which the client echoes as FRAME_PONG.
 *
 * Note that the DERP handshake is NaCl box (X25519 + XSalsa20-Poly1305),
 * which is a different construction from the ChaCha20-Poly1305 used by the
 * WireGuard tunnel running inside it.
 */
#ifndef TC_DERP_H_
#define TC_DERP_H_

#include "tc/tc.h"

/* The 8-byte magic that opens FRAME_SERVER_KEY: "DERP" followed by the UTF-8
 * encoding of U+1F511 KEY. */
#define TC_DERP_MAGIC "DERP\xf0\x9f\x94\x91"
#define TC_DERP_MAGIC_LEN 8

/* Bumped by upstream on wire-incompatible changes. Version 2 puts the source
 * address at the start of FRAME_RECV_PACKET. */
#define TC_DERP_PROTOCOL_VERSION 2

#define TC_DERP_FRAME_HEADER_LEN 5
#define TC_DERP_KEY_LEN 32
#define TC_DERP_NONCE_LEN 24

/* Payload limits, matching upstream. MaxPacketSize bounds a relayed packet;
 * MaxInfoLen bounds the handshake JSON. */
#define TC_DERP_MAX_PACKET_SIZE (64u * 1024u)
#define TC_DERP_MAX_INFO_LEN (1u * 1024u * 1024u)

/* The largest frame we will accept. Anything bigger is a protocol error
 * rather than something to allocate for. */
#define TC_DERP_MAX_FRAME_LEN (TC_DERP_MAX_INFO_LEN + TC_DERP_NONCE_LEN)

/* The server sends a keep-alive at least this often; missing two of them
 * means the connection is dead. */
#define TC_DERP_KEEPALIVE_SECONDS 60

typedef enum {
	TC_DERP_FRAME_SERVER_KEY = 0x01,     /* magic + 32B server public key */
	TC_DERP_FRAME_CLIENT_INFO = 0x02,    /* 32B pub + 24B nonce + box(json) */
	TC_DERP_FRAME_SERVER_INFO = 0x03,    /* 24B nonce + box(json) */
	TC_DERP_FRAME_SEND_PACKET = 0x04,    /* 32B dest pub + packet */
	TC_DERP_FRAME_RECV_PACKET = 0x05,    /* 32B src pub + packet */
	TC_DERP_FRAME_KEEP_ALIVE = 0x06,     /* empty */
	TC_DERP_FRAME_NOTE_PREFERRED = 0x07, /* 1 byte: is this our home relay */
	TC_DERP_FRAME_PEER_GONE = 0x08,      /* 32B pub + 1 byte reason */
	TC_DERP_FRAME_PEER_PRESENT = 0x09,   /* 32B pub + optional extras */
	TC_DERP_FRAME_FORWARD_PACKET = 0x0a, /* 32B src + 32B dst + packet */
	TC_DERP_FRAME_WATCH_CONNS = 0x10,    /* mesh only */
	TC_DERP_FRAME_CLOSE_PEER = 0x11,     /* mesh only */
	TC_DERP_FRAME_PING = 0x12,           /* 8 byte payload to echo */
	TC_DERP_FRAME_PONG = 0x13,           /* the echoed 8 bytes */
	TC_DERP_FRAME_HEALTH = 0x14,         /* body is an error message */
	TC_DERP_FRAME_RESTARTING = 0x15      /* two BE uint32 millisecond hints */
} tc_derp_frame_type;

/* tc_derp_frame_name returns a static name for a frame type, for logs and
 * test failures. Unknown types give "unknown". */
const char *tc_derp_frame_name(unsigned type);

/* ---- frame headers --------------------------------------------------- */

/* tc_derp_frame_header_encode writes the 5-byte header. */
void tc_derp_frame_header_encode(uint8_t out[TC_DERP_FRAME_HEADER_LEN],
                                 uint8_t type, uint32_t payload_len);

/* tc_derp_frame_header_decode reads the 5-byte header.
 *
 * It rejects a payload length above TC_DERP_MAX_FRAME_LEN. The length is
 * attacker-controlled and is used to size a read, so refusing an absurd
 * value here is what stops a single frame from being asked to buffer 4GB. */
int tc_derp_frame_header_decode(const uint8_t in[TC_DERP_FRAME_HEADER_LEN],
                                uint8_t *type, uint32_t *payload_len);

/* ---- handshake frames ------------------------------------------------ */

/* tc_derp_parse_server_key extracts the server's public key from a
 * FRAME_SERVER_KEY payload, checking the magic.
 *
 * Upstream allows the greeting to be longer than 40 bytes for
 * future-proofing, so trailing bytes are ignored rather than rejected. */
int tc_derp_parse_server_key(uint8_t server_key[TC_DERP_KEY_LEN],
                             const uint8_t *payload, size_t len);

/* tc_derp_build_client_info builds a FRAME_CLIENT_INFO payload: our public
 * key, a fresh random nonce, and a NaCl box of the client-info JSON sealed to
 * the server's key.
 *
 * The JSON is generated internally and is deliberately minimal -- just the
 * protocol version -- because tailcat is an ordinary client: no mesh key, not
 * a prober, and it does not ack DERP-level pings.
 *
 * Returns the payload length in *out_len. */
int tc_derp_build_client_info(uint8_t *out, size_t cap, size_t *out_len,
                              const uint8_t our_public[TC_DERP_KEY_LEN],
                              const uint8_t our_private[TC_DERP_KEY_LEN],
                              const uint8_t server_key[TC_DERP_KEY_LEN]);

/* tc_derp_open_server_info verifies and decrypts a FRAME_SERVER_INFO payload
 * (24-byte nonce followed by the box) into out, which must have room for
 * len - 24 - 16 bytes. The plaintext is JSON; tailcat ignores its contents,
 * so this exists mainly to prove the server holds the matching private key. */
int tc_derp_open_server_info(uint8_t *out, size_t cap, size_t *out_len,
                             const uint8_t *payload, size_t len,
                             const uint8_t our_private[TC_DERP_KEY_LEN],
                             const uint8_t server_key[TC_DERP_KEY_LEN]);

/* ---- packet frames --------------------------------------------------- */

/* tc_derp_build_send_packet builds a FRAME_SEND_PACKET payload: the 32-byte
 * destination public key followed by the packet bytes. */
int tc_derp_build_send_packet(uint8_t *out, size_t cap, size_t *out_len,
                              const uint8_t dst_key[TC_DERP_KEY_LEN],
                              const void *pkt, size_t pkt_len);

/* tc_derp_parse_recv_packet splits a FRAME_RECV_PACKET payload into the
 * source public key and the packet. *pkt points into payload, so it stays
 * valid only as long as that buffer does. */
int tc_derp_parse_recv_packet(uint8_t src_key[TC_DERP_KEY_LEN],
                              const uint8_t **pkt, size_t *pkt_len,
                              const uint8_t *payload, size_t len);

/* ---- client ---------------------------------------------------------- */

#include "tc/tls.h"

typedef struct {
	tc_stream stream;
	uint8_t server_key[TC_DERP_KEY_LEN];
	uint8_t our_public[TC_DERP_KEY_LEN];
	uint8_t our_private[TC_DERP_KEY_LEN];
	bool connected;
} tc_derp_client;

typedef struct {
	/* Name for TLS SNI and certificate verification. Required. */
	const char *hostname;

	/* Optional literal IP to dial instead of resolving hostname, which is
	 * what a DERP map's IPv4/IPv6 fields provide. TLS still verifies against
	 * hostname. NULL means resolve hostname. */
	const char *dial_addr;

	/* 0 means 443. */
	uint16_t port;

	/* Skips TLS certificate verification. Corresponds to upstream's
	 * DERPNode.InsecureForTests and is for testing against a relay with a
	 * self-signed certificate. */
	bool insecure_skip_verify;

	/* 0 means no explicit timeout. */
	int timeout_ms;
} tc_derp_dial_opts;

/* tc_derp_connect dials a DERP relay and completes the full setup: TCP, TLS,
 * the HTTP upgrade, and the key exchange. On success the client is ready to
 * send and receive.
 *
 * our_private/our_public are this node's WireGuard-style keypair; DERP
 * addresses peers by public key, so the far side sends to our_public. */
int tc_derp_connect(tc_derp_client *c, const tc_derp_dial_opts *opts,
                    const uint8_t our_private[TC_DERP_KEY_LEN],
                    const uint8_t our_public[TC_DERP_KEY_LEN]);

/* tc_derp_send relays one packet to the peer with the given public key. */
int tc_derp_send(tc_derp_client *c, const uint8_t dst_key[TC_DERP_KEY_LEN],
                 const void *pkt, size_t pkt_len);

/* tc_derp_recv waits for one relayed packet, copying it into buf and the
 * sender's key into src_key.
 *
 * Frames that are not packets -- keep-alives, health notices, peer
 * presence -- are handled internally and do not return to the caller, so this
 * blocks until a real packet arrives or the connection fails. A server ping
 * is answered with a pong automatically. */
int tc_derp_recv(tc_derp_client *c, uint8_t src_key[TC_DERP_KEY_LEN],
                 uint8_t *buf, size_t cap, size_t *pkt_len);

/* tc_derp_set_read_timeout bounds how long tc_derp_recv waits before
 * returning TC_ERR_TIMEOUT. 0 waits indefinitely.
 *
 * A timeout is recoverable: the connection stays usable and the caller can
 * send something and try again. That is what the meow exchange needs, since
 * DERP delivery is best effort and the ping has to be resent while waiting
 * for the acknowledgment. */
int tc_derp_set_read_timeout(tc_derp_client *c, int ms);

/* tc_derp_fd returns a descriptor an event loop can poll, or -1.
 * tc_derp_has_pending must be checked first: a whole frame may already be
 * buffered inside the TLS layer with nothing left on the socket. */
int tc_derp_fd(tc_derp_client *c);
bool tc_derp_has_pending(tc_derp_client *c);

/* tc_derp_close tears down the connection. Safe on a zeroed or already
 * closed client. */
void tc_derp_close(tc_derp_client *c);

/* tc_derp_error_string returns detail about the last failure on this thread,
 * or "" if there is none. */
const char *tc_derp_error_string(void);

#endif /* TC_DERP_H_ */
