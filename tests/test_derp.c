/* SPDX-License-Identifier: BSD-3-Clause
 *
 * DERP frame codec tests. The handshake tests act out both ends: the client
 * side builds a frame with its own keys and the "server" side opens it with
 * the matching private key, which is what proves the NaCl box is wired up the
 * way the real server expects.
 */

#include "tc/derp.h"

#include "tc/crypto.h"
#include "tctest.h"

static void test_frame_header(void)
{
	TCT_CASE("header is type then big-endian length");
	uint8_t hdr[TC_DERP_FRAME_HEADER_LEN];
	tc_derp_frame_header_encode(hdr, TC_DERP_FRAME_SEND_PACKET, 0x01020304u);
	TCT_EQ_INT(hdr[0], TC_DERP_FRAME_SEND_PACKET);
	TCT_EQ_INT(hdr[1], 0x01);
	TCT_EQ_INT(hdr[2], 0x02);
	TCT_EQ_INT(hdr[3], 0x03);
	TCT_EQ_INT(hdr[4], 0x04);

	TCT_CASE("header round trips");
	const uint32_t lens[] = { 0, 1, 255, 256, 65535, 65536,
		                      TC_DERP_MAX_FRAME_LEN };
	for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
		uint8_t t = 0;
		uint32_t n = 0;
		tc_derp_frame_header_encode(hdr, TC_DERP_FRAME_RECV_PACKET, lens[i]);
		TCT_EQ_INT(tc_derp_frame_header_decode(hdr, &t, &n), TC_OK);
		TCT_EQ_INT(t, TC_DERP_FRAME_RECV_PACKET);
		TCT_EQ_INT(n, lens[i]);
	}

	TCT_CASE("an absurd length is refused, not believed");
	/* The length decides how much we are about to buffer, and it comes
	 * straight off the wire. */
	uint8_t t = 0;
	uint32_t n = 0;
	tc_derp_frame_header_encode(hdr, TC_DERP_FRAME_RECV_PACKET, 0xffffffffu);
	TCT_EQ_INT(tc_derp_frame_header_decode(hdr, &t, &n), TC_ERR_TOOMANY);
	tc_derp_frame_header_encode(hdr, TC_DERP_FRAME_RECV_PACKET,
	                            TC_DERP_MAX_FRAME_LEN + 1u);
	TCT_EQ_INT(tc_derp_frame_header_decode(hdr, &t, &n), TC_ERR_TOOMANY);

	TCT_CASE("unknown frame types decode but are named as unknown");
	tc_derp_frame_header_encode(hdr, 0x7f, 3);
	TCT_EQ_INT(tc_derp_frame_header_decode(hdr, &t, &n), TC_OK);
	TCT_EQ_INT(t, 0x7f);
	TCT_EQ_STR(tc_derp_frame_name(0x7f), "unknown");
	TCT_EQ_STR(tc_derp_frame_name(TC_DERP_FRAME_SERVER_KEY), "server-key");
}

static void test_server_key(void)
{
	uint8_t payload[TC_DERP_MAGIC_LEN + TC_DERP_KEY_LEN + 8];
	uint8_t key[TC_DERP_KEY_LEN], got[TC_DERP_KEY_LEN];

	memcpy(payload, TC_DERP_MAGIC, TC_DERP_MAGIC_LEN);
	for (size_t i = 0; i < TC_DERP_KEY_LEN; i++)
		key[i] = (uint8_t)(0x30 + i);
	memcpy(payload + TC_DERP_MAGIC_LEN, key, TC_DERP_KEY_LEN);

	TCT_CASE("parses the server greeting");
	TCT_EQ_INT(tc_derp_parse_server_key(got, payload,
	                                    TC_DERP_MAGIC_LEN + TC_DERP_KEY_LEN),
	           TC_OK);
	TCT_EQ_MEM(got, key, TC_DERP_KEY_LEN);

	TCT_CASE("tolerates a longer greeting, as upstream does");
	memset(payload + TC_DERP_MAGIC_LEN + TC_DERP_KEY_LEN, 0xaa, 8);
	TCT_EQ_INT(tc_derp_parse_server_key(got, payload, sizeof payload), TC_OK);
	TCT_EQ_MEM(got, key, TC_DERP_KEY_LEN);

	TCT_CASE("rejects a bad magic");
	payload[0] ^= 1;
	TCT_EQ_INT(tc_derp_parse_server_key(got, payload, sizeof payload),
	           TC_ERR_INVAL);
	payload[0] ^= 1;
	/* The magic really is "DERP" plus U+1F511. */
	TCT_EQ_MEM(payload, "DERP\xf0\x9f\x94\x91", 8);

	TCT_CASE("rejects a short greeting");
	TCT_EQ_INT(tc_derp_parse_server_key(got, payload,
	                                    TC_DERP_MAGIC_LEN + TC_DERP_KEY_LEN - 1),
	           TC_ERR_TRUNC);
	TCT_EQ_INT(tc_derp_parse_server_key(got, payload, 0), TC_ERR_TRUNC);
}

/* Builds a client-info frame and opens it the way the server would. */
static void test_client_info(void)
{
	uint8_t csk[32], cpk[32], ssk[32], spk[32];
	TCT_EQ_INT(tc_x25519_keypair(csk, cpk), TC_OK);
	TCT_EQ_INT(tc_x25519_keypair(ssk, spk), TC_OK);

	uint8_t frame[256];
	size_t frame_len = 0;

	TCT_CASE("builds a client-info frame");
	TCT_EQ_INT(tc_derp_build_client_info(frame, sizeof frame, &frame_len, cpk,
	                                     csk, spk),
	           TC_OK);
	/* 32B public key + 24B nonce + 16B tag + the JSON. */
	TCT_TRUE(frame_len > TC_DERP_KEY_LEN + TC_DERP_NONCE_LEN + 16);

	TCT_CASE("the frame starts with our public key");
	TCT_EQ_MEM(frame, cpk, TC_DERP_KEY_LEN);

	TCT_CASE("the server can open it with its private key");
	const uint8_t *nonce = frame + TC_DERP_KEY_LEN;
	const uint8_t *box = frame + TC_DERP_KEY_LEN + TC_DERP_NONCE_LEN;
	size_t box_len = frame_len - TC_DERP_KEY_LEN - TC_DERP_NONCE_LEN;

	uint8_t json[128];
	TCT_EQ_INT(tc_box_open(json, nonce, box, box_len, cpk, ssk), TC_OK);
	json[box_len - 16] = '\0';
	TCT_EQ_STR((const char *)json, "{\"version\":2,\"CanAckPings\":false}");

	TCT_CASE("a different server key cannot open it");
	uint8_t osk[32], opk[32];
	TCT_EQ_INT(tc_x25519_keypair(osk, opk), TC_OK);
	TCT_EQ_INT(tc_box_open(json, nonce, box, box_len, cpk, osk), TC_ERR_INVAL);

	TCT_CASE("each frame uses a fresh nonce");
	uint8_t frame2[256];
	size_t frame2_len = 0;
	TCT_EQ_INT(tc_derp_build_client_info(frame2, sizeof frame2, &frame2_len,
	                                     cpk, csk, spk),
	           TC_OK);
	TCT_EQ_INT(frame2_len, frame_len);
	/* Same key prefix, different nonce, therefore different ciphertext. */
	TCT_EQ_MEM(frame2, cpk, TC_DERP_KEY_LEN);
	TCT_TRUE(memcmp(frame + TC_DERP_KEY_LEN, frame2 + TC_DERP_KEY_LEN,
	                TC_DERP_NONCE_LEN) != 0);

	TCT_CASE("a too-small buffer is refused");
	TCT_EQ_INT(tc_derp_build_client_info(frame, 16, &frame_len, cpk, csk, spk),
	           TC_ERR_NOSPACE);
}

/* Builds a server-info frame the way the server would, then opens it. */
static void test_server_info(void)
{
	uint8_t csk[32], cpk[32], ssk[32], spk[32];
	TCT_EQ_INT(tc_x25519_keypair(csk, cpk), TC_OK);
	TCT_EQ_INT(tc_x25519_keypair(ssk, spk), TC_OK);

	static const char kJson[] = "{\"Version\":2,\"TokenBucketBytesPerSecond\":0}";
	const size_t json_len = sizeof kJson - 1;

	uint8_t payload[256];
	TCT_EQ_INT(tc_random_bytes(payload, TC_DERP_NONCE_LEN), TC_OK);
	TCT_EQ_INT(tc_box_seal(payload + TC_DERP_NONCE_LEN, payload, kJson,
	                       json_len, cpk, ssk),
	           TC_OK);
	size_t payload_len = TC_DERP_NONCE_LEN + json_len + 16;

	TCT_CASE("opens the server-info frame");
	uint8_t out[256];
	size_t out_len = 0;
	TCT_EQ_INT(tc_derp_open_server_info(out, sizeof out, &out_len, payload,
	                                    payload_len, csk, spk),
	           TC_OK);
	TCT_EQ_INT(out_len, json_len);
	TCT_EQ_MEM(out, kJson, json_len);

	TCT_CASE("rejects a tampered server-info frame");
	payload[TC_DERP_NONCE_LEN + 2] ^= 1;
	TCT_EQ_INT(tc_derp_open_server_info(out, sizeof out, &out_len, payload,
	                                    payload_len, csk, spk),
	           TC_ERR_INVAL);
	payload[TC_DERP_NONCE_LEN + 2] ^= 1;

	TCT_CASE("rejects a frame from the wrong server key");
	uint8_t osk[32], opk[32];
	TCT_EQ_INT(tc_x25519_keypair(osk, opk), TC_OK);
	TCT_EQ_INT(tc_derp_open_server_info(out, sizeof out, &out_len, payload,
	                                    payload_len, csk, opk),
	           TC_ERR_INVAL);

	TCT_CASE("rejects a frame too short to hold a nonce and tag");
	TCT_EQ_INT(tc_derp_open_server_info(out, sizeof out, &out_len, payload,
	                                    TC_DERP_NONCE_LEN + 15, csk, spk),
	           TC_ERR_TRUNC);
	TCT_EQ_INT(tc_derp_open_server_info(out, sizeof out, &out_len, payload, 0,
	                                    csk, spk),
	           TC_ERR_TRUNC);

	TCT_CASE("refuses to overflow a small output buffer");
	TCT_EQ_INT(tc_derp_open_server_info(out, 4, &out_len, payload, payload_len,
	                                    csk, spk),
	           TC_ERR_NOSPACE);
}

static void test_packet_frames(void)
{
	uint8_t dst[TC_DERP_KEY_LEN];
	for (size_t i = 0; i < sizeof dst; i++)
		dst[i] = (uint8_t)i;

	static uint8_t out[TC_DERP_MAX_PACKET_SIZE + TC_DERP_KEY_LEN + 16];
	static const uint8_t pkt[] = { 1, 2, 3, 4, 5 };
	size_t out_len = 0;

	TCT_CASE("send-packet is destination key then packet");
	TCT_EQ_INT(tc_derp_build_send_packet(out, sizeof out, &out_len, dst, pkt,
	                                     sizeof pkt),
	           TC_OK);
	TCT_EQ_INT(out_len, TC_DERP_KEY_LEN + sizeof pkt);
	TCT_EQ_MEM(out, dst, TC_DERP_KEY_LEN);
	TCT_EQ_MEM(out + TC_DERP_KEY_LEN, pkt, sizeof pkt);

	TCT_CASE("recv-packet splits source key from payload");
	uint8_t src[TC_DERP_KEY_LEN];
	const uint8_t *body = NULL;
	size_t body_len = 0;
	TCT_EQ_INT(tc_derp_parse_recv_packet(src, &body, &body_len, out, out_len),
	           TC_OK);
	TCT_EQ_MEM(src, dst, TC_DERP_KEY_LEN);
	TCT_EQ_INT(body_len, sizeof pkt);
	TCT_EQ_MEM(body, pkt, sizeof pkt);

	TCT_CASE("an empty relayed packet is allowed");
	TCT_EQ_INT(tc_derp_build_send_packet(out, sizeof out, &out_len, dst, NULL,
	                                     0),
	           TC_OK);
	TCT_EQ_INT(out_len, TC_DERP_KEY_LEN);
	TCT_EQ_INT(tc_derp_parse_recv_packet(src, &body, &body_len, out, out_len),
	           TC_OK);
	TCT_EQ_INT(body_len, 0);

	TCT_CASE("a recv-packet with no room for a source key is refused");
	TCT_EQ_INT(tc_derp_parse_recv_packet(src, &body, &body_len, out,
	                                     TC_DERP_KEY_LEN - 1),
	           TC_ERR_TRUNC);

	TCT_CASE("an oversized packet is refused");
	static uint8_t big[TC_DERP_MAX_PACKET_SIZE + 1];
	TCT_EQ_INT(tc_derp_build_send_packet(out, sizeof out, &out_len, dst, big,
	                                     sizeof big),
	           TC_ERR_TOOMANY);

	TCT_CASE("the maximum packet size is accepted");
	TCT_EQ_INT(tc_derp_build_send_packet(out, sizeof out, &out_len, dst, big,
	                                     TC_DERP_MAX_PACKET_SIZE),
	           TC_OK);
	TCT_EQ_INT(out_len, TC_DERP_KEY_LEN + TC_DERP_MAX_PACKET_SIZE);

	TCT_CASE("a too-small output buffer is refused");
	TCT_EQ_INT(tc_derp_build_send_packet(out, 8, &out_len, dst, pkt,
	                                     sizeof pkt),
	           TC_ERR_NOSPACE);
}

/* ---- the receive loop, over a scripted stream --------------------------- */

/* Everything above tests the codec. The frame loop -- what is answered, what
 * is skipped, and what ends the connection -- had no test at all, which is
 * where the liveness and restart handling had to go. A tc_stream backed by a
 * byte buffer is enough to drive it with no network. */

typedef struct {
	const uint8_t *in;
	size_t in_len;
	size_t in_off;
	uint8_t out[4096];
	size_t out_len;
	bool eof_is_timeout; /* run dry as a timeout rather than a close */
} scripted;

static int scripted_read(tc_stream *st, uint8_t *buf, size_t len,
                         size_t *nread)
{
	scripted *sc = (scripted *)st->ctx;
	if (sc->in_off >= sc->in_len)
		return sc->eof_is_timeout ? TC_ERR_TIMEOUT : TC_ERR_TRUNC;
	size_t n = sc->in_len - sc->in_off;
	if (n > len)
		n = len;
	memcpy(buf, sc->in + sc->in_off, n);
	sc->in_off += n;
	*nread = n;
	return TC_OK;
}

static int scripted_write(tc_stream *st, const uint8_t *buf, size_t len)
{
	scripted *sc = (scripted *)st->ctx;
	if (sc->out_len + len > sizeof sc->out)
		return TC_ERR_NOSPACE;
	memcpy(sc->out + sc->out_len, buf, len);
	sc->out_len += len;
	return TC_OK;
}

static void scripted_close(tc_stream *st) { (void)st; }

static void scripted_client(tc_derp_client *c, scripted *sc,
                            const uint8_t *script, size_t len)
{
	memset(c, 0, sizeof *c);
	memset(sc, 0, sizeof *sc);
	sc->in = script;
	sc->in_len = len;
	c->stream.read_some = scripted_read;
	c->stream.write_all = scripted_write;
	c->stream.close = scripted_close;
	c->stream.ctx = sc;
	c->connected = true;
}

/* frame appends one DERP frame to a buffer. */
static size_t frame(uint8_t *out, size_t off, uint8_t type, const void *body,
                    size_t body_len)
{
	tc_derp_frame_header_encode(out + off, type, (uint32_t)body_len);
	off += TC_DERP_FRAME_HEADER_LEN;
	if (body_len != 0)
		memcpy(out + off, body, body_len);
	return off + body_len;
}

static void test_recv_loop(void)
{
	static uint8_t script[1024];
	static uint8_t body[TC_DERP_KEY_LEN + 8];
	uint8_t src[TC_DERP_KEY_LEN];
	static uint8_t buf[512];
	size_t got = 0;
	tc_derp_client c;
	scripted sc;

	TCT_CASE("a keep-alive is skipped and the packet behind it is delivered");
	memset(body, 0xAB, sizeof body);
	size_t n = 0;
	n = frame(script, n, TC_DERP_FRAME_KEEP_ALIVE, NULL, 0);
	n = frame(script, n, TC_DERP_FRAME_HEALTH, "ok", 2);
	n = frame(script, n, TC_DERP_FRAME_RECV_PACKET, body,
	          TC_DERP_KEY_LEN + 5);
	scripted_client(&c, &sc, script, n);
	TCT_EQ_INT(tc_derp_recv(&c, src, buf, sizeof buf, &got), TC_OK);
	TCT_EQ_INT((int)got, 5);

	TCT_CASE("a ping is answered with a pong carrying the same payload");
	static const uint8_t kPing[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	n = frame(script, 0, TC_DERP_FRAME_PING, kPing, sizeof kPing);
	n = frame(script, n, TC_DERP_FRAME_RECV_PACKET, body,
	          TC_DERP_KEY_LEN + 1);
	scripted_client(&c, &sc, script, n);
	TCT_EQ_INT(tc_derp_recv(&c, src, buf, sizeof buf, &got), TC_OK);
	TCT_EQ_INT((int)sc.out_len, TC_DERP_FRAME_HEADER_LEN + 8);
	TCT_EQ_INT(sc.out[0], TC_DERP_FRAME_PONG);
	TCT_EQ_MEM(sc.out + TC_DERP_FRAME_HEADER_LEN, kPing, 8);

	TCT_CASE("FRAME_RESTARTING ends the connection rather than being ignored");
	/* The relay is telling us, before it happens, exactly what is about to
	 * go wrong. Treating it as informational would mean waiting for the
	 * socket to die instead of reconnecting at once. */
	static const uint8_t kRestart[8] = { 0 };
	n = frame(script, 0, TC_DERP_FRAME_RESTARTING, kRestart, sizeof kRestart);
	n = frame(script, n, TC_DERP_FRAME_RECV_PACKET, body,
	          TC_DERP_KEY_LEN + 1);
	scripted_client(&c, &sc, script, n);
	TCT_EQ_INT(tc_derp_recv(&c, src, buf, sizeof buf, &got), TC_ERR_CLOSED);
	TCT_TRUE(tc_derp_is_restarting(&c));
	/* And the packet behind it is not delivered: the caller must rebuild
	 * the connection first. */
	TCT_EQ_INT(tc_derp_recv(&c, src, buf, sizeof buf, &got), TC_ERR_CLOSED);

	TCT_CASE("a relay that hangs up reports a closed connection");
	/* Distinguishing this from a protocol error is what lets the caller
	 * reconnect instead of giving up. */
	n = frame(script, 0, TC_DERP_FRAME_KEEP_ALIVE, NULL, 0);
	scripted_client(&c, &sc, script, n);
	TCT_EQ_INT(tc_derp_recv(&c, src, buf, sizeof buf, &got), TC_ERR_CLOSED);
	TCT_TRUE(!tc_derp_is_restarting(&c));

	TCT_CASE("an unknown frame type is skipped, not fatal");
	/* The protocol is versioned and relays may add types. */
	n = frame(script, 0, 0x7e, "whatever", 8);
	n = frame(script, n, TC_DERP_FRAME_RECV_PACKET, body,
	          TC_DERP_KEY_LEN + 3);
	scripted_client(&c, &sc, script, n);
	TCT_EQ_INT(tc_derp_recv(&c, src, buf, sizeof buf, &got), TC_OK);
	TCT_EQ_INT((int)got, 3);

	TCT_CASE("a packet larger than the caller's buffer is refused");
	n = frame(script, 0, TC_DERP_FRAME_RECV_PACKET, body, sizeof body);
	scripted_client(&c, &sc, script, n);
	TCT_EQ_INT(tc_derp_recv(&c, src, buf, 2, &got), TC_ERR_NOSPACE);

	TCT_CASE("a timeout leaves the connection usable");
	n = 0;
	scripted_client(&c, &sc, script, n);
	sc.eof_is_timeout = true;
	TCT_EQ_INT(tc_derp_recv(&c, src, buf, sizeof buf, &got), TC_ERR_TIMEOUT);
	TCT_TRUE(!tc_derp_is_restarting(&c));

	TCT_CASE("reconnecting a client that was never dialled is refused");
	memset(&c, 0, sizeof c);
	TCT_EQ_INT(tc_derp_reconnect(&c), TC_ERR_INVAL);
	TCT_EQ_INT(tc_derp_reconnect(NULL), TC_ERR_INVAL);
	TCT_EQ_INT((int)tc_derp_reconnect_count(NULL), 0);
	TCT_EQ_INT((int)tc_derp_idle_ms(NULL), 0);
}

int main(void)
{
	test_frame_header();
	test_server_key();
	test_client_info();
	test_server_info();
	test_packet_frames();
	test_recv_loop();
	return tct_report("derp");
}
