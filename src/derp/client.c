/* SPDX-License-Identifier: BSD-3-Clause
 *
 * The DERP client: dialling, the HTTP upgrade, the key exchange, and the
 * steady-state send/receive loop.
 *
 * The frame encoding itself lives in frame.c and is pure; this file is the
 * part that talks to a socket.
 */

#include "tc/derp.h"

#include "tc/crypto.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

static _Thread_local char g_err[256];

const char *tc_derp_error_string(void)
{
	return g_err;
}

#define FAILF(...)                                                            \
	do {                                                                      \
		(void)snprintf(g_err, sizeof g_err, __VA_ARGS__);                     \
	} while (0)

/* ---- framing over a stream ------------------------------------------- */

static int write_frame(tc_stream *s, uint8_t type, const uint8_t *payload,
                       size_t len)
{
	uint8_t hdr[TC_DERP_FRAME_HEADER_LEN];

	if (len > TC_DERP_MAX_FRAME_LEN)
		return TC_ERR_TOOMANY;

	tc_derp_frame_header_encode(hdr, type, (uint32_t)len);
	int rc = s->write_all(s, hdr, sizeof hdr);
	if (rc != TC_OK)
		return rc;
	if (len == 0)
		return TC_OK;
	return s->write_all(s, payload, len);
}

/* read_frame reads one frame into buf. A frame larger than cap is a protocol
 * error rather than something to grow a buffer for: the caller's buffer is
 * already sized for the largest frame the protocol allows. */
static int read_frame(tc_stream *s, uint8_t *type, uint8_t *buf, size_t cap,
                      size_t *len)
{
	uint8_t hdr[TC_DERP_FRAME_HEADER_LEN];
	int rc = tc_stream_read_full(s, hdr, sizeof hdr);
	if (rc != TC_OK)
		return rc;

	uint32_t n = 0;
	rc = tc_derp_frame_header_decode(hdr, type, &n);
	if (rc != TC_OK) {
		FAILF("bad frame header (length %u)", n);
		return rc;
	}
	if (n > cap) {
		FAILF("frame of %u bytes exceeds the %zu byte buffer", n, cap);
		return TC_ERR_TOOMANY;
	}

	if (n != 0) {
		rc = tc_stream_read_full(s, buf, n);
		if (rc != TC_OK)
			return rc;
	}
	*len = n;
	return TC_OK;
}

/* ---- HTTP upgrade ---------------------------------------------------- */

/* read_http_response consumes exactly the response header, stopping at the
 * blank line.
 *
 * Deliberately byte at a time: DERP frames begin immediately after the header
 * terminator on the same connection, so reading even one byte too far would
 * swallow the start of FRAME_SERVER_KEY. Buffering would mean handing that
 * leftover to the frame reader, which is more machinery than a short header
 * justifies. */
static int read_http_response(tc_stream *s, char *buf, size_t cap)
{
	size_t n = 0;
	int matched = 0; /* how much of CRLF CRLF we have seen */

	while (matched < 4) {
		if (n + 1 >= cap) {
			FAILF("HTTP response header exceeded %zu bytes", cap);
			return TC_ERR_TOOMANY;
		}
		uint8_t c = 0;
		int rc = tc_stream_read_full(s, &c, 1);
		if (rc != TC_OK) {
			FAILF("connection closed during HTTP upgrade");
			return rc;
		}
		buf[n++] = (char)c;

		const char want[4] = { '\r', '\n', '\r', '\n' };
		if (c == (uint8_t)want[matched]) {
			matched++;
		} else {
			/* A lone CR restarts the match; anything else resets it. */
			matched = (c == '\r') ? 1 : 0;
		}
	}
	buf[n] = '\0';
	return TC_OK;
}

static int http_upgrade(tc_stream *s, const char *hostname)
{
	char req[512];
	int reqlen = snprintf(req, sizeof req,
	                      "GET /derp HTTP/1.1\r\n"
	                      "Host: %s\r\n"
	                      "Upgrade: DERP\r\n"
	                      "Connection: Upgrade\r\n"
	                      "User-Agent: tailcat-c/0.1\r\n"
	                      "\r\n",
	                      hostname);
	if (reqlen <= 0 || (size_t)reqlen >= sizeof req) {
		FAILF("hostname too long for the upgrade request");
		return TC_ERR_NOSPACE;
	}

	int rc = s->write_all(s, (const uint8_t *)req, (size_t)reqlen);
	if (rc != TC_OK) {
		FAILF("failed to send the HTTP upgrade request");
		return rc;
	}

	char resp[2048];
	rc = read_http_response(s, resp, sizeof resp);
	if (rc != TC_OK)
		return rc;

	/* Expect "HTTP/1.1 101 Switching Protocols". Anything else -- a 404 from
	 * a host that is not a relay, a 502 from a proxy -- must not be treated
	 * as a DERP stream. */
	if (strncmp(resp, "HTTP/1.1 101", 12) != 0 &&
	    strncmp(resp, "HTTP/1.0 101", 12) != 0) {
		char *eol = strpbrk(resp, "\r\n");
		if (eol != NULL)
			*eol = '\0';
		FAILF("expected 101 Switching Protocols, got \"%.120s\"", resp);
		return TC_ERR_INVAL;
	}
	return TC_OK;
}

/* ---- handshake ------------------------------------------------------- */

static int derp_handshake(tc_derp_client *c)
{
	/* Big enough for any handshake frame; the server-info box is bounded by
	 * MaxInfoLen but real servers send a few dozen bytes. */
	static const size_t kBufLen = 4096;
	uint8_t buf[4096];
	uint8_t type = 0;
	size_t len = 0;

	int rc = read_frame(&c->stream, &type, buf, kBufLen, &len);
	if (rc != TC_OK) {
		if (g_err[0] == '\0')
			FAILF("failed to read the server greeting");
		return rc;
	}
	if (type != TC_DERP_FRAME_SERVER_KEY) {
		FAILF("expected server-key frame, got %s (0x%02x)",
		      tc_derp_frame_name(type), type);
		return TC_ERR_INVAL;
	}
	rc = tc_derp_parse_server_key(c->server_key, buf, len);
	if (rc != TC_OK) {
		FAILF("malformed server greeting");
		return rc;
	}

	uint8_t info[256];
	size_t info_len = 0;
	rc = tc_derp_build_client_info(info, sizeof info, &info_len,
	                               c->our_public, c->our_private,
	                               c->server_key);
	if (rc != TC_OK) {
		FAILF("failed to build client-info");
		return rc;
	}
	rc = write_frame(&c->stream, TC_DERP_FRAME_CLIENT_INFO, info, info_len);
	if (rc != TC_OK) {
		FAILF("failed to send client-info");
		return rc;
	}

	rc = read_frame(&c->stream, &type, buf, kBufLen, &len);
	if (rc != TC_OK) {
		if (g_err[0] == '\0')
			FAILF("failed to read server-info");
		return rc;
	}
	if (type != TC_DERP_FRAME_SERVER_INFO) {
		FAILF("expected server-info frame, got %s (0x%02x)",
		      tc_derp_frame_name(type), type);
		return TC_ERR_INVAL;
	}

	/* We do not use anything in the server-info document, but opening it
	 * proves the relay holds the private key matching the public key it
	 * greeted us with. */
	uint8_t plain[4096];
	size_t plain_len = 0;
	rc = tc_derp_open_server_info(plain, sizeof plain, &plain_len, buf, len,
	                              c->our_private, c->server_key);
	if (rc != TC_OK) {
		FAILF("could not open the server-info box; the relay did not prove "
		      "it holds the advertised key");
		return rc;
	}

	tc_memzero_explicit(plain, sizeof plain);
	return TC_OK;
}

/* derp_now_ms is a monotonic millisecond clock. Unlike the layers above, this
 * one already does blocking I/O against real timeouts, so it has no reason to
 * take a clock from its caller. */
static uint64_t derp_now_ms(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

int tc_derp_connect(tc_derp_client *c, const tc_derp_dial_opts *opts,
                    const uint8_t our_private[TC_DERP_KEY_LEN],
                    const uint8_t our_public[TC_DERP_KEY_LEN])
{
	if (c == NULL || opts == NULL || opts->hostname == NULL ||
	    our_private == NULL || our_public == NULL)
		return TC_ERR_INVAL;

	g_err[0] = '\0';
	memset(c, 0, sizeof *c);
	memcpy(c->our_private, our_private, TC_DERP_KEY_LEN);
	memcpy(c->our_public, our_public, TC_DERP_KEY_LEN);

	const char *dial = (opts->dial_addr != NULL && opts->dial_addr[0] != '\0')
	                       ? opts->dial_addr
	                       : opts->hostname;
	uint16_t port = (opts->port != 0) ? opts->port : 443;

	/* Keep enough to repeat this dial. The strings are copied because a
	 * reconnection may come minutes later, long after the caller's own
	 * buffers have been reused. */
	(void)snprintf(c->redial_host, sizeof c->redial_host, "%s", opts->hostname);
	if (opts->dial_addr != NULL && opts->dial_addr[0] != 0) {
		(void)snprintf(c->redial_addr, sizeof c->redial_addr, "%s",
		               opts->dial_addr);
		c->has_redial_addr = true;
	}
	c->redial_port = port;
	c->redial_insecure = opts->insecure_skip_verify;
	c->redial_timeout_ms = opts->timeout_ms;

	tc_stream tcp;
	memset(&tcp, 0, sizeof tcp);
	int rc = tc_net_tcp_connect(&tcp, dial, port, opts->timeout_ms);
	if (rc != TC_OK) {
		FAILF("could not connect to %s port %u", dial, (unsigned)port);
		return rc;
	}

	tc_tls_config tls;
	memset(&tls, 0, sizeof tls);
	tls.server_name = opts->hostname;
	tls.insecure_skip_verify = opts->insecure_skip_verify;

	rc = tc_tls_client(&c->stream, &tcp, &tls);
	if (rc != TC_OK) {
		FAILF("TLS to %s failed: %s", opts->hostname, tc_tls_error_string());
		tcp.close(&tcp);
		return rc;
	}

	rc = http_upgrade(&c->stream, opts->hostname);
	if (rc != TC_OK)
		goto fail;

	rc = derp_handshake(c);
	if (rc != TC_OK)
		goto fail;

	c->connected = true;
	c->last_recv_ms = derp_now_ms();
	return TC_OK;

fail:
	c->stream.close(&c->stream);
	tc_memzero_explicit(c->our_private, sizeof c->our_private);
	return rc;
}

int tc_derp_send(tc_derp_client *c, const uint8_t dst_key[TC_DERP_KEY_LEN],
                 const void *pkt, size_t pkt_len)
{
	if (c == NULL || !c->connected || dst_key == NULL)
		return TC_ERR_INVAL;
	if (c->restarting)
		return TC_ERR_CLOSED;

	static _Thread_local uint8_t payload[TC_DERP_KEY_LEN +
	                                     TC_DERP_MAX_PACKET_SIZE];
	size_t payload_len = 0;
	int rc = tc_derp_build_send_packet(payload, sizeof payload, &payload_len,
	                                   dst_key, pkt, pkt_len);
	if (rc != TC_OK)
		return rc;

	return write_frame(&c->stream, TC_DERP_FRAME_SEND_PACKET, payload,
	                   payload_len);
}

int tc_derp_recv(tc_derp_client *c, uint8_t src_key[TC_DERP_KEY_LEN],
                 uint8_t *buf, size_t cap, size_t *pkt_len)
{
	if (c == NULL || !c->connected || src_key == NULL || buf == NULL)
		return TC_ERR_INVAL;

	/* Once the relay has said it is going away, this connection is finished.
	 * There may be a frame or two still buffered behind the announcement,
	 * but delivering them would let a caller ignore the signal and keep
	 * using a socket that is about to vanish -- and losing a packet is
	 * something every layer above already handles, where a silently dying
	 * relay is not. */
	if (c->restarting)
		return TC_ERR_CLOSED;

	static _Thread_local uint8_t frame[TC_DERP_KEY_LEN +
	                                   TC_DERP_MAX_PACKET_SIZE];

	for (;;) {
		uint8_t type = 0;
		size_t len = 0;
		int rc = read_frame(&c->stream, &type, frame, sizeof frame, &len);
		if (rc == TC_ERR_TRUNC)
			return TC_ERR_CLOSED; /* the relay hung up */
		if (rc != TC_OK)
			return rc;

		/* Any frame proves the relay is alive, keep-alives included -- that
		 * is what they are for. */
		c->last_recv_ms = derp_now_ms();

		switch (type) {
		case TC_DERP_FRAME_RECV_PACKET: {
			const uint8_t *body = NULL;
			size_t body_len = 0;
			rc = tc_derp_parse_recv_packet(src_key, &body, &body_len, frame,
			                               len);
			if (rc != TC_OK) {
				FAILF("malformed recv-packet frame");
				return rc;
			}
			if (body_len > cap) {
				FAILF("relayed packet of %zu bytes exceeds the %zu byte "
				      "buffer",
				      body_len, cap);
				return TC_ERR_NOSPACE;
			}
			if (body_len != 0)
				memcpy(buf, body, body_len);
			*pkt_len = body_len;
			return TC_OK;
		}

		case TC_DERP_FRAME_PING:
			/* Echo the 8-byte payload back. We advertise CanAckPings=false,
			 * so this should not arrive, but answering is cheap and a relay
			 * that pings anyway would otherwise drop us. */
			rc = write_frame(&c->stream, TC_DERP_FRAME_PONG, frame, len);
			if (rc != TC_OK)
				return rc;
			break;

		case TC_DERP_FRAME_RESTARTING:
			/* The relay is going away and expects to be redialled. Acting on
			 * this rather than waiting for the socket to die turns a
			 * multi-second stall into an immediate reconnection -- the relay
			 * is telling us, before it happens, exactly what is about to go
			 * wrong. The body carries suggested timings that we ignore; our
			 * own backoff is no more eager than they ask for. */
			c->restarting = true;
			FAILF("the relay is restarting");
			return TC_ERR_CLOSED;

		case TC_DERP_FRAME_KEEP_ALIVE:
		case TC_DERP_FRAME_PEER_GONE:
		case TC_DERP_FRAME_PEER_PRESENT:
		case TC_DERP_FRAME_HEALTH:
		case TC_DERP_FRAME_SERVER_INFO:
			/* Informational. tailcat learns who its peer is from the meow
			 * exchange rather than from DERP's view of who is connected;
			 * what these are useful for here is liveness, which is recorded
			 * for every frame above. */
			break;

		default:
			/* An unknown frame type is not fatal: the protocol is versioned
			 * and servers may add types. Skipping is what upstream does. */
			break;
		}
	}
}

int tc_derp_set_read_timeout(tc_derp_client *c, int ms)
{
	if (c == NULL || !c->connected)
		return TC_ERR_INVAL;
	return tc_stream_set_read_timeout(&c->stream, ms);
}

int tc_derp_set_write_timeout(tc_derp_client *c, int ms)
{
	if (c == NULL || !c->connected)
		return TC_ERR_INVAL;
	int rc = tc_stream_set_write_timeout(&c->stream, ms);
	/* A transport with no way to bound a write is not an error: the harness
	 * streams in the tests are like that, and they never block. */
	return rc == TC_ERR_UNSUPPORTED ? TC_OK : rc;
}

uint64_t tc_derp_idle_ms(const tc_derp_client *c)
{
	if (c == NULL || !c->connected || c->last_recv_ms == 0)
		return 0;
	uint64_t now = derp_now_ms();
	return now > c->last_recv_ms ? now - c->last_recv_ms : 0;
}

bool tc_derp_is_restarting(const tc_derp_client *c)
{
	return c != NULL && c->restarting;
}

unsigned tc_derp_reconnect_count(const tc_derp_client *c)
{
	return c == NULL ? 0u : c->reconnects;
}

int tc_derp_reconnect(tc_derp_client *c)
{
	if (c == NULL || c->redial_host[0] == '\0')
		return TC_ERR_INVAL;

	/* The identity has to outlive the connection: DERP addresses peers by
	 * public key, so coming back under a new one would make us a different
	 * node and the peer would never find us again. */
	uint8_t priv[TC_DERP_KEY_LEN], pub[TC_DERP_KEY_LEN];
	memcpy(priv, c->our_private, sizeof priv);
	memcpy(pub, c->our_public, sizeof pub);

	char host[sizeof c->redial_host];
	char addr[sizeof c->redial_addr];
	memcpy(host, c->redial_host, sizeof host);
	memcpy(addr, c->redial_addr, sizeof addr);
	bool has_addr = c->has_redial_addr;
	unsigned n = c->reconnects;

	tc_derp_dial_opts opts;
	memset(&opts, 0, sizeof opts);
	opts.hostname = host;
	opts.dial_addr = has_addr ? addr : NULL;
	opts.port = c->redial_port;
	opts.insecure_skip_verify = c->redial_insecure;
	opts.timeout_ms = c->redial_timeout_ms;

	tc_derp_close(c);
	int rc = tc_derp_connect(c, &opts, priv, pub);
	tc_memzero_explicit(priv, sizeof priv);
	if (rc == TC_OK)
		c->reconnects = n + 1;
	return rc;
}

int tc_derp_fd(tc_derp_client *c)
{
	if (c == NULL || !c->connected)
		return -1;
	return tc_stream_fd(&c->stream);
}

bool tc_derp_has_pending(tc_derp_client *c)
{
	return c != NULL && c->connected && tc_stream_has_pending(&c->stream);
}

void tc_derp_close(tc_derp_client *c)
{
	if (c == NULL)
		return;
	if (c->stream.close != NULL)
		c->stream.close(&c->stream);
	tc_memzero_explicit(c->our_private, sizeof c->our_private);
	c->connected = false;
}
