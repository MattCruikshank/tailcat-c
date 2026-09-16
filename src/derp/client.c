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

	static _Thread_local uint8_t frame[TC_DERP_KEY_LEN +
	                                   TC_DERP_MAX_PACKET_SIZE];

	for (;;) {
		uint8_t type = 0;
		size_t len = 0;
		int rc = read_frame(&c->stream, &type, frame, sizeof frame, &len);
		if (rc != TC_OK)
			return rc;

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

		case TC_DERP_FRAME_KEEP_ALIVE:
		case TC_DERP_FRAME_PEER_GONE:
		case TC_DERP_FRAME_PEER_PRESENT:
		case TC_DERP_FRAME_HEALTH:
		case TC_DERP_FRAME_RESTARTING:
		case TC_DERP_FRAME_SERVER_INFO:
			/* Informational. tailcat learns liveness from the WireGuard layer
			 * rather than from DERP's view of who is connected. */
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

void tc_derp_close(tc_derp_client *c)
{
	if (c == NULL)
		return;
	if (c->stream.close != NULL)
		c->stream.close(&c->stream);
	tc_memzero_explicit(c->our_private, sizeof c->our_private);
	c->connected = false;
}
