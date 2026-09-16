/* SPDX-License-Identifier: BSD-3-Clause
 *
 * DERP frame encoding and the handshake frames. See derp.h for the wire
 * format.
 *
 * Everything here is pure: it takes and returns buffers and never touches a
 * socket, so it can be unit-tested and fuzzed directly. The I/O lives in
 * src/derp/client.c.
 */

#include "tc/derp.h"

#include "tc/crypto.h"

#include <stdio.h>
#include <string.h>

const char *tc_derp_frame_name(unsigned type)
{
	switch (type) {
	case TC_DERP_FRAME_SERVER_KEY:     return "server-key";
	case TC_DERP_FRAME_CLIENT_INFO:    return "client-info";
	case TC_DERP_FRAME_SERVER_INFO:    return "server-info";
	case TC_DERP_FRAME_SEND_PACKET:    return "send-packet";
	case TC_DERP_FRAME_RECV_PACKET:    return "recv-packet";
	case TC_DERP_FRAME_KEEP_ALIVE:     return "keep-alive";
	case TC_DERP_FRAME_NOTE_PREFERRED: return "note-preferred";
	case TC_DERP_FRAME_PEER_GONE:      return "peer-gone";
	case TC_DERP_FRAME_PEER_PRESENT:   return "peer-present";
	case TC_DERP_FRAME_FORWARD_PACKET: return "forward-packet";
	case TC_DERP_FRAME_WATCH_CONNS:    return "watch-conns";
	case TC_DERP_FRAME_CLOSE_PEER:     return "close-peer";
	case TC_DERP_FRAME_PING:           return "ping";
	case TC_DERP_FRAME_PONG:           return "pong";
	case TC_DERP_FRAME_HEALTH:         return "health";
	case TC_DERP_FRAME_RESTARTING:     return "restarting";
	default:                           return "unknown";
	}
}

void tc_derp_frame_header_encode(uint8_t out[TC_DERP_FRAME_HEADER_LEN],
                                 uint8_t type, uint32_t payload_len)
{
	out[0] = type;
	out[1] = (uint8_t)(payload_len >> 24);
	out[2] = (uint8_t)(payload_len >> 16);
	out[3] = (uint8_t)(payload_len >> 8);
	out[4] = (uint8_t)payload_len;
}

int tc_derp_frame_header_decode(const uint8_t in[TC_DERP_FRAME_HEADER_LEN],
                                uint8_t *type, uint32_t *payload_len)
{
	if (in == NULL || type == NULL || payload_len == NULL)
		return TC_ERR_INVAL;

	uint32_t n = (uint32_t)in[1] << 24 | (uint32_t)in[2] << 16 |
	             (uint32_t)in[3] << 8 | (uint32_t)in[4];

	/* The length comes straight off the wire and decides how much we are
	 * about to read and buffer, so bound it before anyone acts on it. */
	if (n > TC_DERP_MAX_FRAME_LEN)
		return TC_ERR_TOOMANY;

	*type = in[0];
	*payload_len = n;
	return TC_OK;
}

int tc_derp_parse_server_key(uint8_t server_key[TC_DERP_KEY_LEN],
                             const uint8_t *payload, size_t len)
{
	if (server_key == NULL || payload == NULL)
		return TC_ERR_INVAL;
	if (len < TC_DERP_MAGIC_LEN + TC_DERP_KEY_LEN)
		return TC_ERR_TRUNC;
	if (memcmp(payload, TC_DERP_MAGIC, TC_DERP_MAGIC_LEN) != 0)
		return TC_ERR_INVAL;

	/* Upstream deliberately tolerates a longer greeting so the server can add
	 * fields later, so trailing bytes are ignored rather than rejected. */
	memcpy(server_key, payload + TC_DERP_MAGIC_LEN, TC_DERP_KEY_LEN);
	return TC_OK;
}

int tc_derp_build_client_info(uint8_t *out, size_t cap, size_t *out_len,
                              const uint8_t our_public[TC_DERP_KEY_LEN],
                              const uint8_t our_private[TC_DERP_KEY_LEN],
                              const uint8_t server_key[TC_DERP_KEY_LEN])
{
	if (out == NULL || our_public == NULL || our_private == NULL ||
	    server_key == NULL)
		return TC_ERR_INVAL;

	/* The client-info document. tailcat is a plain client: no mesh key, not a
	 * prober, and it does not advertise an app name. CanAckPings is false
	 * because we never answer DERP-level pings on this connection.
	 *
	 * Written literally rather than through a JSON encoder: it has no
	 * variable parts, so a serialiser would be more code and more risk.
	 *
	 * CanAckPings carries no `omitempty` in upstream's struct, so Go always
	 * emits it; we match that. Declaring false means the server sends
	 * FRAME_KEEP_ALIVE rather than FRAME_PING, though the client answers a
	 * ping anyway if one arrives. */
	static const char kInfo[] = "{\"version\":2,\"CanAckPings\":false}";
	const size_t info_len = sizeof kInfo - 1;

	const size_t need = TC_DERP_KEY_LEN + TC_DERP_NONCE_LEN + TC_BOX_TAG_LEN +
	                    info_len;
	if (cap < need)
		return TC_ERR_NOSPACE;

	memcpy(out, our_public, TC_DERP_KEY_LEN);

	uint8_t *nonce = out + TC_DERP_KEY_LEN;
	int rc = tc_random_bytes(nonce, TC_DERP_NONCE_LEN);
	if (rc != TC_OK)
		return rc;

	rc = tc_box_seal(out + TC_DERP_KEY_LEN + TC_DERP_NONCE_LEN, nonce, kInfo,
	                 info_len, server_key, our_private);
	if (rc != TC_OK)
		return rc;

	if (out_len != NULL)
		*out_len = need;
	return TC_OK;
}

int tc_derp_open_server_info(uint8_t *out, size_t cap, size_t *out_len,
                             const uint8_t *payload, size_t len,
                             const uint8_t our_private[TC_DERP_KEY_LEN],
                             const uint8_t server_key[TC_DERP_KEY_LEN])
{
	if (payload == NULL || our_private == NULL || server_key == NULL)
		return TC_ERR_INVAL;
	if (len < TC_DERP_NONCE_LEN + TC_BOX_TAG_LEN)
		return TC_ERR_TRUNC;
	if (len > TC_DERP_NONCE_LEN + TC_DERP_MAX_INFO_LEN)
		return TC_ERR_TOOMANY;

	const uint8_t *nonce = payload;
	const uint8_t *box = payload + TC_DERP_NONCE_LEN;
	size_t box_len = len - TC_DERP_NONCE_LEN;
	size_t pt_len = box_len - TC_BOX_TAG_LEN;

	if (cap < pt_len)
		return TC_ERR_NOSPACE;

	int rc = tc_box_open(out, nonce, box, box_len, server_key, our_private);
	if (rc != TC_OK)
		return rc;

	if (out_len != NULL)
		*out_len = pt_len;
	return TC_OK;
}

int tc_derp_build_send_packet(uint8_t *out, size_t cap, size_t *out_len,
                              const uint8_t dst_key[TC_DERP_KEY_LEN],
                              const void *pkt, size_t pkt_len)
{
	if (out == NULL || dst_key == NULL)
		return TC_ERR_INVAL;
	if (pkt == NULL && pkt_len != 0)
		return TC_ERR_INVAL;
	if (pkt_len > TC_DERP_MAX_PACKET_SIZE)
		return TC_ERR_TOOMANY;
	if (cap < TC_DERP_KEY_LEN + pkt_len)
		return TC_ERR_NOSPACE;

	memcpy(out, dst_key, TC_DERP_KEY_LEN);
	if (pkt_len != 0)
		memcpy(out + TC_DERP_KEY_LEN, pkt, pkt_len);

	if (out_len != NULL)
		*out_len = TC_DERP_KEY_LEN + pkt_len;
	return TC_OK;
}

int tc_derp_parse_recv_packet(uint8_t src_key[TC_DERP_KEY_LEN],
                              const uint8_t **pkt, size_t *pkt_len,
                              const uint8_t *payload, size_t len)
{
	if (src_key == NULL || pkt == NULL || pkt_len == NULL || payload == NULL)
		return TC_ERR_INVAL;

	/* Protocol version 2 prefixes the source key. A shorter frame is either a
	 * version-1 server or corruption; either way we cannot attribute the
	 * packet to a peer, so refuse it. */
	if (len < TC_DERP_KEY_LEN)
		return TC_ERR_TRUNC;

	size_t n = len - TC_DERP_KEY_LEN;
	if (n > TC_DERP_MAX_PACKET_SIZE)
		return TC_ERR_TOOMANY;

	memcpy(src_key, payload, TC_DERP_KEY_LEN);
	*pkt = payload + TC_DERP_KEY_LEN;
	*pkt_len = n;
	return TC_OK;
}
