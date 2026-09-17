/* SPDX-License-Identifier: BSD-3-Clause
 *
 * The SSH connection layer (RFC 4254): one session channel, flow control, and
 * only the requests a file-transfer server needs.
 *
 * ---- one channel, and only some requests --------------------------------
 *
 * A general sshd multiplexes many channels and answers requests for PTYs,
 * X11, agent forwarding, TCP forwarding and environment variables. Every one
 * of those is a way to reach something other than the thing being served, and
 * a drop box needs none of them. So a second SSH_MSG_CHANNEL_OPEN is refused
 * rather than queued, and every channel request except `subsystem` and `exec`
 * is answered with CHANNEL_FAILURE.
 *
 * Refusing is not the same as ignoring. A request with want_reply set must be
 * answered, or a client waits for a reply that never comes -- which looks
 * exactly like a hung server rather than a refused feature.
 *
 * ---- flow control is not optional ---------------------------------------
 *
 * Each side advertises a window and may not send more than that many bytes of
 * channel data before the other side extends it. A server that ignores the
 * window and sends anyway is not merely impolite: OpenSSH treats an overrun
 * as a protocol error and drops the connection. A server that never *extends*
 * the peer's window stalls silently after the first windowful, which is worse
 * because it works perfectly for small transfers and hangs on large ones.
 */
#ifndef TC_SSHCHAN_H_
#define TC_SSHCHAN_H_

#include "tc/sshkex.h"

#define TC_SSH_MSG_GLOBAL_REQUEST 80
#define TC_SSH_MSG_REQUEST_SUCCESS 81
#define TC_SSH_MSG_REQUEST_FAILURE 82
#define TC_SSH_MSG_CHANNEL_OPEN 90
#define TC_SSH_MSG_CHANNEL_OPEN_CONFIRMATION 91
#define TC_SSH_MSG_CHANNEL_OPEN_FAILURE 92
#define TC_SSH_MSG_CHANNEL_WINDOW_ADJUST 93
#define TC_SSH_MSG_CHANNEL_DATA 94
#define TC_SSH_MSG_CHANNEL_EXTENDED_DATA 95
#define TC_SSH_MSG_CHANNEL_EOF 96
#define TC_SSH_MSG_CHANNEL_CLOSE 97
#define TC_SSH_MSG_CHANNEL_REQUEST 98
#define TC_SSH_MSG_CHANNEL_SUCCESS 99
#define TC_SSH_MSG_CHANNEL_FAILURE 100

/* RFC 4254 section 5.1 open-failure reasons. */
#define TC_SSH_OPEN_ADMINISTRATIVELY_PROHIBITED 1
#define TC_SSH_OPEN_CONNECT_FAILED 2
#define TC_SSH_OPEN_UNKNOWN_CHANNEL_TYPE 3
#define TC_SSH_OPEN_RESOURCE_SHORTAGE 4

/* SSH_EXTENDED_DATA_STDERR, the only extended data type RFC 4254 defines. */
#define TC_SSH_EXTENDED_DATA_STDERR 1

/* Our window, and the largest packet we invite the peer to send. 64KB of
 * window keeps a bulk transfer moving without a round trip per segment; the
 * packet cap stays well inside TC_SSH_MAX_PAYLOAD with room for the framing
 * around it. */
#define TC_SSH_CHAN_WINDOW 65536u
#define TC_SSH_CHAN_MAX_PACKET 16384u

/* When our window has dropped by this much, extend it. Chosen so the peer is
 * never made to wait for a round trip mid-transfer, and so we are not sending
 * an adjustment per packet. */
#define TC_SSH_CHAN_WINDOW_LOW (TC_SSH_CHAN_WINDOW / 2)

#define TC_SSH_MAX_SUBSYSTEM 32

typedef struct {
	bool open;
	bool closed;
	uint32_t local_id;
	uint32_t remote_id;
	/* How much more the peer may send us, and how much more we may send. */
	uint32_t local_window;
	uint32_t remote_window;
	uint32_t remote_max_packet;
	bool eof_received;
	bool eof_sent;
	/* Set once the peer has asked for a subsystem or an exec and we have
	 * agreed. Data arriving before that is a client that did not wait. */
	bool started;
	char subsystem[TC_SSH_MAX_SUBSYSTEM];
} tc_ssh_channel;

void tc_ssh_channel_init(tc_ssh_channel *ch);

/* tc_ssh_channel_open_parse reads SSH_MSG_CHANNEL_OPEN.
 *
 * out_type receives the channel type; a caller that gets anything but
 * "session" must refuse with TC_SSH_OPEN_UNKNOWN_CHANNEL_TYPE rather than
 * treat it as a session. */
int tc_ssh_channel_open_parse(tc_ssh_channel *ch, char *out_type,
                              size_t type_cap, const uint8_t *payload,
                              size_t len);

int tc_ssh_channel_confirm_build(uint8_t *out, size_t cap, size_t *out_len,
                                 const tc_ssh_channel *ch);

int tc_ssh_channel_open_failure_build(uint8_t *out, size_t cap,
                                      size_t *out_len, uint32_t remote_id,
                                      uint32_t reason, const char *message);

/* What a CHANNEL_REQUEST asked for. */
typedef enum {
	TC_SSH_REQ_SUBSYSTEM,
	TC_SSH_REQ_EXEC,
	TC_SSH_REQ_OTHER /* pty-req, env, shell, signal, anything else */
} tc_ssh_request_type;

typedef struct {
	tc_ssh_request_type type;
	bool want_reply;
	/* The subsystem name, or the command for an exec. Truncation is refused
	 * rather than silently accepted: a subsystem called "sftp" and one called
	 * "sftp-and-more" must not become the same request. */
	char arg[256];
} tc_ssh_channel_request;

int tc_ssh_channel_request_parse(tc_ssh_channel_request *out,
                                 const tc_ssh_channel *ch,
                                 const uint8_t *payload, size_t len);

int tc_ssh_channel_reply_build(uint8_t *out, size_t cap, size_t *out_len,
                               uint32_t remote_id, bool success);

/* tc_ssh_channel_data_parse reads SSH_MSG_CHANNEL_DATA, returning a pointer
 * into the payload and charging the bytes against our window.
 *
 * Returns TC_ERR_TOOMANY if the peer sent more than its window allowed, which
 * is a protocol violation and must end the connection: a peer that ignores
 * flow control will overrun any buffer sized from the window. */
int tc_ssh_channel_data_parse(tc_ssh_channel *ch, const uint8_t **out_data,
                              size_t *out_len, const uint8_t *payload,
                              size_t len);

/* tc_ssh_channel_data_build frames outgoing data, charging it against the
 * peer's window.
 *
 * Returns TC_ERR_AGAIN when the window or the peer's maximum packet size does
 * not allow the whole chunk; the caller should send less or wait for an
 * adjustment. Refusing rather than silently truncating keeps "how much went"
 * a question the caller has to answer. */
int tc_ssh_channel_data_build(uint8_t *out, size_t cap, size_t *out_len,
                              tc_ssh_channel *ch, const void *data,
                              size_t data_len);

/* tc_ssh_channel_window_needed reports whether our window has fallen far
 * enough to be worth extending, and by how much. */
bool tc_ssh_channel_window_needed(const tc_ssh_channel *ch,
                                  uint32_t *out_increment);

int tc_ssh_channel_window_adjust_build(uint8_t *out, size_t cap,
                                       size_t *out_len, tc_ssh_channel *ch,
                                       uint32_t increment);

/* tc_ssh_channel_window_adjust_parse credits the peer's extension to our
 * send window, refusing an increment that would overflow it -- RFC 4254
 * caps the window at 2^32 - 1 and a peer that pushes past it is broken or
 * trying to wrap our arithmetic. */
int tc_ssh_channel_window_adjust_parse(tc_ssh_channel *ch,
                                       const uint8_t *payload, size_t len);

int tc_ssh_channel_eof_build(uint8_t *out, size_t cap, size_t *out_len,
                             tc_ssh_channel *ch);
int tc_ssh_channel_close_build(uint8_t *out, size_t cap, size_t *out_len,
                               tc_ssh_channel *ch);

/* tc_ssh_channel_exit_status_build sends the command's exit status, which is
 * what makes `ssh host cmd; echo $?` report the truth. It is a request that
 * never wants a reply. */
int tc_ssh_channel_exit_status_build(uint8_t *out, size_t cap, size_t *out_len,
                                     const tc_ssh_channel *ch,
                                     uint32_t status);

/* ---- the client half --------------------------------------------------- */

/* tc_ssh_channel_open_build asks for a session channel. */
int tc_ssh_channel_open_build(uint8_t *out, size_t cap, size_t *out_len,
                              const tc_ssh_channel *ch);

/* tc_ssh_channel_confirm_parse reads the server's acceptance, taking its
 * channel id, window and maximum packet size. */
int tc_ssh_channel_confirm_parse(tc_ssh_channel *ch, const uint8_t *payload,
                                 size_t len);

/* tc_ssh_channel_subsystem_build asks for a subsystem, always with
 * want_reply set: a client that did not ask for an answer could not tell a
 * server that started sftp from one that ignored the request. */
int tc_ssh_channel_subsystem_build(uint8_t *out, size_t cap, size_t *out_len,
                                   const tc_ssh_channel *ch,
                                   const char *name);

/* tc_ssh_channel_id_matches reports whether a message names our channel.
 * Every channel message carries a recipient id and a server with one channel
 * must still check it: acting on a message for a channel that does not exist
 * is how a confused client corrupts the one that does. */
bool tc_ssh_channel_id_matches(const tc_ssh_channel *ch,
                               const uint8_t *payload, size_t len);

#endif /* TC_SSHCHAN_H_ */
