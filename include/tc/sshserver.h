/* SPDX-License-Identifier: BSD-3-Clause
 *
 * An SSH server: the transport state machine that drives sshkex, sshauth and
 * sshchan over a byte stream.
 *
 * The stream is a pair of callbacks rather than a socket, because the point
 * of this server is to be reached through the tunnel rather than over TCP.
 * The live test drives it over a socket so a real OpenSSH can connect to it;
 * `serve ssh` will drive the same code over a tc_tcp_conn.
 *
 * ---- what it will not do ------------------------------------------------
 *
 * One channel, publickey auth against a fixed list of keys, and only the
 * `subsystem` and `exec` requests. No PTY, no shell, no forwarding, no agent.
 * The refusals are answered rather than ignored, because a client waiting for
 * a reply it will never get cannot tell that from a hung server.
 *
 * Rekeying is implemented, but only as a responder: a peer may start a key
 * exchange at any point and we will complete it, and we never start one
 * ourselves. That covers the case that actually arises, because OpenSSH
 * rekeys on its own schedule and a server has no reason to insist on its
 * own. The session id stays fixed across a rekey, which is what binds the
 * new keys to the identity proven at the start.
 *
 * What remains bounded is the sequence number, which is the cipher nonce and
 * so must never wrap: tc_ssh_server_run stops at 2^32 packets rather than
 * letting it. A peer that rekeys on any sane schedule never gets near it; a
 * peer that refuses to rekey at all would, and stopping is the only safe
 * answer left at that point. Initiating would remove even that, at the cost
 * of buffering channel data between our KEXINIT and the peer's reply, which
 * RFC 4253 section 7.1 requires us to keep accepting.
 */
#ifndef TC_SSHSERVER_H_
#define TC_SSHSERVER_H_

#include "tc/sshauth.h"
#include "tc/sshchan.h"
#include "tc/sshkex.h"

typedef struct tc_ssh_server tc_ssh_server;

/* Read at least one byte, blocking. TC_ERR_CLOSED at end of stream. */
typedef int (*tc_ssh_read_fn)(void *ctx, uint8_t *buf, size_t cap,
                              size_t *nread);
/* Write all len bytes, blocking. */
typedef int (*tc_ssh_write_fn)(void *ctx, const uint8_t *buf, size_t len);

/* Called once the client has asked for a subsystem or an exec and been
 * authenticated. Returning TC_OK accepts the request; anything else refuses
 * it with CHANNEL_FAILURE.
 *
 * Inside the callback, tc_ssh_server_read and tc_ssh_server_write carry
 * channel data. Returning from it ends the session. */
typedef int (*tc_ssh_start_fn)(void *ctx, tc_ssh_server *s,
                               tc_ssh_request_type type, const char *arg);

typedef struct {
	/* The host identity. Its public half is what a client pins in
	 * known_hosts, so changing it makes every client complain -- which is
	 * the point of pinning and not a bug to work around. */
	const uint8_t *host_seed; /* 32 bytes */

	/* Keys allowed in, packed end to end at 32 bytes each. An empty list
	 * denies everyone; see tc/sshauth.h for why that is not the same
	 * convention --allow follows. */
	const uint8_t *authorized;
	size_t num_authorized;

	tc_ssh_read_fn read;
	tc_ssh_write_fn write;
	void *io_ctx;

	tc_ssh_start_fn on_start;
	void *app_ctx;
} tc_ssh_server_opts;

/* tc_ssh_server_run serves one connection to completion. */
int tc_ssh_server_run(const tc_ssh_server_opts *opts);

/* Channel data, for use inside the on_start callback. */
int tc_ssh_server_write(tc_ssh_server *s, const void *data, size_t len);

/* Returns TC_ERR_DONE once the peer has sent EOF and nothing is buffered. */
int tc_ssh_server_read(tc_ssh_server *s, void *buf, size_t cap,
                       size_t *nread);

/* tc_ssh_server_exit sends the command's exit status. Optional, and only
 * meaningful for an exec -- but `ssh host cmd; echo $?` reports 255 without
 * it, which looks like a failure that did not happen. */
int tc_ssh_server_exit(tc_ssh_server *s, uint32_t status);

/* tc_ssh_server_session_id exposes the session identifier, which is the
 * exchange hash of the first key exchange. Callers that bind anything to this
 * session -- an audit record, a per-session key -- should use it rather than
 * inventing one. */
const uint8_t *tc_ssh_server_session_id(const tc_ssh_server *s);

/* tc_ssh_server_rekeys is how many key exchanges have happened after the
 * first. It exists so a test can assert that a rekey really occurred: a
 * transfer that succeeds proves nothing about rekeying if the client never
 * asked for one. */
unsigned tc_ssh_server_rekeys(const tc_ssh_server *s);

#endif /* TC_SSHSERVER_H_ */
