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
 * There is no rekeying, and that bites in two places rather than one.
 *
 * The obvious one is the sequence number, which is the cipher nonce and so
 * must never wrap: tc_ssh_server_run stops at 2^32 packets rather than
 * letting it. For a file drop box that is unreachable in practice.
 *
 * The one that actually happens is a peer asking to rekey. OpenSSH starts a
 * key exchange on its own schedule, and RFC 4253 section 9 has the initiator
 * wait for a KEXINIT in reply -- so a server that ignores the request leaves
 * the client blocked until its own timeout, with nothing to say why. This
 * server answers with SSH_MSG_DISCONNECT instead, which is still a refusal
 * but a legible one. Implementing the exchange properly is the real fix.
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

#endif /* TC_SSHSERVER_H_ */
