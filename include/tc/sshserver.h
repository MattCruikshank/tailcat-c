/* SPDX-License-Identifier: BSD-3-Clause
 *
 * An SSH server: the transport state machine that drives sshkex, sshauth and
 * sshchan over a byte stream.
 *
 * The stream is a pair of callbacks rather than a socket, because the point
 * of this server is to be reached through the tunnel rather than over TCP.
 * The live test drives it over a socket so a real OpenSSH can connect to it;
 * `serve ssh` drives the same code over a tc_tcp_conn.
 *
 * ---- what it will not do ------------------------------------------------
 *
 * One channel, publickey auth against a fixed list of keys, and only the
 * `subsystem`, `exec`, `shell` and `pty-req` requests. No forwarding, no
 * agent, no x11, no env. The refusals are answered rather than ignored,
 * because a client waiting for a reply it will never get cannot tell that
 * from a hung server.
 *
 * A shell and a pty are served only when the caller sets allow_shell and
 * allow_pty. They default off, so `recv` and the drop box refuse them exactly
 * as they always have -- the one thing a drop box must never become is a
 * shell on the serving machine, and that must not depend on a policy
 * callback remembering to say no.
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

/* Decides whether a channel request will be served. Must answer immediately
 * and must not read or write the channel.
 *
 * It is separate from tc_ssh_start_fn because the answer has to go out
 * *before* the work begins. RFC 4254 4 has the requester wait for
 * CHANNEL_SUCCESS before using the channel, so a server that runs the
 * application first and replies afterwards deadlocks against any client that
 * waits -- which OpenSSH does not, because it sends optimistically, and Go's
 * client and ours both do. Getting this wrong is invisible until something
 * other than OpenSSH connects. See bug 26.
 *
 * NULL accepts every subsystem and exec. */
typedef bool (*tc_ssh_accept_fn)(void *ctx, tc_ssh_request_type type,
                                 const char *arg);

/* Called once the request has been accepted *and answered*. Inside it,
 * tc_ssh_server_read and tc_ssh_server_write carry channel data; returning
 * ends the session.
 *
 * Its return value cannot refuse the request -- that decision was made and
 * sent by tc_ssh_accept_fn -- so an error here ends a session that was
 * already agreed to, which is the only thing left to do. */
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

	/* Let anyone in who reached this far, because something below this
	 * layer has already decided who may connect. The `none` method
	 * succeeds, and so does any key.
	 *
	 * This exists for `recv`, where it is not a weakening but a statement of
	 * where the authentication is. Reaching the SSH server at all means
	 * completing a WireGuard handshake keyed to an address the sender had to
	 * be given, and `--allow` can narrow that to named node keys. Demanding
	 * an SSH key on top would mean every sender registering one in advance,
	 * which is not something `scp` can do and not what upstream asks for.
	 *
	 * It is a separate flag rather than "an empty list means anyone" because
	 * an empty list is what a misconfiguration looks like, and the two must
	 * not be spelled the same way. Setting this is a decision; forgetting to
	 * fill the list is an accident. */
	bool any_key_authenticates;

	/* Whether a `shell` request may be served, and whether a `pty-req`
	 * before it is answered with success.
	 *
	 * Two flags rather than one because they fail differently. Without
	 * allow_shell there is no interactive session at all. Without allow_pty
	 * there is one, but on pipes: OpenSSH prints "PTY allocation request
	 * failed on channel 0" and carries on, which is exactly `ssh -T` and is
	 * the right answer on a platform with no ptys to hand out. */
	bool allow_shell;
	bool allow_pty;

	/* Wait for the peer's CHANNEL_CLOSE before returning.
	 *
	 * Set this when the transport is a kernel socket the caller will
	 * close(): closing one that still has unread bytes on it makes the
	 * kernel send RST rather than FIN, and an RST discards whatever output
	 * has not left the send buffer. A client sends CHANNEL_WINDOW_ADJUST
	 * continuously while it reads, so at the end of a large transfer there
	 * is almost always something unread. That was bug 39, and it had been
	 * silently shortening large transfers.
	 *
	 * Do *not* set it when the transport closes cleanly by itself, as the
	 * userspace TCP here does. The read callbacks on that path have no
	 * deadline, a peer can vanish without ever sending CHANNEL_CLOSE -- an
	 * ssh whose ProxyCommand is killed underneath it does exactly that --
	 * and the wait then never ends. That was bug 41, which is this comment's
	 * reason for existing. */
	bool wait_for_close;

	tc_ssh_read_fn read;
	tc_ssh_write_fn write;
	void *io_ctx;

	tc_ssh_accept_fn on_accept;
	tc_ssh_start_fn on_start;
	void *app_ctx;
} tc_ssh_server_opts;

/* tc_ssh_server_run serves one connection to completion. */
int tc_ssh_server_run(const tc_ssh_server_opts *opts);

/* ---- sessions that talk in both directions at once ----------------------
 *
 * Everything else here is request and response: a client asks, the handler
 * answers, and nothing needs to be sent while nothing has been asked. An
 * interactive shell is not like that. The shell produces output whether or
 * not the user is typing, and a server that only wrote when a packet arrived
 * would deliver a command's output on the user's *next* keystroke.
 *
 * So a session that needs it registers a pump, from inside on_start, and the
 * application's read callback calls tc_ssh_server_idle while it waits for
 * bytes. The read callbacks here already loop -- they have to, because the
 * bytes come through a tunnel that needs driving -- so this costs one call
 * per turn of a loop that was going round anyway.
 *
 * ---- what a pump may do -------------------------------------------------
 *
 * It runs *inside* the read callback, which is inside the packet reader. It
 * may call tc_ssh_server_write, and that is deliberately safe: while a pump
 * is running, a write that would have to wait for the peer's window returns
 * TC_ERR_AGAIN instead of reading a packet to get one. Reading a packet
 * there would re-enter the reader that is already part way through a packet,
 * and the pump is expected to hold on to what it could not send and try
 * again next turn -- which is exactly what a full pipe means anyway.
 *
 * A pump must not call tc_ssh_server_read. There is no useful way to make
 * that safe, and nothing needs it. */
typedef int (*tc_ssh_idle_fn)(void *ctx, tc_ssh_server *s);

/* Register the pump. Called from on_start; NULL removes it. */
void tc_ssh_server_set_idle(tc_ssh_server *s, tc_ssh_idle_fn fn, void *ctx);

/* tc_ssh_server_idle runs the registered pump once, or does nothing if there
 * is none. Anything but TC_OK should end the session. */
int tc_ssh_server_idle(tc_ssh_server *s);

/* tc_ssh_server_pty reports the terminal the client asked for, or NULL if it
 * asked for none.
 *
 * The struct is updated in place by any window-change that arrives while the
 * session runs, and tc_ssh_server_pty_generation counts those changes. A
 * shell pump reads the generation, and when it moves, resizes its pty: that
 * is a poll rather than a callback because the change is noticed inside
 * tc_ssh_server_read, and calling back into the application from there would
 * be re-entering it while it is blocked on a read. */
const tc_ssh_pty *tc_ssh_server_pty(const tc_ssh_server *s);
uint64_t tc_ssh_server_pty_generation(const tc_ssh_server *s);

/* Channel data, for use inside the on_start callback. */
int tc_ssh_server_write(tc_ssh_server *s, const void *data, size_t len);

/* tc_ssh_server_write_some sends what the peer's window allows and reports
 * how much that was, without ever waiting.
 *
 * This is the form a pump needs. tc_ssh_server_write can return TC_ERR_AGAIN
 * having already sent part of the buffer, and a caller that requeued the
 * whole thing would send those bytes a second time -- which on a shell
 * session means duplicated output, at an offset that depends on the peer's
 * window. *nwrote of 0 with TC_OK means the window is shut; try later. */
int tc_ssh_server_write_some(tc_ssh_server *s, const void *data, size_t len,
                             size_t *nwrote);

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
