/* SPDX-License-Identifier: BSD-3-Clause
 *
 * A shell at the far end of the tunnel: the `serve ssh` half.
 *
 * The drop box and the file server answer questions. This one hands over a
 * process, which is a different kind of thing entirely, and the whole file is
 * shaped by that: what it runs, how the two byte streams are kept moving at
 * once, and what it refuses to do.
 *
 * ---- a pty, or not ------------------------------------------------------
 *
 * A client that sent `pty-req` gets a pseudo-terminal, which is what makes
 * job control, line editing and full-screen programs work. One that did not
 * -- `ssh -T`, or `ssh host command` -- gets a pipe, and so does every client
 * on Windows, where Cosmopolitan's forkpty returns ENOSYS. That is not a
 * degradation we invented: OpenSSH prints "PTY allocation request failed on
 * channel 0" and carries on in exactly the same way, and a pipe is the right
 * shape for a command whose output is being redirected anyway.
 *
 * The platform difference is reported rather than hidden. A session that
 * silently loses its terminal is one where the user's editor misbehaves for
 * reasons nothing explains.
 *
 * ---- both directions at once --------------------------------------------
 *
 * A shell writes when it feels like it, so the server cannot wait for a
 * packet before sending. The pump registered with tc_ssh_server_set_idle
 * moves shell output out while the reader waits for input; see the section
 * in tc/sshserver.h for why that is safe and what it may not do. Output that
 * will not fit in the peer's window stays buffered and goes next turn, which
 * is the same thing a full pipe means.
 *
 * ---- what it does not do ------------------------------------------------
 *
 * No `env` requests: a client may not set environment variables on the
 * serving machine, because LD_PRELOAD is an environment variable. No agent
 * or port forwarding. No signals. TERM comes from the pty request and is the
 * one thing the client gets to choose, because a terminal name is a lookup
 * key in terminfo and not a command.
 *
 * The child's environment is the server's, plus TERM, plus the two variables
 * `serve exec` also sets -- TAILCAT_PEER_KEY and TAILCAT_REMOTE_ADDR -- so a
 * forced command can tell who it is talking to.
 */
#ifndef TC_SHELLSRV_H_
#define TC_SHELLSRV_H_

#include "tc/sshserver.h"

typedef struct {
	/* The command to run, or NULL for the user's login shell.
	 *
	 * A non-NULL command is run as `sh -c <command>`, which is what an SSH
	 * `exec` request means everywhere and what scp and rsync depend on. It
	 * is not split into arguments here: doing that would be a second, worse
	 * shell, and the difference between the two would be the interesting
	 * part of somebody's day. */
	const char *command;

	/* Written into the child's environment so a forced command can tell who
	 * it is talking to. Both may be NULL. */
	const uint8_t *peer_key; /* 32 bytes */
	const char *peer_addr;

	/* Refuse to run anything the client named, and run `command` instead.
	 * This is the `serve ssh -- cmd` form: whatever the client asks for, it
	 * gets this. */
	bool forced;

	/* What the client asked to run, when `forced` overrode it.
	 *
	 * Passed to the child as SSH_ORIGINAL_COMMAND, which is OpenSSH's name
	 * for it and upstream's too. A forced command that wants to dispatch on
	 * what was asked -- `git-upload-pack` deciding which repository, the
	 * usual reason anyone writes one -- has nowhere else to read it. NULL
	 * when the client asked for nothing, and the variable is then unset
	 * rather than empty, because a script testing -n on it should see the
	 * difference. */
	const char *original_command;
} tc_shell_opts;

/* tc_shell_serve runs one session to completion and reaps the child.
 *
 * Returns TC_OK when the child exited and its status reached the client,
 * which is the ordinary end of a session -- including one where the command
 * failed. A non-TC_OK return means the session broke, not that the command
 * did. */
int tc_shell_serve(tc_ssh_server *s, const tc_shell_opts *opts);

/* tc_shell_have_pty reports whether this build on this machine can allocate
 * one. Exposed so the caller can say so at startup rather than leaving the
 * first user to discover it. */
bool tc_shell_have_pty(void);

/* tc_shell_login_shell returns the shell a session would start: $SHELL, or
 * a sensible default for the platform. Exposed for the startup banner and
 * for tests. Never NULL. */
const char *tc_shell_login_shell(void);

#endif /* TC_SHELLSRV_H_ */
