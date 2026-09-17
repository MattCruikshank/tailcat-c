/* SPDX-License-Identifier: BSD-3-Clause
 *
 * An SSH client: the other half of tc/sshserver.h, for `ls`.
 *
 * Upstream's `ls` links an SSH client and an SFTP client and drives them
 * in-process rather than shelling out to the system `sftp`, which is the one
 * file command it does not exec. This matches that, for the reason given in
 * PLAN.md 5.5: execing would tie our output to whatever the local `sftp`
 * prints and would need an `sftp` binary present, which on Windows is not a
 * given.
 *
 * ---- the host key is not checked, and the signature is ------------------
 *
 * There is no known_hosts here and no callback to supply one, deliberately.
 * Upstream says why, and reached it independently: "The WireGuard tunnel
 * already authenticated the server by its node key in the tailcat address, so
 * the SSH host key adds nothing." A prompt about a key nobody holds would be
 * a prompt nobody can answer.
 *
 * What is *not* skipped is verifying the server's signature over the exchange
 * hash with the key it presented. That is what proves the party we did the
 * key exchange with holds the key it claimed, and it is what stops an
 * attacker splicing two halves of two exchanges together. Go's
 * InsecureIgnoreHostKey does the same: it drops the known-hosts comparison,
 * not the signature check. Confusing the two would turn "we trust the tunnel"
 * into "we verify nothing".
 */
#ifndef TC_SSHCLIENT_H_
#define TC_SSHCLIENT_H_

#include "tc/sshauth.h"
#include "tc/sshchan.h"
#include "tc/sshkex.h"
#include "tc/sshserver.h" /* for tc_ssh_read_fn / tc_ssh_write_fn */

typedef struct tc_ssh_client tc_ssh_client;

/* Called once the subsystem has started. Channel data flows through
 * tc_ssh_client_read and tc_ssh_client_write until it returns. */
typedef int (*tc_ssh_client_ready_fn)(void *ctx, tc_ssh_client *c);

typedef struct {
	/* The user name to authenticate as. Servers that accept the `none`
	 * method ignore it; ours is sent for the ones that do not. */
	const char *user;

	/* An Ed25519 seed for publickey authentication, or NULL to offer only
	 * `none`.
	 *
	 * Upstream's `ls` passes no authentication methods at all, which makes
	 * Go offer `none` and nothing else -- so `none` is what a tailcat file
	 * server accepts. We try it first for exactly that reason, and fall back
	 * to publickey rather than failing, so a server with a stricter policy
	 * is still reachable. */
	const uint8_t *user_seed;

	const char *subsystem; /* "sftp" */

	tc_ssh_read_fn read;
	tc_ssh_write_fn write;
	void *io_ctx;

	tc_ssh_client_ready_fn on_ready;
	void *app_ctx;
} tc_ssh_client_opts;

/* tc_ssh_client_run connects, authenticates, starts the subsystem and calls
 * on_ready. Returns when the session is over. */
int tc_ssh_client_run(const tc_ssh_client_opts *opts);

int tc_ssh_client_write(tc_ssh_client *c, const void *data, size_t len);

/* Returns TC_ERR_DONE once the server has sent EOF and nothing is buffered. */
int tc_ssh_client_read(tc_ssh_client *c, void *buf, size_t cap, size_t *nread);

/* tc_ssh_client_eof says we have finished sending.
 *
 * A request-response protocol like SFTP never needs it, but anything that
 * streams does: a server reading until end of input waits for this, and a
 * client that reads for a reply without sending it first is a deadlock where
 * each side is waiting for the other to speak. */
int tc_ssh_client_eof(tc_ssh_client *c);

/* tc_ssh_client_host_key exposes the key the server presented and proved it
 * holds. Nothing here compares it to anything; a caller that wants to pin it
 * has it. */
const uint8_t *tc_ssh_client_host_key(const tc_ssh_client *c);

#endif /* TC_SSHCLIENT_H_ */
