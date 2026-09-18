/* SPDX-License-Identifier: BSD-3-Clause
 *
 * A directory served over SFTP: the policy half of `serve files`.
 *
 * The drop box next door is the write-only case, where the server chooses
 * every filename and that one rule does most of the work. This is the other
 * one: the client names paths, reads them, lists directories, and with
 * `:rw` writes them too. Naming is exactly what the drop box refuses to
 * allow, so nothing from there transfers and the confinement has to be done
 * properly instead.
 *
 * ---- confinement --------------------------------------------------------
 *
 * Everything the client names is resolved beneath one root and must stay
 * there. That is tc/rootdir.h's job, and it is shared with the recursive drop
 * box, which needs exactly the same guarantee for the paths it creates.
 *
 * ---- read-only means read-only -----------------------------------------
 *
 * The default refuses every write: OPEN for writing, WRITE, SETSTAT,
 * MKDIR, RMDIR, REMOVE, RENAME and SYMLINK. `--files=<dir>:rw` allows them.
 * Read-only is the default because `serve files` with no qualifier is the
 * form someone types when they want to hand out a directory, and handing out
 * write access by accident is not recoverable.
 *
 * Attributes a client asks to set are still refused even in rw mode when
 * they would make a file executable or setuid: the server owns the
 * permissions of files in its own tree, exactly as the drop box does.
 */
#ifndef TC_FILESERV_H_
#define TC_FILESERV_H_

#include "tc/rootdir.h"
#include "tc/sftp.h"
#include "tc/sshserver.h"

#define TC_FILESERV_MAX_HANDLES 16

/* The most one READ may return. OpenSSH's sftp asks for 32KB by default;
 * anything larger would have to be split to stay inside one SFTP packet, and
 * the number comes from the client, so it is bounded here. */
#define TC_FILESERV_MAX_READ 32768

typedef struct {
	bool used;
	bool is_dir;
	int fd;    /* open file, or the directory for a listing */
	void *dir; /* DIR * when is_dir, read through fdopendir */
	bool sent_eof;
	uint8_t id[TC_SFTP_HANDLE_LEN];
} tc_fileserv_handle;

typedef struct {
	tc_rootdir root;
	bool writable;
	tc_fileserv_handle h[TC_FILESERV_MAX_HANDLES];
	uint64_t next_handle;
} tc_fileserv;

/* tc_fileserv_open holds the served directory open for the session.
 *
 * The descriptor is the anchor every path is resolved from, so the tree
 * cannot be swapped underneath a running session by renaming a directory
 * above it. */
int tc_fileserv_open(tc_fileserv *fs, const char *dir, bool writable);

/* tc_fileserv_handle_req answers one request. Refusals are statuses, not
 * failures: see tc/sftpserve.h. */
int tc_fileserv_handle_req(tc_fileserv *fs, const tc_sftp_request *req,
                           uint8_t *out, size_t cap, size_t *out_len);

void tc_fileserv_close(tc_fileserv *fs);

/* tc_fileserv_serve runs a whole session and closes the server afterwards. */
int tc_fileserv_serve(tc_fileserv *fs, tc_ssh_server *s);

/* tc_fileserv_resolve resolves one client path against this server's root.
 *
 * A thin wrapper on tc_rootdir_resolve, kept because the tests for the fence
 * were written against it and are worth running unchanged: they are what says
 * the move into tc/rootdir.h did not alter the behaviour. */
int tc_fileserv_resolve(tc_fileserv *fs, const char *path, bool want_dir,
                        int flags);

#endif /* TC_FILESERV_H_ */
