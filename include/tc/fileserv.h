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
 * there. Upstream uses Go's `os.Root`, which refuses to traverse a symlink
 * or a `..` out of the tree at the system-call level. There is no such thing
 * in C, so this walks the path itself:
 *
 *   - The path is split into components. `.` is dropped, `..` pops -- and
 *     pops *before* anything touches the filesystem, so "a/../../etc" is
 *     rejected as a path rather than opened and then regretted.
 *   - Each component is opened with openat(O_NOFOLLOW) from the directory
 *     above it, so a symlink anywhere along the way fails rather than
 *     redirecting. That is the part a realpath() check cannot do: realpath
 *     resolves the link and then compares, which is both a different answer
 *     and a race.
 *   - An absolute path from the client is taken as relative to the root,
 *     because that is what every SFTP client means by "/" when it has been
 *     given a directory.
 *
 * The result is that a client cannot name anything outside the root, cannot
 * follow a link out of it, and cannot win a race by replacing a component
 * between the check and the open -- there is no separate check to race.
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
	int root_fd;
	bool writable;
	tc_fileserv_handle h[TC_FILESERV_MAX_HANDLES];
	uint64_t next_handle;
	char root[1024];
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

/* tc_fileserv_resolve opens what `path` names, beneath the root, without
 * following a symlink at any step.
 *
 * Exposed for its tests: the confinement is the security property of this
 * file and deserves to be checked directly rather than only through a
 * session. `want_dir` opens it as a directory. Returns a descriptor the
 * caller closes, or -1 with errno set. */
int tc_fileserv_resolve(tc_fileserv *fs, const char *path, bool want_dir,
                        int flags);

#endif /* TC_FILESERV_H_ */
