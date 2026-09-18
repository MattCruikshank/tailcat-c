/* SPDX-License-Identifier: BSD-3-Clause
 *
 * A directory a client cannot get out of -- and, in one deliberate case,
 * one it can.
 *
 * Two services here let a client name paths -- `serve files`, where it reads
 * them, and the recursive drop box, where it creates them -- and both need
 * the same guarantee: **whatever the client names resolves inside one
 * directory, or not at all.** This file is that guarantee, in one place,
 * because a fence with two implementations is a fence with two chances to be
 * subtly different.
 *
 * ---- how ----------------------------------------------------------------
 *
 * Upstream uses Go's `os.Root`, which refuses to traverse a symlink or a `..`
 * out of the tree at the system-call level. There is no such thing in C, so
 * the walk is done here:
 *
 *   - The path is split into components. `.` is dropped, `..` pops -- and
 *     pops *before* anything touches the filesystem, so "a/../../etc" is
 *     rejected as a path rather than opened and then regretted.
 *   - Each component is opened with openat(O_NOFOLLOW) from the directory
 *     above it, so a symlink anywhere along the way fails rather than
 *     redirecting. That is the part a realpath() check cannot do: realpath
 *     resolves the link and then compares, which is both a different answer
 *     and a race against whoever can swap a component in between. Here there
 *     is no separate check to race.
 *   - An absolute path from the client is taken as relative to the root,
 *     because that is what every SFTP client means by "/" when it has been
 *     given a directory.
 *
 * A symlink is *refused*, not resolved, even when it points back inside the
 * root. Refusing only the ones that escape would mean resolving them first
 * and judging afterwards, which is the race again.
 *
 * ---- what it is not -----------------------------------------------------
 *
 * It is not a permission system. It says where a path may land, not what may
 * be done there: read-only, write-only and read-write are the callers'
 * policies, in tc/fileserv.h and tc/dropbox.h. Keeping the two apart is the
 * same reason tc/sftp.h has no opinions -- a change to path handling must not
 * quietly become a change to permissions.
 *
 * ---- the case with no fence ---------------------------------------------
 *
 * tc_rootdir_open_unconfined resolves paths the ordinary way instead. It
 * exists for one caller: the SFTP subsystem of a server that already grants a
 * shell, where confining file transfer would protect nothing -- the client can
 * run `cat` -- while breaking most real paths, since a filesystem is full of
 * symlinks. Upstream makes the same choice for the same case.
 *
 * It is a field on this struct rather than a separate type so that the two
 * cannot silently swap places: every caller says which it wants by choosing a
 * constructor, and the confined one is the one with the short name.
 */
#ifndef TC_ROOTDIR_H_
#define TC_ROOTDIR_H_

#include "tc/tc.h"

#include <stdbool.h>
#include <stddef.h>

/* The longest path component we will consider, and the most components in one
 * path. Both are bounds on attacker-supplied input rather than limits anyone
 * should notice. */
#define TC_ROOTDIR_MAX_NAME 256
#define TC_ROOTDIR_MAX_DEPTH 64

/* Room for the directory half of a path while it is split off. */
#define TC_SFTP_DIRBUF 1024

typedef struct {
	/* The anchor every path is resolved from. Holding it open is what stops
	 * the tree being swapped underneath a running session by renaming a
	 * directory above it. */
	int fd;
	char path[1024];

	/* Resolve paths normally instead: follow symlinks, and let a path leave
	 * the directory.
	 *
	 * This is not a hole in the fence; it is for the case with no fence. A
	 * shell server serves SFTP with the same reach the shell already has --
	 * upstream does the same, and confining the file transfer while handing
	 * out arbitrary command execution would protect nothing while breaking
	 * every path through a symlink, which on a real filesystem is most of
	 * them.
	 *
	 * It is a separate field rather than "root is /" precisely so the two
	 * cannot be confused: a *confined* server rooted at / would still refuse
	 * symlinks, and that is a different and legitimate thing to want. */
	bool unconfined;
} tc_rootdir;

/* tc_rootdir_open holds `dir` open for the session, confining every path to
 * it. */
int tc_rootdir_open(tc_rootdir *r, const char *dir);

/* tc_rootdir_open_unconfined resolves paths against `dir` without confining
 * them: an absolute path is absolute, `..` climbs, and symlinks are followed.
 *
 * Only for a session that already has a shell. See the `unconfined` field. */
int tc_rootdir_open_unconfined(tc_rootdir *r, const char *dir);
void tc_rootdir_close(tc_rootdir *r);

/* tc_rootdir_resolve opens what `path` names, beneath the root, without
 * following a symlink at any step.
 *
 * `want_dir` opens it as a directory whatever `flags` say. Returns a
 * descriptor the caller closes, or -1 with errno set. */
int tc_rootdir_resolve(const tc_rootdir *r, const char *path, bool want_dir,
                       int flags);

/* tc_rootdir_parent opens the *directory containing* what `path` names, and
 * copies out the final component.
 *
 * This is the form for creating something: a caller that resolved the whole
 * path could only discover the thing does not exist yet, and would then have
 * to construct the parent's path as a string and resolve it a second time --
 * which is a second walk, over a tree that may have changed between them.
 * One walk, one descriptor, and the creation happens with *at() against it.
 *
 * A path whose final component is "." or ".." has no name to create, and is
 * refused with EINVAL rather than resolved to something surprising. A path
 * that names the root itself is refused the same way.
 *
 * Returns a descriptor the caller closes, or -1 with errno set. */
int tc_rootdir_parent(const tc_rootdir *r, const char *path, char *name,
                      size_t name_cap);

#endif /* TC_ROOTDIR_H_ */
