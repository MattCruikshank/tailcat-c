/* SPDX-License-Identifier: BSD-3-Clause
 *
 * A write-only SFTP drop box: the policy half of `recv`.
 *
 * tc/sftp.h is the wire format and has no opinions. This file has nothing but
 * opinions, and they are the point of the feature. The two are separate so
 * that a change to parsing cannot quietly become a change to permissions.
 *
 * ---- what a drop box is for ---------------------------------------------
 *
 * Someone you have given an address to can send you a file. That is all. They
 * must not be able to read anything back, learn what is already here,
 * overwrite what is already here, or reach outside the directory. Upstream
 * tailcat's flat mode is the design being copied rather than improved on, and
 * its central rule is the one worth restating: **the server chooses every
 * stored filename.**
 *
 * That single rule does most of the work. A sender who cannot name the
 * destination cannot overwrite a file, cannot plant one at a path of their
 * choosing, and cannot confirm whether a guess exists. Everything else here
 * is a consequence of it or a defence in depth behind it.
 *
 * Concretely:
 *
 *   - The client's path is a *hint*. Only its final component is considered,
 *     which alone defeats every traversal, and it is then sanitised and made
 *     unique. A collision is resolved by choosing a different name, never by
 *     overwriting, and the chosen name is never sent back -- returning it
 *     would leak exactly the directory contents the rule is protecting.
 *   - Reads are refused. So are directory listings, renames, deletions and
 *     symlinks. A drop box that can be read is a file server.
 *   - Attributes a sender asks for are accepted and ignored. Honouring a
 *     mode from the far end is how a drop box ends up with a setuid file in
 *     it, and the server owns its own files' permissions.
 *   - Everything is refused with a status rather than by dropping the
 *     connection, because a client that is told "permission denied" reports
 *     something useful and one that is hung up on reports a network error.
 *
 * ---- the recursive mode, and what it costs -------------------------------
 *
 * `--files <dir>:wo+`, or `recv --accept-dirs`, accepts a directory tree --
 * what `cp -r` sends. It is a *second mode*, not a relaxation of the first,
 * and it is off unless asked for, because it gives up part of the guarantee
 * above and there is no way to have both.
 *
 * What it gives up, stated plainly:
 *
 *   - **A sender can choose names.** An upload keeps the name it asked for
 *     when that name is free, and only falls back to a server-chosen one on
 *     a collision. A tree cannot be reassembled otherwise: the whole point
 *     of `cp -r` is that the names on the far side match.
 *   - **A sender can learn that some paths exist.** Directories have to be
 *     stat-able for a recursive upload to resolve its destinations, so a
 *     sender can discover which directory names are already here -- one
 *     guess at a time. It still cannot list them, and it still cannot learn
 *     anything about *files*.
 *
 * What it keeps:
 *
 *   - Nothing can be read back, listed, renamed, deleted or linked.
 *   - Nothing is overwritten. The create is O_EXCL, so "this name is free"
 *     and "take it" are one operation with nothing in between.
 *   - Everything stays inside the directory. Paths are resolved by
 *     tc/rootdir.h, so `..` cannot climb out and a symlink is refused rather
 *     than followed -- including one the sender just created, because it
 *     cannot create one.
 *   - A sender still learns nothing about files it did not put there: a stat
 *     of a file is "no such file" whether or not it exists, exactly as in
 *     the flat mode.
 *
 * Upstream documents the same trade for the same mode, which is the reason
 * to offer it in the same shape rather than invent a safer-looking one.
 */
#ifndef TC_DROPBOX_H_
#define TC_DROPBOX_H_

#include "tc/rootdir.h"
#include "tc/sftp.h"
#include "tc/sshserver.h"

/* The longest stored name, before the uniquifying suffix. */
#define TC_DROPBOX_MAX_NAME 128

/* A cap on any one file, so a sender cannot fill the disk with one request
 * and cannot ask for a sparse file the size of the address space. */
#ifndef TC_DROPBOX_MAX_FILE
#define TC_DROPBOX_MAX_FILE (1024ull * 1024ull * 1024ull)
#endif

/* How many of this session's own uploads are remembered, for the stat that
 * some clients do straight after writing a file.
 *
 * Bounded because it is attacker-driven, and it degrades in the safe
 * direction: past the bound the oldest is forgotten, and a stat of it answers
 * "no such file" -- which is what the flat mode says about everything. A
 * client that cannot stat a file it uploaded ten files ago is not a client
 * anyone has. */
#define TC_DROPBOX_REMEMBERED 32

/* The longest remembered path. Shorter than an SFTP path may be, because
 * tc_dropbox is a stack local in both callers and the full length would be
 * 32KB of it. A path too long to remember is simply not remembered, which
 * costs a stat of it the "no such file" that everything else gets. */
#define TC_DROPBOX_REMEMBERED_PATH 256

typedef struct {
	tc_rootdir root;
	bool init_seen;
	/* The recursive mode. See the header comment for what it trades. */
	bool recursive;

	/* Paths this session created, as the client named them. Only these are
	 * visible to a stat; everything else is "no such file" whether or not it
	 * is there. */
	char mine[TC_DROPBOX_REMEMBERED][TC_DROPBOX_REMEMBERED_PATH];
	size_t nmine;
	size_t mine_next;

	/* One open file at a time. A drop box has no use for more, and a limit
	 * of one is a limit that cannot be exhausted. */
	bool open;
	int fd;
	uint32_t generation;
	uint64_t written;
	char name[TC_DROPBOX_MAX_NAME + 32];

	/* Counted for the caller to report; the client is never told. */
	unsigned files;
	uint64_t bytes;
} tc_dropbox;

/* tc_dropbox_open prepares a flat, write-only drop box over an existing
 * directory. */
int tc_dropbox_open(tc_dropbox *db, const char *dir);

/* tc_dropbox_open_recursive prepares the recursive mode instead.
 *
 * A separate entry point rather than a boolean on the one above, so that
 * every caller of the flat mode says which it wants by name and no existing
 * one can acquire directories by having a field default the wrong way. */
int tc_dropbox_open_recursive(tc_dropbox *db, const char *dir);

/* tc_dropbox_handle answers one SFTP request, writing the reply packet.
 *
 * Always produces a reply and returns TC_OK unless the arguments are wrong:
 * a refused request is a STATUS, not an error to the caller. The one
 * exception is INIT with a version we cannot speak, which has no status to
 * carry a refusal and so returns TC_ERR_UNSUPPORTED. */
int tc_dropbox_handle(tc_dropbox *db, const tc_sftp_request *req, uint8_t *out,
                      size_t cap, size_t *out_len);

/* tc_dropbox_close releases any open file. Safe to call twice. */
void tc_dropbox_close(tc_dropbox *db);

/* tc_dropbox_serve runs the drop box over an SSH channel until the client is
 * finished, then sends an exit status.
 *
 * The framing is why this lives here rather than being written out at each
 * call site. An SFTP packet is a length followed by that many bytes, carried
 * over a channel that is a byte stream, so one packet may arrive across
 * several reads and several may arrive in one. A loop that assumed a read
 * gave it exactly one packet works against a client that sends them slowly
 * and corrupts the stream against one that pipelines -- which scp does. One
 * copy of that loop, used by the CLI and by the live test, is one place for
 * it to be right. */
int tc_dropbox_serve(tc_dropbox *db, tc_ssh_server *s);

/* tc_dropbox_safe_name reduces a client-supplied path to a storable name, or
 * reports that there is none.
 *
 * Exposed for testing because it is the single most security-relevant
 * function here, and because the cases it has to refuse are easier to
 * enumerate directly than to provoke through the protocol.
 *
 * It takes only the final path component, then refuses: an empty result,
 * "." and "..", anything containing a path separator or a control byte, and
 * -- because this binary runs on Windows too -- the reserved device names
 * and any name ending in a dot or a space, which Windows silently strips
 * before opening the file. */
bool tc_dropbox_safe_name(const char *path, char *out, size_t cap);

#endif /* TC_DROPBOX_H_ */
