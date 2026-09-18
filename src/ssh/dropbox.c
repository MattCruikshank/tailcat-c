/* SPDX-License-Identifier: BSD-3-Clause
 *
 * The write-only drop box. See tc/dropbox.h for what it refuses and why.
 */

#include "tc/dropbox.h"

#include "tc/sftpserve.h"

#include <stdlib.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Windows reserves these as device names in every directory, with or without
 * an extension, and opening "CON.txt" opens the console rather than creating
 * a file. This binary runs on Windows, so the check is not optional here the
 * way it would be in a Unix-only server. */
static const char *const kReserved[] = {
	"con",  "prn",  "aux",  "nul",  "com1", "com2", "com3", "com4",
	"com5", "com6", "com7", "com8", "com9", "lpt1", "lpt2", "lpt3",
	"lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
};

static char lower(char c)
{
	return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
}

static bool is_reserved(const char *name)
{
	/* The stem is what matters: "nul" and "nul.txt" are both the device. */
	size_t stem = 0;
	while (name[stem] != '\0' && name[stem] != '.')
		stem++;

	for (size_t i = 0; i < sizeof kReserved / sizeof *kReserved; i++) {
		size_t n = strlen(kReserved[i]);
		if (n != stem)
			continue;
		bool same = true;
		for (size_t j = 0; j < n; j++)
			if (lower(name[j]) != kReserved[i][j])
				same = false;
		if (same)
			return true;
	}
	return false;
}

bool tc_dropbox_safe_name(const char *path, char *out, size_t cap)
{
	if (path == NULL || out == NULL || cap == 0)
		return false;
	out[0] = '\0';

	/* Only the final component. Both separators, because a client on Windows
	 * sends backslashes and a client that wants to escape will send whichever
	 * the server does not check. */
	const char *base = path;
	for (const char *p = path; *p != '\0'; p++)
		if (*p == '/' || *p == '\\')
			base = p + 1;

	size_t n = strlen(base);
	if (n == 0 || n > TC_DROPBOX_MAX_NAME || n >= cap)
		return false;
	if (strcmp(base, ".") == 0 || strcmp(base, "..") == 0)
		return false;

	for (size_t i = 0; i < n; i++) {
		unsigned char c = (unsigned char)base[i];
		/* Control bytes and DEL: a name that a terminal renders as something
		 * other than what it is, and one that no client needs. */
		if (c < 0x20u || c == 0x7fu)
			return false;
		/* Belt and braces after the basename split above. */
		if (c == '/' || c == '\\')
			return false;
		/* Windows forbids these outright; refusing everywhere keeps one name
		 * meaning one thing on every platform we ship to. */
		if (c == ':' || c == '*' || c == '?' || c == '"' || c == '<' ||
		    c == '>' || c == '|')
			return false;
	}

	/* Windows strips a trailing dot or space before opening, so "evil. " and
	 * "evil" are the same file there and different names here -- which is
	 * exactly the kind of gap that turns "cannot overwrite" into "can". */
	if (base[n - 1] == '.' || base[n - 1] == ' ')
		return false;
	if (is_reserved(base))
		return false;

	memcpy(out, base, n + 1);
	return true;
}

int tc_dropbox_open(tc_dropbox *db, const char *dir)
{
	if (db == NULL || dir == NULL)
		return TC_ERR_INVAL;
	memset(db, 0, sizeof *db);
	db->fd = -1;
	if (snprintf(db->dir, sizeof db->dir, "%s", dir) >= (int)sizeof db->dir)
		return TC_ERR_NOSPACE;

	struct stat st;
	if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode))
		return TC_ERR_INVAL;
	return TC_OK;
}

void tc_dropbox_close(tc_dropbox *db)
{
	if (db == NULL)
		return;
	if (db->open && db->fd >= 0)
		(void)close(db->fd);
	db->open = false;
	db->fd = -1;
}

/* make_handle encodes the slot generation. A handle is opaque to the client,
 * but it must not be *reusable*: without the generation, a client that closed
 * a file and opened another would find its stale handle addressing the new
 * one, and the write meant for the first file would land in the second. */
static void make_handle(const tc_dropbox *db, uint8_t out[TC_SFTP_HANDLE_LEN])
{
	memset(out, 0, TC_SFTP_HANDLE_LEN);
	out[0] = (uint8_t)(db->generation >> 24);
	out[1] = (uint8_t)(db->generation >> 16);
	out[2] = (uint8_t)(db->generation >> 8);
	out[3] = (uint8_t)db->generation;
	out[4] = 'f';
	out[5] = 'i';
	out[6] = 'l';
	out[7] = 'e';
}

static bool handle_matches(const tc_dropbox *db,
                           const uint8_t h[TC_SFTP_HANDLE_LEN])
{
	if (!db->open)
		return false;
	uint8_t want[TC_SFTP_HANDLE_LEN];
	make_handle(db, want);
	return memcmp(want, h, TC_SFTP_HANDLE_LEN) == 0;
}

/* is_root reports whether a path names the drop box itself. Clients ask about
 * "." and "/" constantly; everything else is a file we will not discuss. */
static bool is_root(const char *p)
{
	return p[0] == '\0' || strcmp(p, ".") == 0 || strcmp(p, "/") == 0 ||
	       strcmp(p, "./") == 0;
}

static int status(uint8_t *out, size_t cap, size_t *out_len, uint32_t id,
                  uint32_t code, const char *msg)
{
	return tc_sftp_build_status(out, cap, out_len, id, code, msg);
}

/* create_unique opens a new file under a name derived from the hint.
 *
 * O_EXCL on every attempt is what makes "never overwrite" a property of the
 * filesystem call rather than of a check we did beforehand -- between a stat
 * and an open, anything can happen. */
static int create_unique(tc_dropbox *db, const char *hint)
{
	char base[TC_DROPBOX_MAX_NAME + 1];
	if (!tc_dropbox_safe_name(hint, base, sizeof base))
		return TC_ERR_INVAL;

	for (unsigned attempt = 0; attempt < 1000; attempt++) {
		char name[sizeof db->name];
		int n;
		if (attempt == 0)
			n = snprintf(name, sizeof name, "%s", base);
		else
			n = snprintf(name, sizeof name, "%s.%u", base, attempt);
		if (n < 0 || (size_t)n >= sizeof name)
			return TC_ERR_NOSPACE;

		char full[sizeof db->dir + sizeof db->name + 2];
		n = snprintf(full, sizeof full, "%s/%s", db->dir, name);
		if (n < 0 || (size_t)n >= sizeof full)
			return TC_ERR_NOSPACE;

		/* The flags are cast because cosmo declares open() taking an int and
		 * the O_ macros are unsigned there, which -Wsign-conversion notices. */
		int fd = open(full, (int)(O_WRONLY | O_CREAT | O_EXCL), 0600);
		if (fd >= 0) {
			db->fd = fd;
			db->open = true;
			db->written = 0;
			db->generation++;
			memcpy(db->name, name, (size_t)strlen(name) + 1);
			return TC_OK;
		}
		/* Anything other than "it already exists" is a real failure: retrying
		 * a thousand times against a full disk helps nobody. */
		if (errno != EEXIST)
			return TC_ERR_INVAL;
	}
	return TC_ERR_TOOMANY;
}

int tc_dropbox_handle(tc_dropbox *db, const tc_sftp_request *req, uint8_t *out,
                      size_t cap, size_t *out_len)
{
	if (db == NULL || req == NULL || out == NULL || out_len == NULL)
		return TC_ERR_INVAL;

	if (req->type == TC_SFTP_INIT) {
		/* Version 3 is what OpenSSH speaks. A client offering a later one is
		 * required by the draft to fall back to the server's, so answering
		 * with 3 is the negotiation. A client offering less than 3 has
		 * nothing we can do with it, and there is no status message before
		 * VERSION to explain that in. */
		if (req->version < TC_SFTP_VERSION)
			return TC_ERR_UNSUPPORTED;
		db->init_seen = true;
		return tc_sftp_build_version(out, cap, out_len);
	}
	if (!db->init_seen) {
		/* Nothing before INIT. A client that skips it has not agreed a
		 * version, so nothing after it has an agreed meaning. */
		return status(out, cap, out_len, req->id, TC_SFTP_FX_BAD_MESSAGE,
		              "no INIT");
	}

	switch (req->type) {
	case TC_SFTP_REALPATH: {
		/* Clients resolve "." before doing anything. The answer is always
		 * the root: there is one directory here and no way to leave it. */
		tc_sftp_attrs a;
		memset(&a, 0, sizeof a);
		a.flags = TC_SFTP_ATTR_PERMISSIONS;
		a.permissions = 040700u; /* S_IFDIR | 0700 */
		return tc_sftp_build_name(out, cap, out_len, req->id, "/",
		                          "drwx------ 1 0 0 0 Jan 1 00:00 /", &a);
	}

	case TC_SFTP_STAT:
	case TC_SFTP_LSTAT: {
		if (is_root(req->path)) {
			tc_sftp_attrs a;
			memset(&a, 0, sizeof a);
			a.flags = TC_SFTP_ATTR_PERMISSIONS;
			a.permissions = 040700u;
			return tc_sftp_build_attrs(out, cap, out_len, req->id, &a);
		}
		/* Every other path is "no such file", whether or not it exists.
		 * Answering truthfully would turn stat into the directory listing
		 * this server exists not to provide: a sender could confirm a guess
		 * one name at a time. */
		return status(out, cap, out_len, req->id, TC_SFTP_FX_NO_SUCH_FILE,
		              "no such file");
	}

	case TC_SFTP_OPEN: {
		if (req->pflags & TC_SFTP_FXF_READ)
			return status(out, cap, out_len, req->id,
			              TC_SFTP_FX_PERMISSION_DENIED, "write-only drop box");
		if (!(req->pflags & TC_SFTP_FXF_WRITE))
			return status(out, cap, out_len, req->id,
			              TC_SFTP_FX_PERMISSION_DENIED, "write-only drop box");
		if (db->open)
			return status(out, cap, out_len, req->id, TC_SFTP_FX_FAILURE,
			              "one file at a time");

		int rc = create_unique(db, req->path);
		if (rc == TC_ERR_INVAL)
			return status(out, cap, out_len, req->id, TC_SFTP_FX_FAILURE,
			              "unusable name");
		if (rc != TC_OK)
			return status(out, cap, out_len, req->id, TC_SFTP_FX_FAILURE,
			              "could not create the file");

		uint8_t h[TC_SFTP_HANDLE_LEN];
		make_handle(db, h);
		return tc_sftp_build_handle(out, cap, out_len, req->id, h);
	}

	case TC_SFTP_WRITE: {
		if (!req->has_handle || !handle_matches(db, req->handle))
			return status(out, cap, out_len, req->id, TC_SFTP_FX_FAILURE,
			              "bad handle");
		/* Bounded before the write, not after: an offset near UINT64_MAX
		 * would otherwise ask the filesystem for a file the size of the
		 * address space, and sparse files make that cheap to request and
		 * expensive to host. */
		if (req->offset > TC_DROPBOX_MAX_FILE ||
		    req->data_len > TC_DROPBOX_MAX_FILE - req->offset)
			return status(out, cap, out_len, req->id, TC_SFTP_FX_FAILURE,
			              "file too large");

		size_t done = 0;
		while (done < req->data_len) {
			ssize_t n = pwrite(db->fd, req->data + done, req->data_len - done,
			                   (off_t)(req->offset + done));
			if (n <= 0)
				return status(out, cap, out_len, req->id, TC_SFTP_FX_FAILURE,
				              "write failed");
			done += (size_t)n;
		}
		db->written += req->data_len;
		db->bytes += req->data_len;
		return status(out, cap, out_len, req->id, TC_SFTP_FX_OK, "");
	}

	case TC_SFTP_CLOSE: {
		if (!req->has_handle || !handle_matches(db, req->handle))
			return status(out, cap, out_len, req->id, TC_SFTP_FX_FAILURE,
			              "bad handle");
		tc_dropbox_close(db);
		db->files++;
		return status(out, cap, out_len, req->id, TC_SFTP_FX_OK, "");
	}

	case TC_SFTP_FSETSTAT:
	case TC_SFTP_SETSTAT:
		/* Accepted and ignored. scp sets the mode and timestamps after an
		 * upload, and failing that makes it print a warning about a file
		 * that transferred perfectly -- but honouring a mode from the far
		 * end is how a drop box acquires a setuid file. The server owns its
		 * own files' permissions. */
		return status(out, cap, out_len, req->id, TC_SFTP_FX_OK, "");

	case TC_SFTP_FSTAT: {
		/* About the file the client is itself writing, so this leaks
		 * nothing it does not already know. scp asks. */
		if (!req->has_handle || !handle_matches(db, req->handle))
			return status(out, cap, out_len, req->id, TC_SFTP_FX_FAILURE,
			              "bad handle");
		tc_sftp_attrs a;
		memset(&a, 0, sizeof a);
		a.flags = TC_SFTP_ATTR_SIZE | TC_SFTP_ATTR_PERMISSIONS;
		a.size = db->written;
		a.permissions = 0100600u; /* S_IFREG | 0600 */
		return tc_sftp_build_attrs(out, cap, out_len, req->id, &a);
	}

	case TC_SFTP_READ:
	case TC_SFTP_OPENDIR:
	case TC_SFTP_READDIR:
	case TC_SFTP_REMOVE:
	case TC_SFTP_RMDIR:
	case TC_SFTP_MKDIR:
	case TC_SFTP_RENAME:
	case TC_SFTP_SYMLINK:
	case TC_SFTP_READLINK:
		/* The whole point, in one branch. Reading, listing, renaming,
		 * deleting and linking are each a way to turn a drop box into
		 * something else, and MKDIR is how a sender gets to choose names
		 * again -- which is the guarantee the rest of this file exists to
		 * keep. Upstream's recursive mode trades it away deliberately; this
		 * mode does not have it to trade. */
		return status(out, cap, out_len, req->id,
		              TC_SFTP_FX_PERMISSION_DENIED, "write-only drop box");

	default:
		return status(out, cap, out_len, req->id, TC_SFTP_FX_OP_UNSUPPORTED,
		              "unsupported");
	}
}

/* The signature tc_sftp_serve wants. */
static int dropbox_handle_cb(void *ctx, const tc_sftp_request *req,
                             uint8_t *out, size_t cap, size_t *out_len)
{
	return tc_dropbox_handle((tc_dropbox *)ctx, req, out, cap, out_len);
}

int tc_dropbox_serve(tc_dropbox *db, tc_ssh_server *s)
{
	if (db == NULL || s == NULL)
		return TC_ERR_INVAL;
	/* The loop lives in tc/sftpserve.h now, because the file server needs
	 * the same one and two framing implementations are two chances to get a
	 * length check subtly different. */
	int rc = tc_sftp_serve(s, dropbox_handle_cb, db);
	tc_dropbox_close(db);
	return rc;
}
