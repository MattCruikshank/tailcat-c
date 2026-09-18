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

static int dropbox_open_mode(tc_dropbox *db, const char *dir, bool recursive)
{
	if (db == NULL || dir == NULL)
		return TC_ERR_INVAL;
	memset(db, 0, sizeof *db);
	db->fd = -1;
	db->recursive = recursive;
	return tc_rootdir_open(&db->root, dir);
}

int tc_dropbox_open(tc_dropbox *db, const char *dir)
{
	return dropbox_open_mode(db, dir, false);
}

int tc_dropbox_open_recursive(tc_dropbox *db, const char *dir)
{
	return dropbox_open_mode(db, dir, true);
}

/* close_file releases the one open upload, and nothing else. Separate from
 * tc_dropbox_close because an SFTP CLOSE ends a *file*, not the session: a
 * recursive upload sends many, and closing the root descriptor on the first
 * one would break every later path. */
static void close_file(tc_dropbox *db)
{
	if (db->open && db->fd >= 0)
		(void)close(db->fd);
	db->open = false;
	db->fd = -1;
}

void tc_dropbox_close(tc_dropbox *db)
{
	if (db == NULL)
		return;
	close_file(db);
	tc_rootdir_close(&db->root);
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

/* remember records a path this session created, so a client can stat what it
 * has just written. A ring: past the bound the oldest is forgotten and its
 * stat goes back to "no such file", which is the safe direction. */
static void remember(tc_dropbox *db, const char *client_path)
{
	if (strlen(client_path) >= sizeof db->mine[0])
		return; /* too long to remember; see the header */
	(void)snprintf(db->mine[db->mine_next], sizeof db->mine[0], "%s",
	               client_path);
	db->mine_next = (db->mine_next + 1) % TC_DROPBOX_REMEMBERED;
	if (db->nmine < TC_DROPBOX_REMEMBERED)
		db->nmine++;
}

/* is_mine reports whether this session created the path, comparing the
 * strings the client used rather than anything on disk. Two spellings of one
 * path do not match, which costs a stat nothing: a client asks about the
 * spelling it sent. */
static bool is_mine(const tc_dropbox *db, const char *client_path)
{
	for (size_t i = 0; i < db->nmine; i++) {
		if (strcmp(db->mine[i], client_path) == 0)
			return true;
	}
	return false;
}

/* safe_as_is reports whether the final component of `path` is storable
 * exactly as the client spelled it.
 *
 * The recursive mode keeps the requested name, so it has to *check* names
 * rather than rewrite them -- rewriting a directory would make every later
 * upload into it fail, naming a directory the client never asked for. The
 * check is the flat mode's sanitiser run as a comparison, so the two modes
 * refuse exactly the same names: Windows reserved devices, trailing dots and
 * spaces, control bytes, separators, "." and "..".
 *
 * Only the final component is checked on each request, which is enough: every
 * interior component had to be created by an earlier MKDIR through this same
 * check, or the walk would not find it. */
static bool safe_as_is(const char *path, char *out, size_t cap)
{
	if (!tc_dropbox_safe_name(path, out, cap))
		return false;
	return strcmp(out, path) == 0;
}

static int status(uint8_t *out, size_t cap, size_t *out_len, uint32_t id,
                  uint32_t code, const char *msg)
{
	return tc_sftp_build_status(out, cap, out_len, id, code, msg);
}

/* create_unique opens a new file under `base`, or the first free variation of
 * it, inside the directory `parent`.
 *
 * O_EXCL on every attempt is what makes "never overwrite" a property of the
 * filesystem call rather than of a check we did beforehand -- between a stat
 * and an open, anything can happen. It is also what keeps the recursive mode
 * honest: "is this name free" and "take it" are one operation, so a sender
 * cannot learn about a file except by failing to collide with it, and even
 * then it is told nothing. */
static int create_unique(tc_dropbox *db, int parent, const char *base)
{
	for (unsigned attempt = 0; attempt < 1000; attempt++) {
		char name[sizeof db->name];
		int n;
		if (attempt == 0)
			n = snprintf(name, sizeof name, "%s", base);
		else
			n = snprintf(name, sizeof name, "%s.%u", base, attempt);
		if (n < 0 || (size_t)n >= sizeof name)
			return TC_ERR_NOSPACE;

		/* The flags are cast because cosmo declares openat() taking an int
		 * and the O_ macros are unsigned there, which -Wsign-conversion
		 * notices. O_NOFOLLOW so a symlink left in the tree cannot catch the
		 * write, though nothing here can create one. */
		int fd = openat(parent, name,
		                (int)(unsigned)(O_WRONLY | O_CREAT | O_EXCL |
		                                O_NOFOLLOW),
		                0600);
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

/* open_upload resolves where the client's path should land and creates it.
 *
 * The two modes differ here and nowhere else that matters. Flat takes the
 * final component only -- which alone defeats every traversal, because there
 * is no path left to traverse -- and creates it in the root. Recursive
 * resolves the path inside the root through tc/rootdir.h, which does the same
 * job for a path that is allowed to have directories in it. */
static int open_upload(tc_dropbox *db, const char *client_path)
{
	char base[TC_DROPBOX_MAX_NAME + 1];

	if (!db->recursive) {
		if (!tc_dropbox_safe_name(client_path, base, sizeof base))
			return TC_ERR_INVAL;
		int root = tc_rootdir_resolve(&db->root, ".", true, 0);
		if (root < 0)
			return TC_ERR_INVAL;
		int rc = create_unique(db, root, base);
		(void)close(root);
		return rc;
	}

	char name[TC_ROOTDIR_MAX_NAME];
	int parent = tc_rootdir_parent(&db->root, client_path, name, sizeof name);
	if (parent < 0)
		return TC_ERR_INVAL;
	if (!safe_as_is(name, base, sizeof base)) {
		(void)close(parent);
		return TC_ERR_INVAL;
	}
	int rc = create_unique(db, parent, base);
	(void)close(parent);
	return rc;
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
		/* Clients resolve "." before doing anything. */
		tc_sftp_attrs a;
		memset(&a, 0, sizeof a);
		a.flags = TC_SFTP_ATTR_PERMISSIONS;
		a.permissions = 040700u; /* S_IFDIR | 0700 */
		if (!db->recursive || is_root(req->path)) {
			/* Flat: the answer is always the root. There is one directory
			 * here and no way to name anything below it. */
			return tc_sftp_build_name(out, cap, out_len, req->id, "/",
			                          "drwx------ 1 0 0 0 Jan 1 00:00 /", &a);
		}
		/* Recursive: echo the path back with a leading slash, which is what
		 * it means here. Answered without touching the filesystem, so
		 * REALPATH does not become the existence oracle the stat below is
		 * careful not to be -- a client resolves the destination of a
		 * recursive upload before creating any of it. */
		char canon[TC_SFTP_MAX_PATH + 1];
		if (req->path[0] == '/')
			(void)snprintf(canon, sizeof canon, "%s", req->path);
		else
			(void)snprintf(canon, sizeof canon, "/%s", req->path);
		return tc_sftp_build_name(out, cap, out_len, req->id, canon, canon,
		                          &a);
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

		/* Something this session created. Telling a client about its own
		 * upload reveals nothing it did not send, and scp asks. */
		bool mine = is_mine(db, req->path);

		if (!db->recursive && !mine) {
			/* Every other path is "no such file", whether or not it exists.
			 * Answering truthfully would turn stat into the directory
			 * listing this server exists not to provide: a sender could
			 * confirm a guess one name at a time. */
			return status(out, cap, out_len, req->id,
			              TC_SFTP_FX_NO_SUCH_FILE, "no such file");
		}

		/* Recursive mode answers for directories as well, and this is the
		 * cost of the mode rather than an oversight: a recursive upload has
		 * to resolve its destinations, so a sender can discover which
		 * directory names are already here -- one guess at a time, without
		 * ever being able to list them. Files it did not send stay
		 * invisible, so the flat mode's guarantee about *files* survives
		 * intact. */
		int fd = tc_rootdir_resolve(&db->root, req->path, false, O_RDONLY);
		if (fd < 0 && (errno == EISDIR || errno == ENOTDIR || errno == EACCES))
			fd = tc_rootdir_resolve(&db->root, req->path, true, 0);
		if (fd < 0)
			return status(out, cap, out_len, req->id,
			              TC_SFTP_FX_NO_SUCH_FILE, "no such file");
		struct stat st;
		int rc = fstat(fd, &st);
		(void)close(fd);
		if (rc != 0)
			return status(out, cap, out_len, req->id,
			              TC_SFTP_FX_NO_SUCH_FILE, "no such file");
		if (!mine && !S_ISDIR(st.st_mode)) {
			/* A file somebody else put here. Invisible, exactly as in the
			 * flat mode. */
			return status(out, cap, out_len, req->id,
			              TC_SFTP_FX_NO_SUCH_FILE, "no such file");
		}
		tc_sftp_attrs a;
		memset(&a, 0, sizeof a);
		a.flags = TC_SFTP_ATTR_SIZE | TC_SFTP_ATTR_PERMISSIONS;
		a.size = (uint64_t)st.st_size;
		a.permissions = (uint32_t)st.st_mode;
		return tc_sftp_build_attrs(out, cap, out_len, req->id, &a);
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

		int rc = open_upload(db, req->path);
		if (rc == TC_ERR_INVAL)
			return status(out, cap, out_len, req->id, TC_SFTP_FX_FAILURE,
			              "unusable name");
		if (rc != TC_OK)
			return status(out, cap, out_len, req->id, TC_SFTP_FX_FAILURE,
			              "could not create the file");
		if (db->recursive)
			remember(db, req->path);

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
		close_file(db);
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

	case TC_SFTP_MKDIR: {
		if (!db->recursive)
			return status(out, cap, out_len, req->id,
			              TC_SFTP_FX_PERMISSION_DENIED,
			              "this drop box takes single files only");
		char name[TC_ROOTDIR_MAX_NAME];
		int parent = tc_rootdir_parent(&db->root, req->path, name,
		                               sizeof name);
		if (parent < 0)
			return status(out, cap, out_len, req->id, TC_SFTP_FX_FAILURE,
			              "cannot create that");
		char checked[TC_DROPBOX_MAX_NAME + 1];
		if (!safe_as_is(name, checked, sizeof checked)) {
			(void)close(parent);
			return status(out, cap, out_len, req->id, TC_SFTP_FX_FAILURE,
			              "unusable name");
		}
		int rc = mkdirat(parent, name, 0700);
		(void)close(parent);
		if (rc != 0) {
			/* Including "it is already there". Upstream reports that too,
			 * and a client doing `mkdir -p` treats it as success; inventing
			 * a success here would instead tell a sender that the directory
			 * exists, which is the one thing left to give away. */
			return status(out, cap, out_len, req->id, TC_SFTP_FX_FAILURE,
			              "cannot create that");
		}
		remember(db, req->path);
		return status(out, cap, out_len, req->id, TC_SFTP_FX_OK, "");
	}

	case TC_SFTP_READ:
	case TC_SFTP_OPENDIR:
	case TC_SFTP_READDIR:
	case TC_SFTP_REMOVE:
	case TC_SFTP_RMDIR:
	case TC_SFTP_RENAME:
	case TC_SFTP_SYMLINK:
	case TC_SFTP_READLINK:
		/* The whole point, in one branch. Reading, listing, renaming,
		 * deleting and linking are each a way to turn a drop box into
		 * something else, and they are refused in *both* modes: the
		 * recursive one trades away name choice and the existence of
		 * directories, and nothing else. */
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
