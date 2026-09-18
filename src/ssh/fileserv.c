/* SPDX-License-Identifier: BSD-3-Clause
 *
 * See include/tc/fileserv.h.
 */
#include "tc/fileserv.h"

#include "tc/sftpserve.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Cosmopolitan's O_* macros are unsigned and open(2) takes a signed int, so
 * every combination of them needs one narrowing cast. Named once here rather
 * than sprinkled through the call sites, where a cast is easy to read as
 * something more interesting than it is. */
#define OFLAGS(x) ((int)(unsigned)(x))

/* SSH_FX_* codes, from draft-ietf-secsh-filexfer-02 section 7. */
#define FX_OK 0
#define FX_EOF 1
#define FX_NO_SUCH_FILE 2
#define FX_PERMISSION_DENIED 3
#define FX_FAILURE 4

int tc_fileserv_open(tc_fileserv *fs, const char *dir, bool writable)
{
	if (fs == NULL || dir == NULL)
		return TC_ERR_INVAL;
	memset(fs, 0, sizeof *fs);
	fs->root_fd = -1;
	for (size_t i = 0; i < TC_FILESERV_MAX_HANDLES; i++)
		fs->h[i].fd = -1;

	if ((size_t)snprintf(fs->root, sizeof fs->root, "%s", dir) >=
	    sizeof fs->root)
		return TC_ERR_NOSPACE;

	int fd = open(dir, OFLAGS(O_RDONLY | O_DIRECTORY));
	if (fd < 0)
		return TC_ERR_INVAL;
	fs->root_fd = fd;
	fs->writable = writable;
	fs->next_handle = 1;
	return TC_OK;
}

void tc_fileserv_close(tc_fileserv *fs)
{
	if (fs == NULL)
		return;
	for (size_t i = 0; i < TC_FILESERV_MAX_HANDLES; i++) {
		if (!fs->h[i].used)
			continue;
		if (fs->h[i].dir != NULL)
			(void)closedir((DIR *)fs->h[i].dir);
		else if (fs->h[i].fd >= 0)
			(void)close(fs->h[i].fd);
		fs->h[i].used = false;
		fs->h[i].fd = -1;
		fs->h[i].dir = NULL;
	}
	if (fs->root_fd >= 0)
		(void)close(fs->root_fd);
	fs->root_fd = -1;
}

/* ---- confinement -------------------------------------------------------- */

int tc_fileserv_resolve(tc_fileserv *fs, const char *path, bool want_dir,
                        int flags)
{
	if (fs == NULL || fs->root_fd < 0 || path == NULL) {
		errno = EINVAL;
		return -1;
	}

	/* The components that survive `.` and `..`, resolved before any of them
	 * reaches the filesystem. "a/../../etc" is refused as a path; it is
	 * never opened and then reconsidered. */
	const char *parts[64];
	size_t lens[64];
	size_t n = 0;
	const char *p = path;
	while (*p != '\0') {
		while (*p == '/')
			p++;
		if (*p == '\0')
			break;
		const char *start = p;
		while (*p != '\0' && *p != '/')
			p++;
		size_t len = (size_t)(p - start);
		if (len == 1 && start[0] == '.')
			continue;
		if (len == 2 && start[0] == '.' && start[1] == '.') {
			if (n == 0) {
				/* Above the root. There is nothing there for this client. */
				errno = EACCES;
				return -1;
			}
			n--;
			continue;
		}
		if (n >= sizeof parts / sizeof parts[0]) {
			errno = ENAMETOOLONG;
			return -1;
		}
		parts[n] = start;
		lens[n] = len;
		n++;
	}

	int cur = dup(fs->root_fd);
	if (cur < 0)
		return -1;

	for (size_t i = 0; i < n; i++) {
		char name[256];
		if (lens[i] >= sizeof name) {
			(void)close(cur);
			errno = ENAMETOOLONG;
			return -1;
		}
		memcpy(name, parts[i], lens[i]);
		name[lens[i]] = '\0';

		bool last = (i + 1 == n);
		/* O_NOFOLLOW at every step, which is the whole confinement: a
		 * symlink is refused rather than followed, so nothing can redirect
		 * the walk outside the root. A realpath() check instead would
		 * resolve the link, compare afterwards, and lose a race to whoever
		 * can replace a component in between. */
		int f = last ? OFLAGS((unsigned)flags | O_NOFOLLOW)
		             : OFLAGS(O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
		if (last && want_dir)
			f = OFLAGS(O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
		int next = openat(cur, name, f, 0600);
		(void)close(cur);
		if (next < 0)
			return -1;
		cur = next;
	}

	if (n == 0 && want_dir)
		return cur; /* the root itself */
	return cur;
}

/* ---- replies ------------------------------------------------------------ */

static int status_for_errno(int e)
{
	switch (e) {
	case ENOENT:
	case ENOTDIR:
		return FX_NO_SUCH_FILE;
	case EACCES:
	case EPERM:
	case ELOOP: /* a symlink the walk refused to follow */
		return FX_PERMISSION_DENIED;
	default:
		return FX_FAILURE;
	}
}

static int say(const tc_sftp_request *req, uint8_t *out, size_t cap,
               size_t *out_len, int code, const char *why)
{
	return tc_sftp_build_status(out, cap, out_len, req->id, (uint32_t)code,
	                            why);
}

static void attrs_of(tc_sftp_attrs *a, const struct stat *st)
{
	memset(a, 0, sizeof *a);
	a->flags = TC_SFTP_ATTR_SIZE | TC_SFTP_ATTR_PERMISSIONS |
	           TC_SFTP_ATTR_ACMODTIME;
	a->size = (uint64_t)st->st_size;
	a->permissions = (uint32_t)st->st_mode;
	a->atime = (uint32_t)st->st_atime;
	a->mtime = (uint32_t)st->st_mtime;
}

/* The ls -l line version 3 sends beside each name. Clients display it rather
 * than parse it, so it is cosmetic -- but an empty one makes `ls -l` print
 * nothing useful, which looks like a broken server rather than a terse one. */
static void longname_of(char *out, size_t cap, const char *name,
                        const struct stat *st)
{
	char perms[11];
	mode_t m = st->st_mode;
	perms[0] = S_ISDIR(m) ? 'd' : '-';
	perms[1] = (m & S_IRUSR) ? 'r' : '-';
	perms[2] = (m & S_IWUSR) ? 'w' : '-';
	perms[3] = (m & S_IXUSR) ? 'x' : '-';
	perms[4] = (m & S_IRGRP) ? 'r' : '-';
	perms[5] = (m & S_IWGRP) ? 'w' : '-';
	perms[6] = (m & S_IXGRP) ? 'x' : '-';
	perms[7] = (m & S_IROTH) ? 'r' : '-';
	perms[8] = (m & S_IWOTH) ? 'w' : '-';
	perms[9] = (m & S_IXOTH) ? 'x' : '-';
	perms[10] = '\0';
	(void)snprintf(out, cap, "%s 1 owner group %8llu Jan  1 00:00 %s", perms,
	               (unsigned long long)st->st_size, name);
}

static tc_fileserv_handle *handle_alloc(tc_fileserv *fs)
{
	for (size_t i = 0; i < TC_FILESERV_MAX_HANDLES; i++) {
		if (!fs->h[i].used)
			return &fs->h[i];
	}
	return NULL;
}

static tc_fileserv_handle *handle_find(tc_fileserv *fs, const uint8_t *id)
{
	for (size_t i = 0; i < TC_FILESERV_MAX_HANDLES; i++) {
		if (fs->h[i].used &&
		    memcmp(fs->h[i].id, id, TC_SFTP_HANDLE_LEN) == 0)
			return &fs->h[i];
	}
	return NULL;
}

static void handle_name(tc_fileserv *fs, tc_fileserv_handle *h)
{
	uint64_t v = fs->next_handle++;
	for (size_t i = 0; i < TC_SFTP_HANDLE_LEN; i++)
		h->id[i] = (uint8_t)(v >> (8 * i));
}

static void handle_release(tc_fileserv_handle *h)
{
	if (h->dir != NULL)
		(void)closedir((DIR *)h->dir); /* closes the descriptor with it */
	else if (h->fd >= 0)
		(void)close(h->fd);
	h->used = false;
	h->fd = -1;
	h->dir = NULL;
}

int tc_fileserv_handle_req(tc_fileserv *fs, const tc_sftp_request *req,
                           uint8_t *out, size_t cap, size_t *out_len)
{
	if (fs == NULL || req == NULL || out == NULL || out_len == NULL)
		return TC_ERR_INVAL;

	switch (req->type) {
	case TC_SFTP_INIT:
		return tc_sftp_build_version(out, cap, out_len);

	case TC_SFTP_REALPATH: {
		/* Every path is relative to the root, so the canonical form is the
		 * path itself with a leading slash. Answered without touching the
		 * filesystem, which also keeps REALPATH from telling a client
		 * whether a name exists before it has asked to open it. */
		const char *p = (req->path[0] != '\0') ? req->path : ".";
		char canon[TC_SFTP_MAX_PATH + 1];
		if (strcmp(p, ".") == 0 || strcmp(p, "/") == 0)
			(void)snprintf(canon, sizeof canon, "/");
		else if (p[0] == '/')
			(void)snprintf(canon, sizeof canon, "%s", p);
		else
			(void)snprintf(canon, sizeof canon, "/%s", p);
		tc_sftp_attrs a;
		memset(&a, 0, sizeof a);
		return tc_sftp_build_name(out, cap, out_len, req->id, canon, canon,
		                          &a);
	}

	case TC_SFTP_STAT:
	case TC_SFTP_LSTAT: {
		/* Both are the same answer here. LSTAT would normally describe a
		 * symlink itself, but the walk refuses to open one at all, so the
		 * only honest reply for a link is the refusal, either way. */
		int fd = tc_fileserv_resolve(fs, req->path, false, O_RDONLY);
		if (fd < 0 && (errno == EISDIR || errno == ENOTDIR))
			fd = tc_fileserv_resolve(fs, req->path, true, 0);
		if (fd < 0)
			return say(req, out, cap, out_len, status_for_errno(errno),
			           "no such file");
		struct stat st;
		int rc = fstat(fd, &st);
		(void)close(fd);
		if (rc != 0)
			return say(req, out, cap, out_len, FX_FAILURE, "stat failed");
		tc_sftp_attrs a;
		attrs_of(&a, &st);
		return tc_sftp_build_attrs(out, cap, out_len, req->id, &a);
	}

	case TC_SFTP_FSTAT: {
		tc_fileserv_handle *h =
		    req->has_handle ? handle_find(fs, req->handle) : NULL;
		if (h == NULL)
			return say(req, out, cap, out_len, FX_FAILURE, "bad handle");
		struct stat st;
		if (fstat(h->fd, &st) != 0)
			return say(req, out, cap, out_len, FX_FAILURE, "stat failed");
		tc_sftp_attrs a;
		attrs_of(&a, &st);
		return tc_sftp_build_attrs(out, cap, out_len, req->id, &a);
	}

	case TC_SFTP_OPEN: {
		bool wants_write =
		    (req->pflags & (TC_SFTP_FXF_WRITE | TC_SFTP_FXF_CREAT |
		                    TC_SFTP_FXF_TRUNC | TC_SFTP_FXF_APPEND)) != 0;
		if (wants_write && !fs->writable)
			return say(req, out, cap, out_len, FX_PERMISSION_DENIED,
			           "this directory is served read-only");
		tc_fileserv_handle *h = handle_alloc(fs);
		if (h == NULL)
			return say(req, out, cap, out_len, FX_FAILURE,
			           "too many open files");
		unsigned flags = wants_write ? (O_RDWR | O_CREAT) : O_RDONLY;
		if ((req->pflags & TC_SFTP_FXF_TRUNC) != 0)
			flags |= O_TRUNC;
		if ((req->pflags & TC_SFTP_FXF_EXCL) != 0)
			flags |= O_EXCL;
		int fd = tc_fileserv_resolve(fs, req->path, false, OFLAGS(flags));
		if (fd < 0)
			return say(req, out, cap, out_len, status_for_errno(errno),
			           "cannot open that");
		h->used = true;
		h->is_dir = false;
		h->fd = fd;
		h->dir = NULL;
		h->sent_eof = false;
		handle_name(fs, h);
		return tc_sftp_build_handle(out, cap, out_len, req->id, h->id);
	}

	case TC_SFTP_OPENDIR: {
		tc_fileserv_handle *h = handle_alloc(fs);
		if (h == NULL)
			return say(req, out, cap, out_len, FX_FAILURE,
			           "too many open files");
		int fd = tc_fileserv_resolve(fs, req->path, true, 0);
		if (fd < 0)
			return say(req, out, cap, out_len, status_for_errno(errno),
			           "cannot open that directory");
		DIR *d = fdopendir(fd);
		if (d == NULL) {
			(void)close(fd);
			return say(req, out, cap, out_len, FX_FAILURE,
			           "cannot read that directory");
		}
		h->used = true;
		h->is_dir = true;
		h->fd = fd;
		h->dir = d;
		h->sent_eof = false;
		handle_name(fs, h);
		return tc_sftp_build_handle(out, cap, out_len, req->id, h->id);
	}

	case TC_SFTP_READ: {
		tc_fileserv_handle *h =
		    req->has_handle ? handle_find(fs, req->handle) : NULL;
		if (h == NULL || h->is_dir)
			return say(req, out, cap, out_len, FX_FAILURE, "bad handle");
		size_t want = req->length;
		if (want > TC_FILESERV_MAX_READ)
			want = TC_FILESERV_MAX_READ;
		uint8_t *tmp = malloc(want != 0 ? want : 1);
		if (tmp == NULL)
			return say(req, out, cap, out_len, FX_FAILURE, "out of memory");
		ssize_t got = pread(h->fd, tmp, want, (off_t)req->offset);
		int rc;
		if (got < 0)
			rc = say(req, out, cap, out_len, FX_FAILURE, "read failed");
		else if (got == 0)
			rc = say(req, out, cap, out_len, FX_EOF, "end of file");
		else
			rc = tc_sftp_build_data(out, cap, out_len, req->id, tmp,
			                        (size_t)got);
		free(tmp);
		return rc;
	}

	case TC_SFTP_WRITE: {
		if (!fs->writable)
			return say(req, out, cap, out_len, FX_PERMISSION_DENIED,
			           "this directory is served read-only");
		tc_fileserv_handle *h =
		    req->has_handle ? handle_find(fs, req->handle) : NULL;
		if (h == NULL || h->is_dir)
			return say(req, out, cap, out_len, FX_FAILURE, "bad handle");
		ssize_t put =
		    pwrite(h->fd, req->data, req->data_len, (off_t)req->offset);
		if (put < 0 || (size_t)put != req->data_len)
			return say(req, out, cap, out_len, FX_FAILURE, "write failed");
		return say(req, out, cap, out_len, FX_OK, "");
	}

	case TC_SFTP_READDIR: {
		tc_fileserv_handle *h =
		    req->has_handle ? handle_find(fs, req->handle) : NULL;
		if (h == NULL || !h->is_dir || h->dir == NULL)
			return say(req, out, cap, out_len, FX_FAILURE, "bad handle");
		if (h->sent_eof)
			return say(req, out, cap, out_len, FX_EOF, "end of directory");

		/* One entry per reply. A NAME response may carry any number and most
		 * servers batch; the client loops until EOF either way, so this
		 * spends a round trip per file rather than growing a second builder.
		 * Worth revisiting for a directory of thousands, not for handing
		 * someone a folder. */
		for (;;) {
			struct dirent *de = readdir((DIR *)h->dir);
			if (de == NULL) {
				h->sent_eof = true;
				return say(req, out, cap, out_len, FX_EOF,
				           "end of directory");
			}
			if (strcmp(de->d_name, ".") == 0 ||
			    strcmp(de->d_name, "..") == 0)
				continue;
			struct stat st;
			/* AT_SYMLINK_NOFOLLOW: a listing describes the link itself, not
			 * whatever it points at, which may well be outside the root. */
			if (fstatat(h->fd, de->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0)
				continue;
			if (S_ISLNK(st.st_mode))
				continue; /* not served, so not advertised */
			tc_sftp_attrs a;
			attrs_of(&a, &st);
			char longname[512];
			longname_of(longname, sizeof longname, de->d_name, &st);
			return tc_sftp_build_name(out, cap, out_len, req->id, de->d_name,
			                          longname, &a);
		}
	}

	case TC_SFTP_CLOSE: {
		tc_fileserv_handle *h =
		    req->has_handle ? handle_find(fs, req->handle) : NULL;
		if (h != NULL)
			handle_release(h);
		return say(req, out, cap, out_len, FX_OK, "");
	}

	case TC_SFTP_SETSTAT:
	case TC_SFTP_FSETSTAT:
		/* Accepted and ignored, even when writable. The server owns the
		 * permissions of files in its own tree; honouring a mode from the
		 * far end is how a served directory acquires a setuid file. sftp
		 * sends this after every upload to preserve times, and failing it
		 * would make a successful transfer report an error. */
		if (!fs->writable)
			return say(req, out, cap, out_len, FX_PERMISSION_DENIED,
			           "this directory is served read-only");
		return say(req, out, cap, out_len, FX_OK, "");

	case TC_SFTP_MKDIR:
	case TC_SFTP_RMDIR:
	case TC_SFTP_REMOVE:
	case TC_SFTP_RENAME:
		if (!fs->writable)
			return say(req, out, cap, out_len, FX_PERMISSION_DENIED,
			           "this directory is served read-only");
		return say(req, out, cap, out_len, FX_FAILURE,
		           "not supported by this server");

	case TC_SFTP_SYMLINK:
	case TC_SFTP_READLINK:
		/* Never, in either mode. A symlink is the one thing that can point
		 * out of the tree, so a server that will make or follow one has
		 * given away the confinement above. */
		return say(req, out, cap, out_len, FX_PERMISSION_DENIED,
		           "symlinks are not served");

	default:
		return say(req, out, cap, out_len, FX_FAILURE,
		           "not supported by this server");
	}
}

static int fileserv_cb(void *ctx, const tc_sftp_request *req, uint8_t *out,
                       size_t cap, size_t *out_len)
{
	return tc_fileserv_handle_req((tc_fileserv *)ctx, req, out, cap, out_len);
}

int tc_fileserv_serve(tc_fileserv *fs, tc_ssh_server *s)
{
	if (fs == NULL || s == NULL)
		return TC_ERR_INVAL;
	int rc = tc_sftp_serve(s, fileserv_cb, fs);
	tc_fileserv_close(fs);
	return rc;
}
