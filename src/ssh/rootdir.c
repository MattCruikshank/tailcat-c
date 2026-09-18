/* SPDX-License-Identifier: BSD-3-Clause
 *
 * See include/tc/rootdir.h.
 */
#include "tc/rootdir.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Cosmopolitan's O_* macros are unsigned and open(2) takes a signed int, so
 * every combination of them needs one narrowing cast. Named once here rather
 * than sprinkled through the call sites, where a cast is easy to read as
 * something more interesting than it is. */
#define OFLAGS(x) ((int)(unsigned)(x))

int tc_rootdir_open(tc_rootdir *r, const char *dir)
{
	if (r == NULL || dir == NULL)
		return TC_ERR_INVAL;
	memset(r, 0, sizeof *r);
	r->fd = -1;

	if ((size_t)snprintf(r->path, sizeof r->path, "%s", dir) >= sizeof r->path)
		return TC_ERR_NOSPACE;

	int fd = open(dir, OFLAGS(O_RDONLY | O_DIRECTORY));
	if (fd < 0)
		return TC_ERR_INVAL;
	r->fd = fd;
	return TC_OK;
}

void tc_rootdir_close(tc_rootdir *r)
{
	if (r == NULL)
		return;
	if (r->fd >= 0)
		(void)close(r->fd);
	r->fd = -1;
}

/* split reduces a client path to the components that survive `.` and `..`.
 *
 * Done before any of it reaches the filesystem, which is the whole point: a
 * path that dips below the root at any point is rejected as a path, even when
 * it would climb back. That is stricter than a realpath() comparison, which
 * would allow "../root/file" -- and being stricter here costs nothing, since
 * nobody writes that on purpose. */
static int split(const char *path, const char *parts[TC_ROOTDIR_MAX_DEPTH],
                 size_t lens[TC_ROOTDIR_MAX_DEPTH], size_t *out_n)
{
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
		if (n >= TC_ROOTDIR_MAX_DEPTH) {
			errno = ENAMETOOLONG;
			return -1;
		}
		parts[n] = start;
		lens[n] = len;
		n++;
	}
	*out_n = n;
	return 0;
}

/* walk descends `count` components from the root, opening each with
 * O_NOFOLLOW. Returns a descriptor for the last directory, or -1. */
static int walk(const tc_rootdir *r, const char *parts[], const size_t lens[],
                size_t count)
{
	int cur = dup(r->fd);
	if (cur < 0)
		return -1;
	for (size_t i = 0; i < count; i++) {
		char name[TC_ROOTDIR_MAX_NAME];
		if (lens[i] >= sizeof name) {
			(void)close(cur);
			errno = ENAMETOOLONG;
			return -1;
		}
		memcpy(name, parts[i], lens[i]);
		name[lens[i]] = '\0';
		int next = openat(cur, name,
		                  OFLAGS(O_RDONLY | O_DIRECTORY | O_NOFOLLOW));
		(void)close(cur);
		if (next < 0)
			return -1;
		cur = next;
	}
	return cur;
}

int tc_rootdir_resolve(const tc_rootdir *r, const char *path, bool want_dir,
                       int flags)
{
	if (r == NULL || r->fd < 0 || path == NULL) {
		errno = EINVAL;
		return -1;
	}

	const char *parts[TC_ROOTDIR_MAX_DEPTH];
	size_t lens[TC_ROOTDIR_MAX_DEPTH];
	size_t n = 0;
	if (split(path, parts, lens, &n) != 0)
		return -1;

	if (n == 0) {
		/* The root itself. Duplicated rather than returned directly, so a
		 * caller that closes what it is given cannot close ours. */
		return dup(r->fd);
	}

	int parent = walk(r, parts, lens, n - 1);
	if (parent < 0)
		return -1;

	char name[TC_ROOTDIR_MAX_NAME];
	if (lens[n - 1] >= sizeof name) {
		(void)close(parent);
		errno = ENAMETOOLONG;
		return -1;
	}
	memcpy(name, parts[n - 1], lens[n - 1]);
	name[lens[n - 1]] = '\0';

	/* O_NOFOLLOW on the last component too, which is the whole confinement:
	 * a symlink is refused rather than followed, so nothing can redirect the
	 * walk outside the root. */
	int f = want_dir ? OFLAGS(O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
	                 : OFLAGS((unsigned)flags | O_NOFOLLOW);
	int fd = openat(parent, name, f, 0600);
	(void)close(parent);
	return fd;
}

int tc_rootdir_parent(const tc_rootdir *r, const char *path, char *name,
                      size_t name_cap)
{
	if (r == NULL || r->fd < 0 || path == NULL || name == NULL) {
		errno = EINVAL;
		return -1;
	}

	const char *parts[TC_ROOTDIR_MAX_DEPTH];
	size_t lens[TC_ROOTDIR_MAX_DEPTH];
	size_t n = 0;
	if (split(path, parts, lens, &n) != 0)
		return -1;

	if (n == 0) {
		/* The path named the root, or climbed back to it. There is no final
		 * component to create, and inventing one would be a guess. */
		errno = EINVAL;
		return -1;
	}
	if (lens[n - 1] >= name_cap) {
		errno = ENAMETOOLONG;
		return -1;
	}

	int parent = walk(r, parts, lens, n - 1);
	if (parent < 0)
		return -1;

	memcpy(name, parts[n - 1], lens[n - 1]);
	name[lens[n - 1]] = '\0';
	return parent;
}
