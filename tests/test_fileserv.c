/* SPDX-License-Identifier: BSD-3-Clause
 *
 * A served directory, and the fence around it.
 *
 * The drop box next door defends one sentence -- a sender cannot choose the
 * filename -- and its tests are written as the attacks on that sentence. This
 * file defends a different one: **a client cannot reach outside the root.**
 * It is a harder sentence to keep, because here the client does name paths,
 * and names are exactly what the drop box refuses to accept.
 *
 * So most of what follows is tc_fileserv_resolve, hammered directly. That is
 * the function the guarantee rests on; the request handler above it is a
 * switch statement, and a switch statement that calls a correct resolver is
 * much easier to audit than a resolver reached only through a live SFTP
 * session. The handler still gets tested -- read-only has to mean read-only,
 * and a handle from one session must not open a file in another -- but the
 * resolver gets the attacks.
 *
 * Symlink cases are skipped, loudly, where the filesystem will not make a
 * symlink: Windows needs a privilege for it that a test run does not have. A
 * skipped test that says so is honest; one that silently passes is the thing
 * this whole codebase keeps getting bitten by.
 */

#include "tc/fileserv.h"

#include "tctest.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_root[256];  /* the served directory */
static char g_outside[256]; /* a sibling of it, holding the secret */
static bool g_symlinks;   /* did the filesystem let us make one? */

static void write_file(const char *path, const char *contents)
{
	int fd = open(path, (int)(unsigned)(O_WRONLY | O_CREAT | O_TRUNC), 0600);
	if (fd < 0) {
		fprintf(stderr, "test_fileserv: cannot create %s\n", path);
		exit(1);
	}
	(void)!write(fd, contents, strlen(contents));
	(void)close(fd);
}

static void setup(void)
{
	char base[200];
	snprintf(base, sizeof base, "/tmp/tc_fileserv_XXXXXX");
	if (mkdtemp(base) == NULL) {
		fprintf(stderr, "test_fileserv: no temp directory\n");
		exit(1);
	}
	snprintf(g_root, sizeof g_root, "%s/root", base);
	snprintf(g_outside, sizeof g_outside, "%s/outside", base);
	(void)mkdir(g_root, 0700);
	(void)mkdir(g_outside, 0700);

	char p[512];
	snprintf(p, sizeof p, "%s/hello.txt", g_root);
	write_file(p, "hello");
	snprintf(p, sizeof p, "%s/sub", g_root);
	(void)mkdir(p, 0700);
	snprintf(p, sizeof p, "%s/sub/nested.txt", g_root);
	write_file(p, "nested");
	snprintf(p, sizeof p, "%s/secret.txt", g_outside);
	write_file(p, "the secret");

	/* A link out of the tree, a link into it, and a directory link used as
	 * an intermediate component. All three must be refused; the second one
	 * is included because refusing only the escaping links would mean the
	 * code resolves links and then judges them, which is the race. */
	char target[512], link[512];
	snprintf(target, sizeof target, "%s/secret.txt", g_outside);
	snprintf(link, sizeof link, "%s/escape.txt", g_root);
	g_symlinks = (symlink(target, link) == 0);
	if (g_symlinks) {
		snprintf(target, sizeof target, "%s/hello.txt", g_root);
		snprintf(link, sizeof link, "%s/inside.txt", g_root);
		g_symlinks = g_symlinks && symlink(target, link) == 0;
		snprintf(link, sizeof link, "%s/updir", g_root);
		g_symlinks = g_symlinks && symlink(g_outside, link) == 0;
	}
	/* All three, or none of them. The first version set g_symlinks from the
	 * first symlink and assumed the other two -- and `refuses()` passes when
	 * a path cannot be opened for *any* reason, including never having been
	 * created. A link that silently failed to appear would have made the
	 * check that a symlink into the tree is refused pass while testing
	 * nothing. gcc's warn_unused_result was pointing at a real hole, not at
	 * a missing cast. */
}

/* ---- the fence --------------------------------------------------------- */

static void opens(tc_fileserv *fs, const char *path, const char *why)
{
	tct_checks++;
	int fd = tc_fileserv_resolve(fs, path, false, O_RDONLY);
	if (fd < 0)
		TCT_FAILF("refused \"%s\" (%s): %s", path, why, strerror(errno));
	else
		(void)close(fd);
}

static void refuses(tc_fileserv *fs, const char *path, const char *why)
{
	tct_checks++;
	int fd = tc_fileserv_resolve(fs, path, false, O_RDONLY);
	if (fd >= 0) {
		/* Report what it actually got hold of: "refused" and "opened the
		 * wrong thing" are different bugs and the first line of the failure
		 * should say which. */
		char buf[64] = {0};
		ssize_t n = read(fd, buf, sizeof buf - 1);
		(void)close(fd);
		TCT_FAILF("opened \"%s\" (%s); it contains \"%.*s\"", path, why,
		          (int)(n > 0 ? n : 0), buf);
	}
}

static void test_the_root_itself_works(void)
{
	TCT_CASE("ordinary paths");
	tc_fileserv fs;
	TCT_EQ_INT(tc_fileserv_open(&fs, g_root, false), TC_OK);

	opens(&fs, "hello.txt", "a plain file");
	opens(&fs, "./hello.txt", "a leading dot");
	opens(&fs, "sub/nested.txt", "one level down");
	opens(&fs, "/hello.txt", "absolute, meaning relative to the root");
	opens(&fs, "//hello.txt", "doubled separators");
	opens(&fs, "sub/../hello.txt", "a dot-dot that stays inside");
	opens(&fs, "sub/./../sub/nested.txt", "a longer walk to the same place");

	tc_fileserv_close(&fs);
}

static void test_nothing_escapes(void)
{
	TCT_CASE("traversal");
	tc_fileserv fs;
	TCT_EQ_INT(tc_fileserv_open(&fs, g_root, false), TC_OK);

	refuses(&fs, "../outside/secret.txt", "one level up");
	refuses(&fs, "../../etc/passwd", "two levels up");
	refuses(&fs, "/../outside/secret.txt", "absolute then up");
	refuses(&fs, "sub/../../outside/secret.txt",
	        "down first, so the pop happens below the root");
	refuses(&fs, "..", "the parent itself");
	refuses(&fs, "../", "the parent with a separator");
	refuses(&fs, "./../outside/secret.txt", "dot then up");
	refuses(&fs, "sub/../sub/../../outside/secret.txt", "up after two pops");

	/* The count matters as much as the individual cases: the walk pops `..`
	 * before touching the filesystem, so a path that dips below the root at
	 * any point is rejected even when it would climb back. That is stricter
	 * than a realpath() check, which would allow the last one. */
	refuses(&fs, "../root/hello.txt",
	        "leaves the root and returns; still refused");

	tc_fileserv_close(&fs);
}

static void test_symlinks_are_refused_not_resolved(void)
{
	TCT_CASE("symlinks");
	if (!g_symlinks) {
		fprintf(stderr,
		        "test_fileserv: SKIP symlink cases (the filesystem will not "
		        "make one here)\n");
		return;
	}
	tc_fileserv fs;
	TCT_EQ_INT(tc_fileserv_open(&fs, g_root, false), TC_OK);

	refuses(&fs, "escape.txt", "a link pointing out of the tree");
	refuses(&fs, "inside.txt",
	        "a link pointing *into* the tree -- refused, not resolved");
	refuses(&fs, "updir/secret.txt", "a link as an intermediate component");
	refuses(&fs, "updir", "the directory link itself");

	tc_fileserv_close(&fs);
}

/* ---- the policy -------------------------------------------------------- */

/* status_of runs one request and reports the SSH_FX_* code, or -1 when the
 * reply was not a STATUS packet. */
static int status_of(tc_fileserv *fs, tc_sftp_request *req)
{
	uint8_t reply[TC_SFTP_MAX_PACKET];
	size_t len = 0;
	if (tc_fileserv_handle_req(fs, req, reply, sizeof reply, &len) != TC_OK)
		return -2;
	if (len < 13 || reply[4] != TC_SFTP_STATUS)
		return -1;
	return (int)((uint32_t)reply[9] << 24 | (uint32_t)reply[10] << 16 |
	             (uint32_t)reply[11] << 8 | reply[12]);
}

static uint8_t g_reply[TC_SFTP_MAX_PACKET];
static size_t g_reply_len;

static int run(tc_fileserv *fs, tc_sftp_request *req)
{
	g_reply_len = 0;
	return tc_fileserv_handle_req(fs, req, g_reply, sizeof g_reply,
	                              &g_reply_len);
}

static void req_init(tc_sftp_request *req, uint8_t type, const char *path)
{
	memset(req, 0, sizeof *req);
	req->type = type;
	req->id = 7;
	if (path != NULL)
		snprintf(req->path, sizeof req->path, "%s", path);
}

/* open_handle runs an OPEN or OPENDIR and copies out the handle it returns. */
static bool open_handle(tc_fileserv *fs, uint8_t type, const char *path,
                        uint32_t pflags, uint8_t out[TC_SFTP_HANDLE_LEN])
{
	tc_sftp_request req;
	req_init(&req, type, path);
	req.pflags = pflags;
	if (run(fs, &req) != TC_OK)
		return false;
	if (g_reply_len < 5 + 4 + 4 + TC_SFTP_HANDLE_LEN ||
	    g_reply[4] != TC_SFTP_HANDLE)
		return false;
	memcpy(out, g_reply + 13, TC_SFTP_HANDLE_LEN);
	return true;
}

static void test_read_only_means_read_only(void)
{
	TCT_CASE("read-only");
	tc_fileserv fs;
	TCT_EQ_INT(tc_fileserv_open(&fs, g_root, false), TC_OK);

	tc_sftp_request req;

	/* Reading is fine. */
	req_init(&req, TC_SFTP_OPEN, "hello.txt");
	req.pflags = TC_SFTP_FXF_READ;
	TCT_EQ_INT(run(&fs, &req), TC_OK);
	TCT_EQ_INT(g_reply[4], TC_SFTP_HANDLE);

	/* Every way of asking to write is not. Each flag is checked separately
	 * because OPEN's refusal is one condition over four bits, and a missing
	 * bit there is a writable server that reports itself read-only. */
	static const uint32_t writing[] = {
	    TC_SFTP_FXF_WRITE,
	    TC_SFTP_FXF_CREAT,
	    TC_SFTP_FXF_TRUNC,
	    TC_SFTP_FXF_APPEND,
	    TC_SFTP_FXF_READ | TC_SFTP_FXF_WRITE,
	};
	for (size_t i = 0; i < sizeof writing / sizeof writing[0]; i++) {
		req_init(&req, TC_SFTP_OPEN, "new.txt");
		req.pflags = writing[i];
		TCT_EQ_INT(status_of(&fs, &req), TC_SFTP_FX_PERMISSION_DENIED);
	}
	/* ...and the file it would have made does not exist. */
	refuses(&fs, "new.txt", "a file a refused OPEN must not have created");

	static const uint8_t mutating[] = {
	    TC_SFTP_WRITE,  TC_SFTP_SETSTAT, TC_SFTP_FSETSTAT, TC_SFTP_MKDIR,
	    TC_SFTP_RMDIR,  TC_SFTP_REMOVE,  TC_SFTP_RENAME,   TC_SFTP_SYMLINK,
	};
	for (size_t i = 0; i < sizeof mutating / sizeof mutating[0]; i++) {
		req_init(&req, mutating[i], "hello.txt");
		TCT_EQ_INT(status_of(&fs, &req), TC_SFTP_FX_PERMISSION_DENIED);
	}

	/* hello.txt still says what it said. */
	char buf[32] = {0};
	char p[512];
	snprintf(p, sizeof p, "%s/hello.txt", g_root);
	int fd = open(p, O_RDONLY);
	TCT_TRUE(fd >= 0);
	if (fd >= 0) {
		(void)!read(fd, buf, sizeof buf - 1);
		(void)close(fd);
	}
	TCT_EQ_STR(buf, "hello");

	tc_fileserv_close(&fs);
}

static void test_symlinks_are_refused_even_writable(void)
{
	TCT_CASE("no symlinks, ever");
	tc_fileserv fs;
	TCT_EQ_INT(tc_fileserv_open(&fs, g_root, true), TC_OK);

	tc_sftp_request req;
	/* The one refusal that does not relax with :rw. A writable server that
	 * would create a symlink has handed the client a way out of the root,
	 * which is the whole property. */
	req_init(&req, TC_SFTP_SYMLINK, "link");
	TCT_EQ_INT(status_of(&fs, &req), TC_SFTP_FX_PERMISSION_DENIED);
	req_init(&req, TC_SFTP_READLINK, "escape.txt");
	TCT_EQ_INT(status_of(&fs, &req), TC_SFTP_FX_PERMISSION_DENIED);

	tc_fileserv_close(&fs);
}

static void test_writable_writes(void)
{
	TCT_CASE("rw");
	tc_fileserv fs;
	TCT_EQ_INT(tc_fileserv_open(&fs, g_root, true), TC_OK);

	uint8_t h[TC_SFTP_HANDLE_LEN];
	TCT_TRUE(open_handle(&fs, TC_SFTP_OPEN, "written.txt",
	                     TC_SFTP_FXF_WRITE | TC_SFTP_FXF_CREAT, h));

	tc_sftp_request req;
	req_init(&req, TC_SFTP_WRITE, NULL);
	memcpy(req.handle, h, sizeof h);
	req.has_handle = true;
	req.offset = 0;
	req.data = (const uint8_t *)"written by a client";
	req.data_len = 19;
	TCT_EQ_INT(status_of(&fs, &req), TC_SFTP_FX_OK);

	req_init(&req, TC_SFTP_CLOSE, NULL);
	memcpy(req.handle, h, sizeof h);
	req.has_handle = true;
	TCT_EQ_INT(status_of(&fs, &req), TC_SFTP_FX_OK);

	char buf[64] = {0};
	char p[512];
	snprintf(p, sizeof p, "%s/written.txt", g_root);
	int fd = open(p, O_RDONLY);
	TCT_TRUE(fd >= 0);
	if (fd >= 0) {
		(void)!read(fd, buf, sizeof buf - 1);
		(void)close(fd);
	}
	TCT_EQ_STR(buf, "written by a client");
	(void)unlink(p);

	/* Writable does not mean the fence moved. */
	tc_sftp_request esc;
	req_init(&esc, TC_SFTP_OPEN, "../outside/secret.txt");
	esc.pflags = TC_SFTP_FXF_WRITE | TC_SFTP_FXF_CREAT;
	int st = status_of(&fs, &esc);
	TCT_TRUE(st == TC_SFTP_FX_PERMISSION_DENIED ||
	         st == TC_SFTP_FX_NO_SUCH_FILE);

	tc_fileserv_close(&fs);
}

static void test_reading_a_file(void)
{
	TCT_CASE("read");
	tc_fileserv fs;
	TCT_EQ_INT(tc_fileserv_open(&fs, g_root, false), TC_OK);

	uint8_t h[TC_SFTP_HANDLE_LEN];
	TCT_TRUE(open_handle(&fs, TC_SFTP_OPEN, "hello.txt", TC_SFTP_FXF_READ, h));

	tc_sftp_request req;
	req_init(&req, TC_SFTP_READ, NULL);
	memcpy(req.handle, h, sizeof h);
	req.has_handle = true;
	req.offset = 0;
	req.length = 100;
	TCT_EQ_INT(run(&fs, &req), TC_OK);
	TCT_EQ_INT(g_reply[4], TC_SFTP_DATA);
	TCT_EQ_INT(g_reply_len, 4 + 1 + 4 + 4 + 5); /* "hello" */
	TCT_EQ_MEM(g_reply + 13, "hello", 5);

	/* Past the end is EOF, not an error and not a short read of nothing. */
	req.offset = 5;
	TCT_EQ_INT(status_of(&fs, &req), TC_SFTP_FX_EOF);

	/* A client asking for more than we will hand back gets a short read,
	 * which is legal, rather than a 4GB allocation. */
	req.offset = 0;
	req.length = 0xFFFFFFFFu;
	TCT_EQ_INT(run(&fs, &req), TC_OK);
	TCT_EQ_INT(g_reply[4], TC_SFTP_DATA);

	req_init(&req, TC_SFTP_CLOSE, NULL);
	memcpy(req.handle, h, sizeof h);
	req.has_handle = true;
	TCT_EQ_INT(status_of(&fs, &req), TC_SFTP_FX_OK);

	/* And the handle is gone afterwards. */
	req_init(&req, TC_SFTP_READ, NULL);
	memcpy(req.handle, h, sizeof h);
	req.has_handle = true;
	req.length = 10;
	TCT_EQ_INT(status_of(&fs, &req), TC_SFTP_FX_FAILURE);

	tc_fileserv_close(&fs);
}

static void test_handles_are_not_guessable_or_reusable(void)
{
	TCT_CASE("handles");
	tc_fileserv fs;
	TCT_EQ_INT(tc_fileserv_open(&fs, g_root, false), TC_OK);

	tc_sftp_request req;

	/* No handle at all. */
	req_init(&req, TC_SFTP_READ, NULL);
	req.length = 10;
	TCT_EQ_INT(status_of(&fs, &req), TC_SFTP_FX_FAILURE);

	/* A handle that was never issued. */
	req.has_handle = true;
	memset(req.handle, 0xAB, sizeof req.handle);
	TCT_EQ_INT(status_of(&fs, &req), TC_SFTP_FX_FAILURE);

	/* All zeroes, which is what an uninitialised client sends. Handles start
	 * at 1 precisely so this is never valid. */
	memset(req.handle, 0, sizeof req.handle);
	TCT_EQ_INT(status_of(&fs, &req), TC_SFTP_FX_FAILURE);

	/* A directory handle used for READ, and a file handle for READDIR. */
	uint8_t dirh[TC_SFTP_HANDLE_LEN], fileh[TC_SFTP_HANDLE_LEN];
	TCT_TRUE(open_handle(&fs, TC_SFTP_OPENDIR, "sub", 0, dirh));
	TCT_TRUE(
	    open_handle(&fs, TC_SFTP_OPEN, "hello.txt", TC_SFTP_FXF_READ, fileh));

	req_init(&req, TC_SFTP_READ, NULL);
	memcpy(req.handle, dirh, sizeof dirh);
	req.has_handle = true;
	req.length = 10;
	TCT_EQ_INT(status_of(&fs, &req), TC_SFTP_FX_FAILURE);

	req_init(&req, TC_SFTP_READDIR, NULL);
	memcpy(req.handle, fileh, sizeof fileh);
	req.has_handle = true;
	TCT_EQ_INT(status_of(&fs, &req), TC_SFTP_FX_FAILURE);

	/* Exhausting the table is a refusal, not a crash or a leak. */
	uint8_t junk[TC_SFTP_HANDLE_LEN];
	int opened = 2;
	while (opened < TC_FILESERV_MAX_HANDLES &&
	       open_handle(&fs, TC_SFTP_OPEN, "hello.txt", TC_SFTP_FXF_READ,
	                   junk))
		opened++;
	TCT_EQ_INT(opened, TC_FILESERV_MAX_HANDLES);
	req_init(&req, TC_SFTP_OPEN, "hello.txt");
	req.pflags = TC_SFTP_FXF_READ;
	TCT_EQ_INT(status_of(&fs, &req), TC_SFTP_FX_FAILURE);

	/* tc_fileserv_close has to release all of them; if it does not, the
	 * next test in this process runs short of descriptors. */
	tc_fileserv_close(&fs);
	TCT_EQ_INT(tc_fileserv_open(&fs, g_root, false), TC_OK);
	TCT_TRUE(open_handle(&fs, TC_SFTP_OPEN, "hello.txt", TC_SFTP_FXF_READ,
	                     junk));
	tc_fileserv_close(&fs);
}

static void test_listing(void)
{
	TCT_CASE("readdir");
	tc_fileserv fs;
	TCT_EQ_INT(tc_fileserv_open(&fs, g_root, false), TC_OK);

	uint8_t h[TC_SFTP_HANDLE_LEN];
	TCT_TRUE(open_handle(&fs, TC_SFTP_OPENDIR, "/", 0, h));

	bool saw_hello = false, saw_sub = false, saw_link = false;
	int guard = 0;
	for (;;) {
		tc_sftp_request req;
		req_init(&req, TC_SFTP_READDIR, NULL);
		memcpy(req.handle, h, sizeof h);
		req.has_handle = true;
		if (run(&fs, &req) != TC_OK) {
			TCT_FAILF("READDIR failed mid-listing");
			break;
		}
		if (g_reply[4] == TC_SFTP_STATUS)
			break; /* EOF */
		TCT_EQ_INT(g_reply[4], TC_SFTP_NAME);

		/* NAME: length, type, id, count, then string name. */
		const uint8_t *p = g_reply + 13;
		uint32_t n = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
		             (uint32_t)p[2] << 8 | p[3];
		char name[256] = {0};
		if (n < sizeof name)
			memcpy(name, p + 4, n);
		if (strcmp(name, "hello.txt") == 0)
			saw_hello = true;
		else if (strcmp(name, "sub") == 0)
			saw_sub = true;
		else if (strcmp(name, "escape.txt") == 0 ||
		         strcmp(name, "inside.txt") == 0 ||
		         strcmp(name, "updir") == 0)
			saw_link = true;
		/* "." and ".." are never listed: a client that followed ".." from a
		 * listing would be asking for something the resolver refuses, and a
		 * listing should not advertise what it will not serve. */
		TCT_TRUE(strcmp(name, ".") != 0 && strcmp(name, "..") != 0);

		if (++guard > 100) {
			TCT_FAILF("READDIR never reported EOF");
			break;
		}
	}
	TCT_TRUE(saw_hello);
	TCT_TRUE(saw_sub);
	TCT_TRUE(!saw_link); /* symlinks are not served, so not advertised */

	/* After EOF it stays at EOF rather than starting over. */
	tc_sftp_request req;
	req_init(&req, TC_SFTP_READDIR, NULL);
	memcpy(req.handle, h, sizeof h);
	req.has_handle = true;
	TCT_EQ_INT(status_of(&fs, &req), TC_SFTP_FX_EOF);

	/* A directory outside the root cannot be listed either. */
	uint8_t bad[TC_SFTP_HANDLE_LEN];
	TCT_TRUE(!open_handle(&fs, TC_SFTP_OPENDIR, "../outside", 0, bad));

	tc_fileserv_close(&fs);
}

static void test_stat_and_realpath(void)
{
	TCT_CASE("stat");
	tc_fileserv fs;
	TCT_EQ_INT(tc_fileserv_open(&fs, g_root, false), TC_OK);

	tc_sftp_request req;
	req_init(&req, TC_SFTP_STAT, "hello.txt");
	TCT_EQ_INT(run(&fs, &req), TC_OK);
	TCT_EQ_INT(g_reply[4], TC_SFTP_ATTRS);

	/* A directory stats too -- sftp calls STAT on the remote path before it
	 * decides whether to cd into it, so a server that only stats files
	 * cannot be cd'd into. */
	req_init(&req, TC_SFTP_STAT, "sub");
	TCT_EQ_INT(run(&fs, &req), TC_OK);
	TCT_EQ_INT(g_reply[4], TC_SFTP_ATTRS);

	req_init(&req, TC_SFTP_STAT, "../outside/secret.txt");
	int st = status_of(&fs, &req);
	TCT_TRUE(st == TC_SFTP_FX_NO_SUCH_FILE ||
	         st == TC_SFTP_FX_PERMISSION_DENIED);

	req_init(&req, TC_SFTP_STAT, "nope.txt");
	TCT_EQ_INT(status_of(&fs, &req), TC_SFTP_FX_NO_SUCH_FILE);

	/* REALPATH answers in the client's coordinates, where the root is "/",
	 * and never leaks the server's actual directory. */
	static const char *const asked[] = {".", "/", "", "sub", "/sub"};
	static const char *const want[] = {"/", "/", "/", "/sub", "/sub"};
	for (size_t i = 0; i < sizeof asked / sizeof asked[0]; i++) {
		req_init(&req, TC_SFTP_REALPATH, asked[i]);
		TCT_EQ_INT(run(&fs, &req), TC_OK);
		TCT_EQ_INT(g_reply[4], TC_SFTP_NAME);
		const uint8_t *p = g_reply + 13;
		uint32_t n = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
		             (uint32_t)p[2] << 8 | p[3];
		char name[256] = {0};
		if (n < sizeof name)
			memcpy(name, p + 4, n);
		TCT_EQ_STR(name, want[i]);
	}

	tc_fileserv_close(&fs);
}

static void test_bad_arguments(void)
{
	TCT_CASE("arguments");
	tc_fileserv fs;
	TCT_EQ_INT(tc_fileserv_open(&fs, g_root, false), TC_OK);

	tc_sftp_request req;
	req_init(&req, TC_SFTP_STAT, "hello.txt");
	uint8_t reply[64];
	size_t len = 0;
	TCT_EQ_INT(tc_fileserv_handle_req(NULL, &req, reply, sizeof reply, &len),
	           TC_ERR_INVAL);
	TCT_EQ_INT(tc_fileserv_handle_req(&fs, NULL, reply, sizeof reply, &len),
	           TC_ERR_INVAL);
	TCT_EQ_INT(tc_fileserv_handle_req(&fs, &req, NULL, sizeof reply, &len),
	           TC_ERR_INVAL);
	TCT_EQ_INT(tc_fileserv_handle_req(&fs, &req, reply, sizeof reply, NULL),
	           TC_ERR_INVAL);

	/* An unknown request type is refused, not dispatched. */
	req_init(&req, 200, "hello.txt");
	TCT_EQ_INT(status_of(&fs, &req), TC_SFTP_FX_FAILURE);

	/* A path far longer than any component. */
	char deep[TC_SFTP_MAX_PATH];
	size_t at = 0;
	while (at + 4 < sizeof deep - 1) {
		memcpy(deep + at, "sub/", 4);
		at += 4;
	}
	deep[at] = '\0';
	refuses(&fs, deep, "a path deeper than the component limit");

	tc_fileserv_close(&fs);

	/* Opening a directory that is not one, or does not exist. */
	TCT_TRUE(tc_fileserv_open(&fs, "/nonexistent/nowhere", false) != TC_OK);
	TCT_EQ_INT(tc_fileserv_open(NULL, g_root, false), TC_ERR_INVAL);
	TCT_EQ_INT(tc_fileserv_open(&fs, NULL, false), TC_ERR_INVAL);
	tc_fileserv_close(NULL); /* must not crash */
}

int main(void)
{
	setup();
	test_the_root_itself_works();
	test_nothing_escapes();
	test_symlinks_are_refused_not_resolved();
	test_read_only_means_read_only();
	test_symlinks_are_refused_even_writable();
	test_writable_writes();
	test_reading_a_file();
	test_handles_are_not_guessable_or_reusable();
	test_listing();
	test_stat_and_realpath();
	test_bad_arguments();
	return tct_report("fileserv");
}
