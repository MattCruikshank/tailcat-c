/* SPDX-License-Identifier: BSD-3-Clause
 *
 * The write-only drop box.
 *
 * The guarantee this file exists to defend is one sentence: **a sender cannot
 * choose the stored filename.** Everything else -- no reads, no listings, no
 * overwrites, no traversal -- either follows from it or guards it.
 *
 * So the tests are written as the attacks rather than as the features. Each
 * one is something a sender might try, and the check is that it does not
 * work. The happy path gets one test; the refusals get the rest.
 *
 * tc_dropbox_safe_name is exercised directly and heavily, because it is the
 * function the guarantee actually rests on, and because the inputs that break
 * it are much easier to write down than to provoke through a real client.
 */

#include "tc/dropbox.h"

#include "tctest.h"

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ---- the name sanitiser ------------------------------------------------ */

static void check_refused(const char *path, const char *why)
{
	char out[TC_DROPBOX_MAX_NAME + 1];
	tct_checks++;
	if (tc_dropbox_safe_name(path, out, sizeof out))
		TCT_FAILF("accepted %s (%s), storing it as \"%s\"", path, why, out);
}

static void check_becomes(const char *path, const char *want)
{
	char out[TC_DROPBOX_MAX_NAME + 1];
	tct_checks++;
	if (!tc_dropbox_safe_name(path, out, sizeof out)) {
		TCT_FAILF("refused %s, which should be usable", path);
		return;
	}
	if (strcmp(out, want) != 0)
		TCT_FAILF("%s became \"%s\", want \"%s\"", path, out, want);
}

static void test_traversal_is_impossible(void)
{
	TCT_CASE("a path is reduced to its last component");
	/* This single rule defeats every traversal at once, which is why it is
	 * the rule rather than a list of forbidden sequences. */
	check_becomes("file.txt", "file.txt");
	check_becomes("/etc/passwd", "passwd");
	check_becomes("../../../etc/passwd", "passwd");
	check_becomes("/../../file.txt", "file.txt");
	check_becomes("dir/sub/deep.bin", "deep.bin");
	check_becomes("./file.txt", "file.txt");

	TCT_CASE("and backslashes count as separators too");
	/* A client on Windows sends these, and a client trying to escape sends
	 * whichever separator the server forgot to check. */
	check_becomes("C:\\windows\\system32\\evil.dll", "evil.dll");
	check_becomes("..\\..\\file.txt", "file.txt");
	check_becomes("dir\\sub/mixed.txt", "mixed.txt");
	/* And doubled, which is what a client that escaped them once too often
	 * sends -- still separators, still nothing to escape with. */
	check_becomes("..\\\\..\\\\file.txt", "file.txt");

	TCT_CASE("a path with nothing usable at the end is refused");
	check_refused("", "empty");
	check_refused("/", "a bare separator");
	check_refused("dir/", "a trailing separator");
	check_refused(".", "the current directory");
	check_refused("..", "the parent directory");
	check_refused("foo/..", "a parent at the end");
	check_refused("a/b/", "a trailing separator after components");
}

static void test_dangerous_names_are_refused(void)
{
	TCT_CASE("control bytes are refused");
	/* A name a terminal renders as something other than what it is. */
	check_refused("ev\til.txt", "a tab");
	check_refused("ev\nil.txt", "a newline");
	check_refused("\033[2Kevil.txt", "an escape sequence");
	check_refused("evil\x7f.txt", "a DEL");

	TCT_CASE("Windows device names are refused, with or without a suffix");
	/* This binary runs on Windows, where opening "CON.txt" opens the console
	 * rather than creating a file -- so this is not a Unix server's optional
	 * politeness. */
	check_refused("nul", "a device name");
	check_refused("NUL", "a device name in capitals");
	check_refused("NuL.txt", "a device name with an extension");
	check_refused("con", "the console");
	check_refused("COM1.dat", "a serial port");
	check_refused("lpt9", "a printer port");
	/* But names that merely start the same way are fine. */
	check_becomes("nullable.txt", "nullable.txt");
	check_becomes("console.log", "console.log");
	check_becomes("com10.txt", "com10.txt");

	TCT_CASE("a trailing dot or space is refused");
	/* Windows strips both before opening, so "evil. " and "evil" are one
	 * file there and two names here -- which is exactly how "cannot
	 * overwrite" quietly becomes "can". */
	check_refused("evil.", "a trailing dot");
	check_refused("evil ", "a trailing space");
	check_refused("evil.txt.", "a trailing dot after an extension");

	TCT_CASE("characters Windows forbids are refused everywhere");
	/* One name means one thing on every platform we ship to, which is worth
	 * more than accepting a few extra names on Unix. */
	check_refused("a:b.txt", "a colon");
	check_refused("a*b.txt", "a wildcard");
	check_refused("a?b.txt", "a wildcard");
	check_refused("a\"b.txt", "a quote");
	check_refused("a<b.txt", "a redirect");
	check_refused("a|b.txt", "a pipe");

	TCT_CASE("an over-long name is refused rather than truncated");
	/* Truncating would map many names onto one, and two senders' files onto
	 * one file. */
	char longname[TC_DROPBOX_MAX_NAME + 64];
	memset(longname, 'a', sizeof longname - 1);
	longname[sizeof longname - 1] = '\0';
	check_refused(longname, "too long");

	TCT_CASE("ordinary names survive");
	check_becomes("report.pdf", "report.pdf");
	check_becomes("a-file_with.many.dots.tar.gz", "a-file_with.many.dots.tar.gz");
	check_becomes(".hidden", ".hidden");
	check_becomes("...leading-dots.txt", "...leading-dots.txt");
	/* Unicode is not a security problem and refusing it would be rude. */
	check_becomes("\xc3\xa9t\xc3\xa9.txt", "\xc3\xa9t\xc3\xa9.txt");
}

/* ---- the protocol policy ----------------------------------------------- */

static char g_dir[256];

static bool make_tmpdir(void)
{
	snprintf(g_dir, sizeof g_dir, "/tmp/tc_dropbox_XXXXXX");
	return mkdtemp(g_dir) != NULL;
}

/* ask runs one request and returns the status code, or -1 if the reply was
 * not a STATUS. */
static int ask(tc_dropbox *db, tc_sftp_request *req, uint8_t *reply,
               size_t cap, size_t *reply_len)
{
	if (tc_dropbox_handle(db, req, reply, cap, reply_len) != TC_OK)
		return -2;
	if (*reply_len < 9 || reply[4] != TC_SFTP_STATUS)
		return -1;
	return (int)((uint32_t)reply[9] << 24 | (uint32_t)reply[10] << 16 |
	             (uint32_t)reply[11] << 8 | reply[12]);
}

static void init_box(tc_dropbox *db)
{
	TCT_EQ_INT(tc_dropbox_open(db, g_dir), TC_OK);
	tc_sftp_request req;
	memset(&req, 0, sizeof req);
	req.type = TC_SFTP_INIT;
	req.version = 3;
	uint8_t reply[256];
	size_t n = 0;
	TCT_EQ_INT(tc_dropbox_handle(db, &req, reply, sizeof reply, &n), TC_OK);
	TCT_EQ_INT(reply[4], TC_SFTP_VERSION_MSG);
}

static void test_everything_that_reads_is_refused(void)
{
	TCT_CASE("every request that could read or mutate is refused");
	tc_dropbox db;
	init_box(&db);

	/* Each of these is a way to turn a drop box into something else. MKDIR
	 * is in the list because a sender who can make directories can choose
	 * names again, which is the guarantee itself. */
	static const uint8_t forbidden[] = {
		TC_SFTP_READ,   TC_SFTP_OPENDIR, TC_SFTP_READDIR,  TC_SFTP_REMOVE,
		TC_SFTP_RMDIR,  TC_SFTP_MKDIR,   TC_SFTP_RENAME,   TC_SFTP_SYMLINK,
		TC_SFTP_READLINK,
	};
	for (size_t i = 0; i < sizeof forbidden / sizeof *forbidden; i++) {
		tc_sftp_request req;
		memset(&req, 0, sizeof req);
		req.type = forbidden[i];
		req.id = (uint32_t)i;
		snprintf(req.path, sizeof req.path, "anything");
		uint8_t reply[512];
		size_t n = 0;
		int code = ask(&db, &req, reply, sizeof reply, &n);
		if (code != TC_SFTP_FX_PERMISSION_DENIED)
			TCT_FAILF("request type %u was not refused (status %d)",
			          forbidden[i], code);
	}
	tct_checks++;

	TCT_CASE("opening for reading is refused");
	tc_sftp_request req;
	memset(&req, 0, sizeof req);
	req.type = TC_SFTP_OPEN;
	req.id = 99;
	snprintf(req.path, sizeof req.path, "file.txt");
	req.pflags = TC_SFTP_FXF_READ;
	uint8_t reply[512];
	size_t n = 0;
	TCT_EQ_INT(ask(&db, &req, reply, sizeof reply, &n),
	           TC_SFTP_FX_PERMISSION_DENIED);

	TCT_CASE("and so is opening for both reading and writing");
	/* The interesting case: a client that asks for read|write must not get
	 * read access smuggled in on the strength of the write bit. */
	req.pflags = TC_SFTP_FXF_READ | TC_SFTP_FXF_WRITE | TC_SFTP_FXF_CREAT;
	TCT_EQ_INT(ask(&db, &req, reply, sizeof reply, &n),
	           TC_SFTP_FX_PERMISSION_DENIED);

	tc_dropbox_close(&db);
}

static void test_stat_reveals_nothing(void)
{
	TCT_CASE("stat on an existing file still says it does not exist");
	/* Answering truthfully would make stat a directory listing one name at a
	 * time: a sender could confirm a guess without ever reading anything. */
	char path[512];
	snprintf(path, sizeof path, "%s/secret.txt", g_dir);
	FILE *f = fopen(path, "w");
	TCT_TRUE(f != NULL);
	if (f != NULL) {
		fputs("shh", f);
		fclose(f);
	}

	tc_dropbox db;
	init_box(&db);

	tc_sftp_request req;
	memset(&req, 0, sizeof req);
	req.type = TC_SFTP_STAT;
	req.id = 1;
	snprintf(req.path, sizeof req.path, "secret.txt");
	uint8_t reply[512];
	size_t n = 0;
	TCT_EQ_INT(ask(&db, &req, reply, sizeof reply, &n),
	           TC_SFTP_FX_NO_SUCH_FILE);

	TCT_CASE("and gives the same answer for one that really does not");
	/* Same code for both, so the two cases are indistinguishable. */
	snprintf(req.path, sizeof req.path, "absent.txt");
	TCT_EQ_INT(ask(&db, &req, reply, sizeof reply, &n),
	           TC_SFTP_FX_NO_SUCH_FILE);

	TCT_CASE("but the root is a directory, which clients need to know");
	snprintf(req.path, sizeof req.path, ".");
	TCT_EQ_INT(tc_dropbox_handle(&db, &req, reply, sizeof reply, &n), TC_OK);
	TCT_EQ_INT(reply[4], TC_SFTP_ATTRS);

	tc_dropbox_close(&db);
	(void)unlink(path);
}

static void test_uploads_never_overwrite(void)
{
	TCT_CASE("a second file of the same name does not replace the first");
	char path[512];
	snprintf(path, sizeof path, "%s/dup.txt", g_dir);
	FILE *f = fopen(path, "w");
	TCT_TRUE(f != NULL);
	if (f != NULL) {
		fputs("original", f);
		fclose(f);
	}

	tc_dropbox db;
	init_box(&db);

	tc_sftp_request req;
	memset(&req, 0, sizeof req);
	req.type = TC_SFTP_OPEN;
	req.id = 1;
	snprintf(req.path, sizeof req.path, "dup.txt");
	req.pflags = TC_SFTP_FXF_WRITE | TC_SFTP_FXF_CREAT | TC_SFTP_FXF_TRUNC;
	uint8_t reply[512];
	size_t n = 0;
	TCT_EQ_INT(tc_dropbox_handle(&db, &req, reply, sizeof reply, &n), TC_OK);
	TCT_EQ_INT(reply[4], TC_SFTP_HANDLE);

	uint8_t handle[TC_SFTP_HANDLE_LEN];
	memcpy(handle, reply + 13, TC_SFTP_HANDLE_LEN);

	memset(&req, 0, sizeof req);
	req.type = TC_SFTP_WRITE;
	req.id = 2;
	req.has_handle = true;
	memcpy(req.handle, handle, sizeof handle);
	req.data = (const uint8_t *)"replacement";
	req.data_len = 11;
	TCT_EQ_INT(ask(&db, &req, reply, sizeof reply, &n), TC_SFTP_FX_OK);

	memset(&req, 0, sizeof req);
	req.type = TC_SFTP_CLOSE;
	req.id = 3;
	req.has_handle = true;
	memcpy(req.handle, handle, sizeof handle);
	TCT_EQ_INT(ask(&db, &req, reply, sizeof reply, &n), TC_SFTP_FX_OK);

	/* The original is untouched... */
	char buf[64] = { 0 };
	f = fopen(path, "r");
	TCT_TRUE(f != NULL);
	if (f != NULL) {
		size_t got = fread(buf, 1, sizeof buf - 1, f);
		buf[got] = '\0';
		fclose(f);
	}
	TCT_EQ_STR(buf, "original");

	TCT_CASE("and the new one landed under a name the server chose");
	char alt[512];
	snprintf(alt, sizeof alt, "%s/dup.txt.1", g_dir);
	f = fopen(alt, "r");
	TCT_TRUE(f != NULL);
	if (f != NULL) {
		memset(buf, 0, sizeof buf);
		size_t got = fread(buf, 1, sizeof buf - 1, f);
		buf[got] = '\0';
		fclose(f);
		TCT_EQ_STR(buf, "replacement");
		(void)unlink(alt);
	}

	tc_dropbox_close(&db);
	(void)unlink(path);
}

static void test_handles(void)
{
	TCT_CASE("a stale handle does not address the next file");
	/* Without a generation in the handle, a client that closed one file and
	 * opened another would find its old handle pointing at the new one, and
	 * the write meant for the first would land in the second. */
	tc_dropbox db;
	init_box(&db);

	tc_sftp_request req;
	uint8_t reply[512];
	size_t n = 0;

	memset(&req, 0, sizeof req);
	req.type = TC_SFTP_OPEN;
	req.id = 1;
	snprintf(req.path, sizeof req.path, "first.txt");
	req.pflags = TC_SFTP_FXF_WRITE | TC_SFTP_FXF_CREAT;
	TCT_EQ_INT(tc_dropbox_handle(&db, &req, reply, sizeof reply, &n), TC_OK);
	uint8_t stale[TC_SFTP_HANDLE_LEN];
	memcpy(stale, reply + 13, sizeof stale);

	memset(&req, 0, sizeof req);
	req.type = TC_SFTP_CLOSE;
	req.id = 2;
	req.has_handle = true;
	memcpy(req.handle, stale, sizeof stale);
	TCT_EQ_INT(ask(&db, &req, reply, sizeof reply, &n), TC_SFTP_FX_OK);

	memset(&req, 0, sizeof req);
	req.type = TC_SFTP_OPEN;
	req.id = 3;
	snprintf(req.path, sizeof req.path, "second.txt");
	req.pflags = TC_SFTP_FXF_WRITE | TC_SFTP_FXF_CREAT;
	TCT_EQ_INT(tc_dropbox_handle(&db, &req, reply, sizeof reply, &n), TC_OK);
	uint8_t fresh[TC_SFTP_HANDLE_LEN];
	memcpy(fresh, reply + 13, sizeof fresh);

	/* The two handles must differ, and the old one must not work. */
	TCT_TRUE(memcmp(stale, fresh, sizeof stale) != 0);
	memset(&req, 0, sizeof req);
	req.type = TC_SFTP_WRITE;
	req.id = 4;
	req.has_handle = true;
	memcpy(req.handle, stale, sizeof stale);
	req.data = (const uint8_t *)"wrong file";
	req.data_len = 10;
	TCT_EQ_INT(ask(&db, &req, reply, sizeof reply, &n), TC_SFTP_FX_FAILURE);

	TCT_CASE("an invented handle does not work either");
	uint8_t invented[TC_SFTP_HANDLE_LEN];
	memset(invented, 0, sizeof invented);
	memcpy(req.handle, invented, sizeof invented);
	TCT_EQ_INT(ask(&db, &req, reply, sizeof reply, &n), TC_SFTP_FX_FAILURE);

	tc_dropbox_close(&db);
	char p[512];
	snprintf(p, sizeof p, "%s/first.txt", g_dir);
	(void)unlink(p);
	snprintf(p, sizeof p, "%s/second.txt", g_dir);
	(void)unlink(p);
}

static void test_write_bounds(void)
{
	TCT_CASE("a write at an absurd offset is refused");
	/* Sparse files make a petabyte cheap to ask for and expensive to host,
	 * and the offset is entirely the sender's to choose. */
	tc_dropbox db;
	init_box(&db);

	tc_sftp_request req;
	uint8_t reply[512];
	size_t n = 0;
	memset(&req, 0, sizeof req);
	req.type = TC_SFTP_OPEN;
	req.id = 1;
	snprintf(req.path, sizeof req.path, "big.bin");
	req.pflags = TC_SFTP_FXF_WRITE | TC_SFTP_FXF_CREAT;
	TCT_EQ_INT(tc_dropbox_handle(&db, &req, reply, sizeof reply, &n), TC_OK);
	uint8_t handle[TC_SFTP_HANDLE_LEN];
	memcpy(handle, reply + 13, sizeof handle);

	memset(&req, 0, sizeof req);
	req.type = TC_SFTP_WRITE;
	req.id = 2;
	req.has_handle = true;
	memcpy(req.handle, handle, sizeof handle);
	req.data = (const uint8_t *)"x";
	req.data_len = 1;
	req.offset = UINT64_MAX - 16;
	TCT_EQ_INT(ask(&db, &req, reply, sizeof reply, &n), TC_SFTP_FX_FAILURE);

	TCT_CASE("and one just past the cap, without wrapping");
	req.offset = TC_DROPBOX_MAX_FILE;
	TCT_EQ_INT(ask(&db, &req, reply, sizeof reply, &n), TC_SFTP_FX_FAILURE);

	TCT_CASE("but an ordinary one is allowed");
	req.offset = 0;
	TCT_EQ_INT(ask(&db, &req, reply, sizeof reply, &n), TC_SFTP_FX_OK);

	tc_dropbox_close(&db);
	char p[512];
	snprintf(p, sizeof p, "%s/big.bin", g_dir);
	(void)unlink(p);
}

static void test_init_is_required(void)
{
	TCT_CASE("nothing is served before INIT");
	/* Without a version agreed, nothing after it has an agreed meaning. */
	tc_dropbox db;
	TCT_EQ_INT(tc_dropbox_open(&db, g_dir), TC_OK);

	tc_sftp_request req;
	memset(&req, 0, sizeof req);
	req.type = TC_SFTP_OPEN;
	req.id = 1;
	snprintf(req.path, sizeof req.path, "file.txt");
	req.pflags = TC_SFTP_FXF_WRITE | TC_SFTP_FXF_CREAT;
	uint8_t reply[512];
	size_t n = 0;
	TCT_EQ_INT(ask(&db, &req, reply, sizeof reply, &n),
	           TC_SFTP_FX_BAD_MESSAGE);

	TCT_CASE("a version older than 3 is refused");
	memset(&req, 0, sizeof req);
	req.type = TC_SFTP_INIT;
	req.version = 2;
	TCT_EQ_INT(tc_dropbox_handle(&db, &req, reply, sizeof reply, &n),
	           TC_ERR_UNSUPPORTED);

	TCT_CASE("and a newer one negotiates down to ours");
	/* The draft has the client fall back to the server's version, so
	 * answering 3 is the negotiation. */
	req.version = 6;
	TCT_EQ_INT(tc_dropbox_handle(&db, &req, reply, sizeof reply, &n), TC_OK);
	TCT_EQ_INT(reply[4], TC_SFTP_VERSION_MSG);
	TCT_EQ_INT(reply[8], TC_SFTP_VERSION);

	tc_dropbox_close(&db);
}

int main(void)
{
	if (!make_tmpdir()) {
		fprintf(stderr, "test_dropbox: could not make a temp directory\n");
		return 1;
	}
	test_traversal_is_impossible();
	test_dangerous_names_are_refused();
	test_everything_that_reads_is_refused();
	test_stat_reveals_nothing();
	test_uploads_never_overwrite();
	test_handles();
	test_write_bounds();
	test_init_is_required();
	(void)rmdir(g_dir);
	return tct_report("dropbox");
}
