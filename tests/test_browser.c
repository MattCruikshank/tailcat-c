/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Opening a browser.
 *
 * Almost all of this file is about the two places the feature can go wrong in
 * a way nobody notices until it matters: the argv handed to an opener, and
 * the decision not to open one at all. The fork-and-exec is four lines and
 * the only part that cannot be tested without a desktop; everything that
 * decides *what* gets exec'd is a pure function, which is why it is shaped
 * that way.
 */

#include "tc/browser.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "tctest.h"

/* joined renders a command as one string so a whole argv can be compared in
 * one assertion. Spaces separate arguments, which is ambiguous in general and
 * exact here, because no expected argv in this file contains one. */
static const char *joined(const tc_browser_cmd *c)
{
	static char buf[TC_BROWSER_BUF * 2];
	size_t w = 0;

	buf[0] = '\0';
	for (size_t i = 0; i < c->argc; i++) {
		int n = snprintf(buf + w, sizeof buf - w, "%s%s", i ? " " : "",
		                 c->argv[i]);
		if (n < 0 || (size_t)n >= sizeof buf - w)
			break;
		w += (size_t)n;
	}
	return buf;
}

static void test_url(void)
{
	char u[TC_BROWSER_BUF];

	TCT_CASE("an ordinary loopback listener");
	TCT_EQ_INT(tc_browser_url(u, sizeof u, "127.0.0.1", 8080), TC_OK);
	TCT_EQ_STR(u, "http://127.0.0.1:8080/");

	TCT_CASE("a listener on every interface becomes the loopback one");
	/* http://0.0.0.0/ is not somewhere a browser can go, and the listener
	 * is reachable on 127.0.0.1 by construction. */
	TCT_EQ_INT(tc_browser_url(u, sizeof u, "0.0.0.0", 1), TC_OK);
	TCT_EQ_STR(u, "http://127.0.0.1:1/");

	TCT_CASE("another interface is left alone");
	TCT_EQ_INT(tc_browser_url(u, sizeof u, "192.168.1.10", 443), TC_OK);
	TCT_EQ_STR(u, "http://192.168.1.10:443/");

	TCT_CASE("the whole port range renders");
	TCT_EQ_INT(tc_browser_url(u, sizeof u, "127.0.0.1", 65535), TC_OK);
	TCT_EQ_STR(u, "http://127.0.0.1:65535/");
	TCT_EQ_INT(tc_browser_url(u, sizeof u, "127.0.0.1", 0), TC_OK);
	TCT_EQ_STR(u, "http://127.0.0.1:0/");
}

static void test_url_refuses(void)
{
	char u[TC_BROWSER_BUF];

	/* The point of building the URL in one place is that nothing else can
	 * ever hand an opener a string this program did not construct. These are
	 * the inputs that would let one through. */

	TCT_CASE("a hostname is refused rather than resolved");
	TCT_EQ_INT(tc_browser_url(u, sizeof u, "localhost", 80), TC_ERR_INVAL);

	TCT_CASE("an IPv6 literal is refused");
	/* forward's listen address goes through inet_pton(AF_INET), so this
	 * cannot arrive today. It is refused anyway, because "cannot arrive
	 * today" is a property of a different file. */
	TCT_EQ_INT(tc_browser_url(u, sizeof u, "::1", 80), TC_ERR_INVAL);

	TCT_CASE("anything with a shell or URL metacharacter in it");
	static const char *const bad[] = {
		"127.0.0.1 &calc",  "127.0.0.1;id",     "127.0.0.1/../x",
		"127.0.0.1\"",      "127.0.0.1'",       "127.0.0.1\n",
		"127.0.0.1@evil",   "127.0.0.1#",       "127.0.0.1?x=1",
		"$(id)",            "`id`",             "",
	};
	for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
		TCT_EQ_INT(tc_browser_url(u, sizeof u, bad[i], 80), TC_ERR_INVAL);

	TCT_CASE("a near-miss dotted quad");
	/* Each of these parses as four numbers under a sloppier reading. */
	static const char *const near[] = {
		"127.0.0.256", "127.0.0.1.2", "127.0.0",   "127.0.0.",
		".1.2.3.4",    "127.0.0.01a", "127.0.0.1 ", " 127.0.0.1",
		"127.0.0.0001",
	};
	for (size_t i = 0; i < sizeof near / sizeof near[0]; i++)
		TCT_EQ_INT(tc_browser_url(u, sizeof u, near[i], 80), TC_ERR_INVAL);

	TCT_CASE("leading zeroes are not read as octal");
	/* inet_aton would call 127.0.0.010 port 8, which is a different host
	 * from the one the user typed. Three digits are allowed, so this has to
	 * be checked rather than fallen into. */
	TCT_EQ_INT(tc_browser_url(u, sizeof u, "127.0.0.010", 80), TC_OK);
	TCT_EQ_STR(u, "http://127.0.0.10:80/");

	TCT_CASE("a NULL or zero-length destination");
	TCT_EQ_INT(tc_browser_url(u, 0, "127.0.0.1", 80), TC_ERR_INVAL);
	TCT_EQ_INT(tc_browser_url(NULL, 16, "127.0.0.1", 80), TC_ERR_INVAL);
	TCT_EQ_INT(tc_browser_url(u, sizeof u, NULL, 80), TC_ERR_INVAL);

	TCT_CASE("a destination too small for the result");
	char tiny[10];
	TCT_EQ_INT(tc_browser_url(tiny, sizeof tiny, "127.0.0.1", 8080),
	           TC_ERR_NOSPACE);
}

static void test_defaults(void)
{
	tc_browser_cmd c;
	const char *url = "http://127.0.0.1:8080/";

	TCT_CASE("macOS uses open");
	TCT_EQ_INT(tc_browser_default(&c, TC_OS_MACOS, 0, url), TC_OK);
	TCT_EQ_STR(joined(&c), "open http://127.0.0.1:8080/");
	TCT_EQ_INT(tc_browser_default(&c, TC_OS_MACOS, 1, url), TC_ERR_DONE);

	TCT_CASE("Linux and the BSDs use xdg-open, then gio");
	static const tc_os unixy[] = { TC_OS_LINUX, TC_OS_FREEBSD, TC_OS_OPENBSD,
		                           TC_OS_NETBSD };
	for (size_t i = 0; i < sizeof unixy / sizeof unixy[0]; i++) {
		TCT_EQ_INT(tc_browser_default(&c, unixy[i], 0, url), TC_OK);
		TCT_EQ_STR(joined(&c), "xdg-open http://127.0.0.1:8080/");
		TCT_EQ_INT(tc_browser_default(&c, unixy[i], 1, url), TC_OK);
		TCT_EQ_STR(joined(&c), "gio open http://127.0.0.1:8080/");
		TCT_EQ_INT(tc_browser_default(&c, unixy[i], 2, url), TC_ERR_DONE);
	}

	TCT_CASE("no candidate is ever the bare name `open` off macOS");
	/* On Linux that name belongs to util-linux and switches virtual
	 * terminals, which is a memorable way to fail. */
	for (size_t i = 0; i < sizeof unixy / sizeof unixy[0]; i++) {
		for (size_t k = 0; tc_browser_default(&c, unixy[i], k, url) == TC_OK;
		     k++)
			TCT_TRUE(strcmp(c.argv[0], "open") != 0);
	}

	TCT_CASE("Windows tries rundll32 before cmd");
	TCT_EQ_INT(tc_browser_default(&c, TC_OS_WINDOWS, 0, url), TC_OK);
	TCT_EQ_STR(joined(&c),
	           "rundll32.exe url.dll,FileProtocolHandler "
	           "http://127.0.0.1:8080/");
	TCT_EQ_INT(tc_browser_default(&c, TC_OS_WINDOWS, 1, url), TC_OK);
	TCT_EQ_STR(joined(&c), "cmd.exe /c start  http://127.0.0.1:8080/");
	TCT_EQ_INT(tc_browser_default(&c, TC_OS_WINDOWS, 2, url), TC_ERR_DONE);

	TCT_CASE("start gets its empty title argument");
	/* Without it, `start <url>` reads the URL as the window title and opens
	 * nothing. The join above renders it as a double space; this is the
	 * assertion that actually says so. */
	TCT_EQ_INT(tc_browser_default(&c, TC_OS_WINDOWS, 1, url), TC_OK);
	TCT_EQ_INT((int)c.argc, 5);
	TCT_EQ_STR(c.argv[3], "");
	TCT_EQ_STR(c.argv[4], url);

	TCT_CASE("the URL is always the last argument, and argv is terminated");
	static const tc_os all[] = { TC_OS_LINUX,   TC_OS_MACOS,   TC_OS_WINDOWS,
		                         TC_OS_FREEBSD, TC_OS_OPENBSD, TC_OS_NETBSD };
	for (size_t i = 0; i < sizeof all / sizeof all[0]; i++) {
		for (size_t k = 0; tc_browser_default(&c, all[i], k, url) == TC_OK;
		     k++) {
			TCT_EQ_STR(c.argv[c.argc - 1], url);
			TCT_TRUE(c.argv[c.argc] == NULL);
		}
	}

	TCT_CASE("an unrecognised system has no opener at all");
	TCT_EQ_INT(tc_browser_default(&c, TC_OS_UNKNOWN, 0, url),
	           TC_ERR_UNSUPPORTED);

	TCT_CASE("the running system is one we recognise");
	/* Not a tautology: it is the only assertion that the runtime detection
	 * returns anything at all, and it fails on a platform nobody has taught
	 * tc_host_os about. */
	TCT_TRUE(tc_host_os() != TC_OS_UNKNOWN);
	TCT_TRUE(strcmp(tc_os_name(tc_host_os()), "unknown") != 0);
}

static void test_spec(void)
{
	tc_browser_cmd c;
	const char *url = "http://127.0.0.1:8080/";

	TCT_CASE("a bare command gets the URL appended");
	TCT_EQ_INT(tc_browser_from_spec(&c, "firefox", url), TC_OK);
	TCT_EQ_STR(joined(&c), "firefox http://127.0.0.1:8080/");

	TCT_CASE("arguments are kept, and the URL still goes last");
	TCT_EQ_INT(tc_browser_from_spec(&c, "chromium --incognito", url), TC_OK);
	TCT_EQ_STR(joined(&c), "chromium --incognito http://127.0.0.1:8080/");

	TCT_CASE("%s is substituted where it appears, not appended");
	TCT_EQ_INT(tc_browser_from_spec(&c, "firefox %s --new-window", url),
	           TC_OK);
	TCT_EQ_STR(joined(&c),
	           "firefox http://127.0.0.1:8080/ --new-window");

	TCT_CASE("%s inside a larger word");
	TCT_EQ_INT(tc_browser_from_spec(&c, "opener --url=%s", url), TC_OK);
	TCT_EQ_STR(joined(&c), "opener --url=http://127.0.0.1:8080/");

	TCT_CASE("%% is a literal percent and does not count as a substitution");
	/* If it did, the URL would be dropped and the command would open
	 * nothing at all -- a silent no-op, which is the worst failure here. */
	TCT_EQ_INT(tc_browser_from_spec(&c, "opener --pct=100%%", url), TC_OK);
	TCT_EQ_STR(joined(&c), "opener --pct=100% http://127.0.0.1:8080/");

	TCT_CASE("surrounding and repeated whitespace collapses");
	TCT_EQ_INT(tc_browser_from_spec(&c, "   firefox   -P  work  ", url),
	           TC_OK);
	TCT_EQ_STR(joined(&c), "firefox -P work http://127.0.0.1:8080/");

	TCT_CASE("a tab separates words on its own");
	/* With spaces on either side of it, a tab that is not treated as a
	 * separator still produces the right argv, and the assertion above
	 * proves nothing about tabs. This one has no spaces at all. */
	TCT_EQ_INT(tc_browser_from_spec(&c, "firefox\t-P\twork", url), TC_OK);
	TCT_EQ_STR(joined(&c), "firefox -P work http://127.0.0.1:8080/");

	TCT_CASE("an empty or blank entry is refused, not run");
	TCT_EQ_INT(tc_browser_from_spec(&c, "", url), TC_ERR_INVAL);
	TCT_EQ_INT(tc_browser_from_spec(&c, "   ", url), TC_ERR_INVAL);

	TCT_CASE("a spec is never handed to a shell, so it is never quoted");
	/* The argv is exec'd directly. A metacharacter is part of an argument
	 * and nothing else, which is the whole reason for not building a
	 * string. */
	TCT_EQ_INT(tc_browser_from_spec(&c, "opener ;id", url), TC_OK);
	TCT_EQ_INT((int)c.argc, 3);
	TCT_EQ_STR(c.argv[1], ";id");

	TCT_CASE("too many words, and a word too long, are refused");
	TCT_EQ_INT(tc_browser_from_spec(&c, "a b c d e f g h i j k l m n o p q",
	                                url),
	           TC_ERR_TOOMANY);
	char big[TC_BROWSER_BUF + 32];
	memset(big, 'x', sizeof big - 1);
	big[sizeof big - 1] = '\0';
	TCT_EQ_INT(tc_browser_from_spec(&c, big, url), TC_ERR_NOSPACE);

	TCT_CASE("NULL arguments");
	TCT_EQ_INT(tc_browser_from_spec(NULL, "firefox", url), TC_ERR_INVAL);
	TCT_EQ_INT(tc_browser_from_spec(&c, NULL, url), TC_ERR_INVAL);
	TCT_EQ_INT(tc_browser_from_spec(&c, "firefox", NULL), TC_ERR_INVAL);
}

static void test_refusal(void)
{
	tc_browser_env env;

	TCT_CASE("a Linux desktop with X is fine");
	memset(&env, 0, sizeof env);
	env.display = ":0";
	TCT_TRUE(tc_browser_refusal(TC_OS_LINUX, &env) == NULL);

	TCT_CASE("a Wayland-only session is a desktop too");
	/* The Go package upstream uses checks $DISPLAY alone, which refuses on
	 * a session that has a screen. Asking about screens rather than about
	 * X11 is the difference. */
	memset(&env, 0, sizeof env);
	env.wayland_display = "wayland-0";
	TCT_TRUE(tc_browser_refusal(TC_OS_LINUX, &env) == NULL);

	TCT_CASE("a headless Linux box is refused");
	memset(&env, 0, sizeof env);
	TCT_TRUE(tc_browser_refusal(TC_OS_LINUX, &env) != NULL);

	TCT_CASE("an exported but empty variable counts as unset");
	/* Which is how it reaches getenv from a shell that exported it without
	 * a value, and the case a `!= NULL` test gets wrong. */
	memset(&env, 0, sizeof env);
	env.display = "";
	env.wayland_display = "";
	TCT_TRUE(tc_browser_refusal(TC_OS_LINUX, &env) != NULL);

	TCT_CASE("an ssh session is refused even with a display");
	/* X forwarding would make it work, and it would still open the browser
	 * on the wrong side of the connection more often than not. */
	memset(&env, 0, sizeof env);
	env.display = ":0";
	env.ssh_client = "10.0.0.2 1234 22";
	TCT_TRUE(tc_browser_refusal(TC_OS_LINUX, &env) != NULL);
	memset(&env, 0, sizeof env);
	env.display = ":0";
	env.ssh_tty = "/dev/pts/3";
	TCT_TRUE(tc_browser_refusal(TC_OS_LINUX, &env) != NULL);

	TCT_CASE("macOS needs no display, but still refuses over ssh");
	memset(&env, 0, sizeof env);
	TCT_TRUE(tc_browser_refusal(TC_OS_MACOS, &env) == NULL);
	env.ssh_tty = "/dev/ttys003";
	TCT_TRUE(tc_browser_refusal(TC_OS_MACOS, &env) != NULL);

	TCT_CASE("Windows asks neither question");
	/* There is no $DISPLAY, and a Windows box being reached over ssh is
	 * rare enough that the false refusals would outnumber the right ones. */
	memset(&env, 0, sizeof env);
	env.ssh_client = "10.0.0.2 1234 22";
	TCT_TRUE(tc_browser_refusal(TC_OS_WINDOWS, &env) == NULL);

	TCT_CASE("$BROWSER answers the question and ends the argument");
	/* Someone who named a text browser on a headless machine meant it.
	 * This is the one place the behaviour differs from upstream's. */
	memset(&env, 0, sizeof env);
	env.browser = "lynx";
	TCT_TRUE(tc_browser_refusal(TC_OS_LINUX, &env) == NULL);
	env.ssh_tty = "/dev/pts/3";
	TCT_TRUE(tc_browser_refusal(TC_OS_LINUX, &env) == NULL);

	TCT_CASE("an empty $BROWSER does not");
	memset(&env, 0, sizeof env);
	env.browser = "";
	TCT_TRUE(tc_browser_refusal(TC_OS_LINUX, &env) != NULL);

	TCT_CASE("no environment at all is not a refusal");
	TCT_TRUE(tc_browser_refusal(TC_OS_LINUX, NULL) == NULL);
}

/* The one part above that is not a pure function is fork, exec and wait, and
 * it is the part that fails silently: a browser that never opens looks
 * exactly like a browser the user closed. So this runs it for real, with
 * $BROWSER pointing at this binary -- which, re-invoked with a URL, writes
 * the URL down and exits. No shell, no desktop, and nothing platform
 * specific, so it runs everywhere the rest of the suite does.
 *
 * $PATH is emptied first, and that is not tidiness. xdg-open implements the
 * same $BROWSER convention this file does, so on a machine that has it, a
 * build which ignored $BROWSER entirely still ends up running the recorder --
 * by a different route, through the fallback. Three mutations survived on
 * exactly that before $PATH was taken away. An opener that has to be found on
 * $PATH now cannot run at all, so what reaches the recorder can only have
 * come from the code under test. */
#define RECORD_ENV "TCT_BROWSER_RECORD"
#define SLEEP_ENV "TCT_BROWSER_SLEEP_MS"

/* await_record waits for the opener to write the URL down, and returns how
 * long that took in milliseconds, or -1. */
static long await_record(const char *path, char *got, size_t cap)
{
	got[0] = '\0';
	for (int i = 0; i < 500; i++) {
		FILE *f = fopen(path, "rb");
		if (f != NULL) {
			size_t n = fread(got, 1, cap - 1, f);
			got[n] = '\0';
			(void)fclose(f);
			if (n > 0)
				return i * 10L;
		}
		usleep(10000);
	}
	return -1;
}

static uint64_t now_ms(void)
{
	struct timespec ts;
	(void)clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

static void test_open_for_real(const char *self)
{
	char abs[PATH_MAX]; /* realpath writes up to this, and checks */
	char path[512];
	char list[PATH_MAX + 64];
	char url[TC_BROWSER_BUF];
	char got[TC_BROWSER_BUF];

	/* execvp only consults $PATH for a name with no slash in it, so the
	 * recorder has to be named by an absolute path to survive the next
	 * line. */
	if (realpath(self, abs) == NULL) {
		TCT_FAILF("cannot resolve %s", self);
		return;
	}
	TCT_EQ_INT(setenv("PATH", "/nonexistent-path-for-tests", 1), 0);

	(void)snprintf(path, sizeof path, "/tmp/tct-browser-%ld.txt",
	               (long)getpid());
	TCT_EQ_INT(setenv(RECORD_ENV, path, 1), 0);
	TCT_EQ_INT(tc_browser_url(url, sizeof url, "127.0.0.1", 31337), TC_OK);

	TCT_CASE("tc_browser_open execs the opener with the URL");
	(void)remove(path);
	TCT_EQ_INT(setenv("BROWSER", abs, 1), 0);
	TCT_EQ_INT(tc_browser_open(url), TC_OK);
	TCT_TRUE(await_record(path, got, sizeof got) >= 0);
	TCT_EQ_STR(got, url);

	TCT_CASE("a $BROWSER entry that fails falls through to the next");
	/* The list is tried in order until one exits cleanly, so an opener that
	 * is not installed has to be distinguishable from one that worked.
	 * Without the exit status check this passes by accident, having opened
	 * nothing. The empty middle entry is skipped rather than run. */
	(void)snprintf(list, sizeof list, "/nonexistent-opener-%ld::%s",
	               (long)getpid(), abs);
	(void)remove(path);
	TCT_EQ_INT(setenv("BROWSER", list, 1), 0);
	TCT_EQ_INT(tc_browser_open(url), TC_OK);
	TCT_TRUE(await_record(path, got, sizeof got) >= 0);
	TCT_EQ_STR(got, url);

	TCT_CASE("and returns without waiting for the browser to finish");
	/* The promise in the header. On several systems the opener does not
	 * exit until the window closes, and a forwarder that waited for that
	 * would never forward anything. */
	(void)remove(path);
	TCT_EQ_INT(setenv(SLEEP_ENV, "1500", 1), 0);
	TCT_EQ_INT(setenv("BROWSER", abs, 1), 0);
	uint64_t t0 = now_ms();
	TCT_EQ_INT(tc_browser_open(url), TC_OK);
	uint64_t elapsed = now_ms() - t0;
	TCT_TRUE(elapsed < 500);
	(void)unsetenv(SLEEP_ENV);

	TCT_CASE("the slow opener still gets there, after we have gone on");
	long took = await_record(path, got, sizeof got);
	TCT_TRUE(took >= 0);
	TCT_EQ_STR(got, url);
	TCT_TRUE((uint64_t)took > elapsed);
	(void)remove(path);

	TCT_CASE("and nothing is left behind to be reaped");
	/* Forking once and walking away would leave a zombie in a program that
	 * then sits in a loop for hours. */
	TCT_TRUE(waitpid(-1, NULL, WNOHANG) == -1 && errno == ECHILD);

	TCT_CASE("with no opener that can run, it says so rather than hanging");
	(void)unsetenv("BROWSER");
	(void)remove(path);
	TCT_EQ_INT(tc_browser_open(url), TC_OK);
	TCT_TRUE(await_record(path, got, sizeof got) < 0);

	(void)unsetenv(RECORD_ENV);
}

int main(int argc, char **argv)
{
	/* Re-invoked as the browser: write the URL down and get out of the way
	 * before any assertion machinery runs. */
	const char *record = getenv(RECORD_ENV);
	if (argc == 2 && record != NULL && record[0] != '\0') {
		const char *slow = getenv(SLEEP_ENV);
		if (slow != NULL && slow[0] != '\0')
			usleep((useconds_t)(atoi(slow) * 1000));
		FILE *f = fopen(record, "wb");
		if (f == NULL)
			return 1;
		(void)fputs(argv[1], f);
		return fclose(f) == 0 ? 0 : 1;
	}

	test_url();
	test_url_refuses();
	test_defaults();
	test_spec();
	test_refusal();
	test_open_for_real(argv[0]);
	return tct_report("browser");
}
