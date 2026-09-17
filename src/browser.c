/* SPDX-License-Identifier: BSD-3-Clause
 *
 * See include/tc/browser.h.
 */
#include "tc/browser.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __COSMOPOLITAN__
#include <cosmo.h>
#endif

/* ---- which system are we on -------------------------------------------- */

tc_os tc_host_os(void)
{
#ifdef __COSMOPOLITAN__
	/* A fat APE is one file that starts on six systems, so this is a
	 * question about the machine, not about the compiler. Cosmopolitan
	 * answers it from what its loader found at startup. */
	if (IsWindows())
		return TC_OS_WINDOWS;
	if (IsXnu())
		return TC_OS_MACOS;
	if (IsLinux())
		return TC_OS_LINUX;
	if (IsFreebsd())
		return TC_OS_FREEBSD;
	if (IsOpenbsd())
		return TC_OS_OPENBSD;
	if (IsNetbsd())
		return TC_OS_NETBSD;
	return TC_OS_UNKNOWN;
#elif defined(_WIN32)
	return TC_OS_WINDOWS;
#elif defined(__APPLE__)
	return TC_OS_MACOS;
#elif defined(__linux__)
	return TC_OS_LINUX;
#elif defined(__FreeBSD__)
	return TC_OS_FREEBSD;
#elif defined(__OpenBSD__)
	return TC_OS_OPENBSD;
#elif defined(__NetBSD__)
	return TC_OS_NETBSD;
#else
	return TC_OS_UNKNOWN;
#endif
}

const char *tc_os_name(tc_os os)
{
	switch (os) {
	case TC_OS_LINUX:
		return "linux";
	case TC_OS_MACOS:
		return "macos";
	case TC_OS_WINDOWS:
		return "windows";
	case TC_OS_FREEBSD:
		return "freebsd";
	case TC_OS_OPENBSD:
		return "openbsd";
	case TC_OS_NETBSD:
		return "netbsd";
	case TC_OS_UNKNOWN:
	default:
		return "unknown";
	}
}

/* ---- building a command ------------------------------------------------ */

static void cmd_reset(tc_browser_cmd *c)
{
	memset(c, 0, sizeof *c);
}

/* cmd_push copies one argument into the command's own storage.
 *
 * Copied rather than pointed at, because the arguments come from a mix of
 * string literals, a URL on the caller's stack and a $BROWSER entry that has
 * to be split in place -- and an argv holding pointers into three different
 * lifetimes is a use-after-free waiting for someone to refactor it. */
static int cmd_push(tc_browser_cmd *c, const char *arg, size_t len)
{
	if (c->argc + 1 >= TC_BROWSER_MAX_ARGV)
		return TC_ERR_TOOMANY;
	if (c->used + len + 1 > sizeof c->buf)
		return TC_ERR_NOSPACE;
	char *dst = c->buf + c->used;
	memcpy(dst, arg, len);
	dst[len] = '\0';
	c->used += len + 1;
	c->argv[c->argc++] = dst;
	c->argv[c->argc] = NULL;
	return TC_OK;
}

static int cmd_push_str(tc_browser_cmd *c, const char *arg)
{
	return cmd_push(c, arg, strlen(arg));
}

/* ---- the URL ----------------------------------------------------------- */

/* A dotted quad and nothing else. `forward` already requires one -- its
 * listen address goes through inet_pton -- so this is not the check that
 * makes the address valid, it is the check that keeps this file's promise
 * that a browser is only ever handed a string built from four numbers and a
 * port. */
static bool is_dotted_quad(const char *s, unsigned octets[4])
{
	for (int i = 0; i < 4; i++) {
		if (*s < '0' || *s > '9')
			return false;
		unsigned v = 0;
		int digits = 0;
		while (*s >= '0' && *s <= '9') {
			v = v * 10u + (unsigned)(*s - '0');
			s++;
			if (++digits > 3 || v > 255u)
				return false;
		}
		octets[i] = v;
		if (i < 3) {
			if (*s != '.')
				return false;
			s++;
		}
	}
	return *s == '\0';
}

int tc_browser_url(char *out, size_t cap, const char *bind, uint16_t port)
{
	unsigned q[4];

	if (out == NULL || cap == 0 || bind == NULL)
		return TC_ERR_INVAL;
	if (!is_dotted_quad(bind, q))
		return TC_ERR_INVAL;

	/* 0.0.0.0 is a listener on every interface, which includes the loopback
	 * one; it is not somewhere a browser can go. */
	if (q[0] == 0 && q[1] == 0 && q[2] == 0 && q[3] == 0) {
		q[0] = 127;
		q[1] = 0;
		q[2] = 0;
		q[3] = 1;
	}

	int n = snprintf(out, cap, "http://%u.%u.%u.%u:%u/", q[0], q[1], q[2],
	                 q[3], (unsigned)port);
	if (n < 0 || (size_t)n >= cap)
		return TC_ERR_NOSPACE;
	return TC_OK;
}

/* ---- the opener each system uses --------------------------------------- */

int tc_browser_default(tc_browser_cmd *out, tc_os os, size_t index,
                       const char *url)
{
	int rc;

	if (out == NULL || url == NULL)
		return TC_ERR_INVAL;
	cmd_reset(out);

	switch (os) {
	case TC_OS_WINDOWS:
		/* rundll32 before cmd, because the first takes an argv and the
		 * second takes a command line that cmd.exe then re-parses. The
		 * fallback is there because rundll32 is the less usual spelling
		 * and this program cannot test every Windows there is; the empty
		 * "" is start's title argument, which it otherwise steals from
		 * the URL. */
		if (index == 0) {
			rc = cmd_push_str(out, "rundll32.exe");
			if (rc == TC_OK)
				rc = cmd_push_str(out, "url.dll,FileProtocolHandler");
			break;
		}
		if (index == 1) {
			rc = cmd_push_str(out, "cmd.exe");
			if (rc == TC_OK)
				rc = cmd_push_str(out, "/c");
			if (rc == TC_OK)
				rc = cmd_push_str(out, "start");
			if (rc == TC_OK)
				rc = cmd_push_str(out, "");
			break;
		}
		return TC_ERR_DONE;

	case TC_OS_MACOS:
		if (index != 0)
			return TC_ERR_DONE;
		rc = cmd_push_str(out, "open");
		break;

	case TC_OS_LINUX:
	case TC_OS_FREEBSD:
	case TC_OS_OPENBSD:
	case TC_OS_NETBSD:
		/* xdg-open is the portable answer and honours $BROWSER itself.
		 * gio is the fallback for a desktop that has GLib but not
		 * xdg-utils. Deliberately no bare `open`: on Linux that name
		 * belongs to util-linux, and it switches virtual terminals. */
		if (index == 0) {
			rc = cmd_push_str(out, "xdg-open");
			break;
		}
		if (index == 1) {
			rc = cmd_push_str(out, "gio");
			if (rc == TC_OK)
				rc = cmd_push_str(out, "open");
			break;
		}
		return TC_ERR_DONE;

	case TC_OS_UNKNOWN:
	default:
		return TC_ERR_UNSUPPORTED;
	}

	if (rc != TC_OK)
		return rc;
	return cmd_push_str(out, url);
}

/* ---- $BROWSER ---------------------------------------------------------- */

/* One word of a $BROWSER entry, with %s replaced by the URL if it appears. */
static int push_word(tc_browser_cmd *out, const char *word, size_t len,
                     const char *url, bool *substituted)
{
	char tmp[TC_BROWSER_BUF];
	size_t w = 0;

	for (size_t i = 0; i < len; i++) {
		if (word[i] == '%' && i + 1 < len && word[i + 1] == 's') {
			size_t ul = strlen(url);
			if (w + ul >= sizeof tmp)
				return TC_ERR_NOSPACE;
			memcpy(tmp + w, url, ul);
			w += ul;
			i++;
			*substituted = true;
			continue;
		}
		/* %% is a literal percent, so that a URL is never produced by an
		 * entry that meant to print one. */
		if (word[i] == '%' && i + 1 < len && word[i + 1] == '%')
			i++;
		if (w + 1 >= sizeof tmp)
			return TC_ERR_NOSPACE;
		tmp[w++] = word[i];
	}
	return cmd_push(out, tmp, w);
}

int tc_browser_from_spec(tc_browser_cmd *out, const char *spec, const char *url)
{
	bool substituted = false;
	const char *p = spec;

	if (out == NULL || spec == NULL || url == NULL)
		return TC_ERR_INVAL;
	cmd_reset(out);

	while (*p != '\0') {
		while (*p == ' ' || *p == '\t')
			p++;
		if (*p == '\0')
			break;
		const char *start = p;
		while (*p != '\0' && *p != ' ' && *p != '\t')
			p++;
		int rc = push_word(out, start, (size_t)(p - start), url,
		                   &substituted);
		if (rc != TC_OK)
			return rc;
	}

	if (out->argc == 0)
		return TC_ERR_INVAL;
	if (substituted)
		return TC_OK;
	return cmd_push_str(out, url);
}

/* ---- whether to try at all --------------------------------------------- */

static bool set(const char *v)
{
	return v != NULL && v[0] != '\0';
}

const char *tc_browser_refusal(tc_os os, const tc_browser_env *env)
{
	if (env == NULL)
		return NULL;

	/* Someone who exported $BROWSER has already answered this. */
	if (set(env->browser))
		return NULL;

	if (os == TC_OS_LINUX || os == TC_OS_FREEBSD || os == TC_OS_OPENBSD ||
	    os == TC_OS_NETBSD) {
		/* Wayland as well as X: a session with only WAYLAND_DISPLAY set
		 * has a screen, and refusing there would be answering a question
		 * about X11 when the question was about screens. */
		if (!set(env->display) && !set(env->wayland_display))
			return "no screen to open a browser on";
	}
	if (os == TC_OS_LINUX || os == TC_OS_MACOS) {
		/* The browser would open on the machine running this, which in an
		 * ssh session is not the machine the user is looking at. */
		if (set(env->ssh_client) || set(env->ssh_tty))
			return "this is an ssh session; the browser would open "
			       "somewhere else";
	}
	return NULL;
}

/* ---- running it -------------------------------------------------------- */

/* try_one runs a command and reports whether it succeeded.
 *
 * stdin and stdout go to /dev/null: a browser is not part of this program's
 * data path, and one that inherited stdout could write into a pipe the user
 * is reading. stderr is kept, because "xdg-open: no method available" is the
 * one thing worth seeing. */
static bool try_one(const tc_browser_cmd *c)
{
	pid_t pid = fork();
	if (pid < 0)
		return false;
	if (pid == 0) {
		int null = open("/dev/null", O_RDWR);
		if (null >= 0) {
			(void)dup2(null, STDIN_FILENO);
			(void)dup2(null, STDOUT_FILENO);
			if (null > STDERR_FILENO)
				(void)close(null);
		}
		execvp(c->argv[0], (char *const *)(uintptr_t)c->argv);
		_exit(127);
	}

	int status = 0;
	while (waitpid(pid, &status, 0) < 0) {
		if (errno != EINTR)
			return false;
	}
	return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

/* run_candidates is what the detached child does: try each opener until one
 * exits cleanly. */
static void run_candidates(const char *url, tc_os os,
                           const tc_browser_env *env)
{
	tc_browser_cmd cmd;

	if (set(env->browser)) {
		const char *p = env->browser;
		while (*p != '\0') {
			const char *colon = strchr(p, ':');
			size_t len = (colon != NULL) ? (size_t)(colon - p) : strlen(p);
			char entry[TC_BROWSER_BUF];
			if (len > 0 && len < sizeof entry) {
				memcpy(entry, p, len);
				entry[len] = '\0';
				if (tc_browser_from_spec(&cmd, entry, url) == TC_OK &&
				    try_one(&cmd))
					return;
			}
			if (colon == NULL)
				break;
			p = colon + 1;
		}
	}

	for (size_t i = 0;; i++) {
		int rc = tc_browser_default(&cmd, os, i, url);
		if (rc != TC_OK)
			break;
		if (try_one(&cmd))
			return;
	}

	fprintf(stderr, "# opening a browser failed; go to %s yourself\n", url);
}

int tc_browser_open(const char *url)
{
	tc_browser_env env;
	tc_browser_cmd probe;
	tc_os os = tc_host_os();

	if (url == NULL)
		return TC_ERR_INVAL;

	env.browser = getenv("BROWSER");
	env.display = getenv("DISPLAY");
	env.wayland_display = getenv("WAYLAND_DISPLAY");
	env.ssh_client = getenv("SSH_CLIENT");
	env.ssh_tty = getenv("SSH_TTY");

	const char *why = tc_browser_refusal(os, &env);
	if (why != NULL) {
		fprintf(stderr, "# not opening a browser: %s. Go to %s\n", why, url);
		return TC_ERR_UNSUPPORTED;
	}
	if (!set(env.browser) &&
	    tc_browser_default(&probe, os, 0, url) == TC_ERR_UNSUPPORTED) {
		fprintf(stderr, "# no known way to open a browser on %s. Go to %s\n",
		        tc_os_name(os), url);
		return TC_ERR_UNSUPPORTED;
	}

	fprintf(stderr, "# opening %s\n", url);
	(void)fflush(stderr);

	/* Twice, so that nothing is left to reap. The middle process exits at
	 * once and is waited for here; the one that actually runs the openers is
	 * orphaned, and reaps its own children. The alternative -- forking once
	 * and not waiting -- leaves a zombie in a program whose whole job is to
	 * sit in a loop afterwards, and an opener that does not exit until the
	 * browser window closes would make it a long-lived one. */
	pid_t mid = fork();
	if (mid < 0) {
		fprintf(stderr, "# opening a browser failed: %s\n", strerror(errno));
		return TC_ERR_UNSUPPORTED;
	}
	if (mid == 0) {
		pid_t grand = fork();
		if (grand == 0) {
			run_candidates(url, os, &env);
			_exit(0);
		}
		_exit(0);
	}

	int status = 0;
	while (waitpid(mid, &status, 0) < 0) {
		if (errno != EINTR)
			break;
	}
	return TC_OK;
}
