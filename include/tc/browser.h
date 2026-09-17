/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Opening a web browser, for `browse` and `forward --open-browser`.
 *
 * Upstream's `tailcat browse <tc-addr>` is an alias for
 * `tailcat forward --open-browser <tc-addr> 0:80`: it forwards a
 * kernel-chosen local port to the server's port 80 and points a browser at
 * the local end. The forwarding is the part that already existed here; this
 * file is only the pointing.
 *
 * Three things make that more than a call to system():
 *
 * There is no shell. Every opener is exec'd with an argv array, because the
 * conventional Windows incantation -- `cmd /c start <url>` -- hands a URL to
 * a command interpreter, and the Go package upstream uses carries an `&` ->
 * `^&` escape to prove it. A URL that never meets a parser needs no escaping,
 * so `rundll32 url.dll,FileProtocolHandler` is tried first there.
 *
 * The opener depends on the operating system, which a fat APE does not know
 * until it runs. `#ifdef __APPLE__` is a question about the compiler, and the
 * same binary starts on six systems; tc_host_os asks Cosmopolitan at runtime
 * instead, and falls back to compile-time detection under a host compiler,
 * where the question really is settled at build time.
 *
 * Not every machine should be asked to open a browser at all. A headless
 * Linux box and an ssh session both have no screen to put one on, and trying
 * anyway either fails slowly or -- worse -- opens something on a screen
 * somebody else is looking at.
 */
#ifndef TC_BROWSER_H_
#define TC_BROWSER_H_

#include "tc/tc.h"

/* Which system this process is running on, decided at runtime. */
typedef enum {
	TC_OS_UNKNOWN = 0,
	TC_OS_LINUX,
	TC_OS_MACOS,
	TC_OS_WINDOWS,
	TC_OS_FREEBSD,
	TC_OS_OPENBSD,
	TC_OS_NETBSD
} tc_os;

tc_os tc_host_os(void);

/* tc_os_name is for messages: "linux", "macos", and so on. */
const char *tc_os_name(tc_os os);

/* A command to run, as argv rather than as a string. */
#define TC_BROWSER_MAX_ARGV 16
#define TC_BROWSER_BUF 512

typedef struct {
	/* NULL-terminated, and every entry points into buf. */
	const char *argv[TC_BROWSER_MAX_ARGV];
	size_t argc;
	char buf[TC_BROWSER_BUF];
	size_t used;
} tc_browser_cmd;

/* The URL is built here rather than by the caller so that exactly one piece
 * of code decides what a browser is ever handed.
 *
 * `bind` is the local listen address, which `forward` has already required to
 * be an IPv4 literal. An unspecified address (0.0.0.0) becomes 127.0.0.1: a
 * listener on every interface is still reachable on the loopback one, and
 * "http://0.0.0.0/" is not a thing a browser can usefully open.
 *
 * Returns TC_ERR_INVAL if `bind` is not a dotted quad -- which is a refusal
 * to guess, not politeness. Anything else reaching an opener would be a
 * string this program did not construct. */
int tc_browser_url(char *out, size_t cap, const char *bind, uint16_t port);

/* tc_browser_default fills `out` with the `index`th opener to try for `os`,
 * with `url` as its last argument.
 *
 * Returns TC_ERR_DONE when `index` is past the last candidate, and
 * TC_ERR_UNSUPPORTED for a system with no known opener at all. */
int tc_browser_default(tc_browser_cmd *out, tc_os os, size_t index,
                       const char *url);

/* tc_browser_from_spec reads one entry of $BROWSER.
 *
 * The convention, as Python's webbrowser and much else implement it: entries
 * are separated by colons, an entry is split on spaces into a command and its
 * arguments, and a `%s` anywhere in it is replaced by the URL. With no `%s`
 * the URL is appended, which is what almost every entry in the wild wants.
 *
 * `spec` is one entry, already split from the list. Returns TC_ERR_INVAL for
 * an empty entry and TC_ERR_NOSPACE if it does not fit. */
int tc_browser_from_spec(tc_browser_cmd *out, const char *spec,
                         const char *url);

/* What tc_browser_open reads from the environment, passed explicitly so that
 * the decision below can be tested without one. A NULL member means unset;
 * so, deliberately, does an empty string, because that is how an exported
 * but empty variable reaches getenv. */
typedef struct {
	const char *browser;         /* $BROWSER */
	const char *display;         /* $DISPLAY */
	const char *wayland_display; /* $WAYLAND_DISPLAY */
	const char *ssh_client;      /* $SSH_CLIENT */
	const char *ssh_tty;         /* $SSH_TTY */
} tc_browser_env;

/* tc_browser_refusal returns why the OS default should not be tried, or NULL
 * if it should. The string is static and suitable for printing after
 * "tailcat-c: ".
 *
 * $BROWSER overrides all of it: someone who has named a browser has answered
 * the question this is guessing at, and a text browser on a headless machine
 * is a perfectly ordinary thing to have named. This is the one place the
 * behaviour deliberately differs from upstream's Go package, which checks
 * before consulting any candidate. */
const char *tc_browser_refusal(tc_os os, const tc_browser_env *env);

/* tc_browser_open opens `url`, and does not wait for the browser.
 *
 * It returns as soon as the work is handed off, because the caller is a
 * forwarder that has to start forwarding: on several systems the opener does
 * not exit until the browser window closes, and upstream has the same note
 * against the package it uses. Nothing is left to reap.
 *
 * Diagnostics go to stderr, prefixed with "# " as the rest of the program's
 * progress reporting is. Returns TC_OK once the attempt is under way, or
 * TC_ERR_UNSUPPORTED when there is nothing to try -- the caller keeps
 * forwarding either way, since a failed browser is not a failed tunnel. */
int tc_browser_open(const char *url);

#endif /* TC_BROWSER_H_ */
