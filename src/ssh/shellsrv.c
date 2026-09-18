/* SPDX-License-Identifier: BSD-3-Clause
 *
 * See include/tc/shellsrv.h.
 */
#include "tc/shellsrv.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

/* Cosmopolitan declares these in <termios.h>; on a host build they come from
 * <pty.h>, which it does not have. Declared here so one source builds under
 * both toolchains. */
#ifndef __COSMOPOLITAN__
#include <pty.h>
#endif

/* How much shell output we will hold while the peer's window is closed.
 *
 * A bound rather than a growing buffer: the peer controls the window, so an
 * unbounded queue here is a peer-controlled allocation. When it fills we stop
 * reading the pty, which backs pressure up to the shell exactly as a full
 * pipe would on a local terminal. */
#define OUTQ 16384

typedef struct {
	int master;   /* the pty master, or our end of the socketpair */
	pid_t child;
	bool have_pty;
	bool child_gone;
	int status;

	uint8_t q[OUTQ];
	size_t q_len;

	/* The pty size last pushed to the kernel, so a window-change is noticed
	 * without asking every turn. */
	uint64_t pty_gen;
} shell_state;

bool tc_shell_have_pty(void)
{
#ifdef __COSMOPOLITAN__
	/* Cosmopolitan's forkpty is ENOSYS on Windows and works everywhere else,
	 * and there is no compile-time answer for a fat binary that runs on both.
	 * Asking the system for a master is cheap and is the only honest test. */
	int fd = posix_openpt((int)(unsigned)(O_RDWR | O_NOCTTY));
	if (fd < 0)
		return false;
	(void)close(fd);
	return true;
#else
	return true;
#endif
}

const char *tc_shell_login_shell(void)
{
	const char *sh = getenv("SHELL");
	if (sh != NULL && sh[0] != '\0')
		return sh;
	return "/bin/sh";
}

/* ---- starting the child ------------------------------------------------ */

static void set_child_env(const tc_shell_opts *opts, const tc_ssh_pty *pty)
{
	if (pty != NULL && pty->term[0] != '\0')
		(void)setenv("TERM", pty->term, 1);
	else if (getenv("TERM") == NULL)
		(void)setenv("TERM", "dumb", 1);

	if (opts->peer_key != NULL) {
		char hex[65];
		static const char kHex[] = "0123456789abcdef";
		for (size_t i = 0; i < 32; i++) {
			hex[i * 2] = kHex[opts->peer_key[i] >> 4];
			hex[i * 2 + 1] = kHex[opts->peer_key[i] & 0x0F];
		}
		hex[64] = '\0';
		(void)setenv("TAILCAT_PEER_KEY", hex, 1);
	}
	if (opts->peer_addr != NULL)
		(void)setenv("TAILCAT_REMOTE_ADDR", opts->peer_addr, 1);
	if (opts->original_command != NULL)
		(void)setenv("SSH_ORIGINAL_COMMAND", opts->original_command, 1);
}

/* exec_child never returns. */
static void exec_child(const tc_shell_opts *opts)
{
	const char *sh = tc_shell_login_shell();
	if (opts->command != NULL) {
		/* `sh -c` rather than a split: an exec request carries one string
		 * and every client -- scp, rsync, git -- expects a shell to read
		 * it. Splitting it here would be a second, worse shell. */
		execl(sh, sh, "-c", opts->command, (char *)NULL);
		execl("/bin/sh", "sh", "-c", opts->command, (char *)NULL);
	} else {
		/* The leading '-' is what makes it a login shell, which is what
		 * reads the profile a user expects to have been read. */
		const char *base = strrchr(sh, '/');
		char argv0[64];
		(void)snprintf(argv0, sizeof argv0, "-%s",
		               base != NULL ? base + 1 : sh);
		execl(sh, argv0, (char *)NULL);
		execl("/bin/sh", "-sh", (char *)NULL);
	}
	/* Down here the shell could not be started at all. The message goes to
	 * the channel, because the client is the only one listening. */
	(void)fprintf(stderr, "tailcat-c: cannot start %s: %s\n", sh,
	              strerror(errno));
	_exit(127);
}

static void apply_winsize(int fd, const tc_ssh_pty *pty)
{
	if (pty == NULL || fd < 0)
		return;
	struct winsize ws;
	memset(&ws, 0, sizeof ws);
	ws.ws_col = (unsigned short)(pty->cols != 0 ? pty->cols : 80);
	ws.ws_row = (unsigned short)(pty->rows != 0 ? pty->rows : 24);
	ws.ws_xpixel = (unsigned short)pty->width_px;
	ws.ws_ypixel = (unsigned short)pty->height_px;
	(void)ioctl(fd, TIOCSWINSZ, &ws);
}

static int start_child(shell_state *st, const tc_shell_opts *opts,
                       const tc_ssh_pty *pty)
{
	st->master = -1;
	st->child = -1;

	if (pty != NULL && tc_shell_have_pty()) {
		int master = -1;
		/* Cosmopolitan declares the name argument non-null, so it gets a
		 * buffer even though nothing here wants the slave's path. */
		char slave_name[64];
		pid_t pid = forkpty(&master, slave_name, NULL, NULL);
		if (pid == 0) {
			set_child_env(opts, pty);
			exec_child(opts);
		}
		if (pid > 0) {
			st->master = master;
			st->child = pid;
			st->have_pty = true;
			apply_winsize(master, pty);
			return TC_OK;
		}
		/* Fall through to pipes. A machine that cannot hand out a terminal
		 * can still run a shell, and `ssh -T` is a working session. */
	}

	/* A socketpair rather than two pipes: one descriptor carries both
	 * directions, and shutdown() on it gives the child a clean EOF without
	 * a second fd to track. */
	int sp[2];
	/* TC_ERR_NOSPACE for both: a socketpair or a fork that fails here has
	 * run out of descriptors or processes, which is the closest thing in
	 * the error list to what actually happened. */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0)
		return TC_ERR_NOSPACE;
	pid_t pid = fork();
	if (pid < 0) {
		(void)close(sp[0]);
		(void)close(sp[1]);
		return TC_ERR_NOSPACE;
	}
	if (pid == 0) {
		(void)close(sp[0]);
		(void)dup2(sp[1], STDIN_FILENO);
		(void)dup2(sp[1], STDOUT_FILENO);
		(void)dup2(sp[1], STDERR_FILENO);
		if (sp[1] > STDERR_FILENO)
			(void)close(sp[1]);
		/* A new session, so the child does not share our controlling
		 * terminal: without this a ^C typed at the server's own console
		 * would reach the client's shell. */
		(void)setsid();
		set_child_env(opts, pty);
		exec_child(opts);
	}
	(void)close(sp[1]);
	st->master = sp[0];
	st->child = pid;
	st->have_pty = false;
	return TC_OK;
}

/* ---- the pump ----------------------------------------------------------- */

/* flush_out moves the queue to the client.
 *
 * `may_wait` is the whole of the difference between the two callers, and it
 * matters more than it looks:
 *
 *   - false, from the pump: we are inside the packet reader, so we send what
 *     the peer's window already allows and keep the rest. Trying to wait
 *     here would mean reading a packet from inside the reader.
 *
 *   - true, from the session loop after the client has sent EOF: nothing
 *     else is reading packets any more, so this has to, or it waits for a
 *     window adjustment that is sitting unread in the socket. That was a
 *     hang, not a slowdown.
 */
static int flush_out(shell_state *st, tc_ssh_server *s, bool may_wait)
{
	while (st->q_len > 0) {
		if (may_wait) {
			int rc = tc_ssh_server_write(s, st->q, st->q_len);
			if (rc != TC_OK)
				return rc;
			st->q_len = 0;
			return TC_OK;
		}
		size_t wrote = 0;
		int rc = tc_ssh_server_write_some(s, st->q, st->q_len, &wrote);
		if (rc != TC_OK)
			return rc;
		if (wrote == 0)
			return TC_OK; /* the window is shut; the rest waits */
		st->q_len -= wrote;
		memmove(st->q, st->q + wrote, st->q_len);
	}
	return TC_OK;
}

/* drain_child reads whatever the shell has produced into the queue. */
static void drain_child(shell_state *st)
{
	while (st->q_len < sizeof st->q && st->master >= 0) {
		struct pollfd p;
		p.fd = st->master;
		p.events = POLLIN;
		p.revents = 0;
		int pr = poll(&p, 1, 0);
		if (pr < 0)
			return; /* EINTR; try again next turn */
		if (pr == 0)
			return; /* nothing yet */
		/* POLLHUP counts, and this is the subtle one. When the shell has
		 * exited and everything it wrote has been read, the master reports
		 * POLLHUP with no POLLIN -- and the end of file itself, which on
		 * Linux is read() failing with EIO, is only delivered to something
		 * that calls read(). A loop that read only on POLLIN therefore
		 * never learns the session is over, and hangs with the child long
		 * since reaped. It also has to read *first* rather than give up on
		 * POLLHUP, because a hung-up pty can still have buffered output
		 * waiting. */
		if ((p.revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) == 0)
			return;
		ssize_t n = read(st->master, st->q + st->q_len,
		                 sizeof st->q - st->q_len);
		if (n > 0) {
			st->q_len += (size_t)n;
			continue;
		}
		if (n < 0 && (errno == EINTR || errno == EAGAIN))
			return;
		/* 0 on a socketpair, and -1/EIO on a pty master whose last slave
		 * descriptor has closed. Both mean the shell is gone. */
		(void)close(st->master);
		st->master = -1;
		return;
	}
}

static void reap(shell_state *st)
{
	if (st->child <= 0 || st->child_gone)
		return;
	int status = 0;
	pid_t r = waitpid(st->child, &status, WNOHANG);
	if (r == st->child) {
		st->child_gone = true;
		st->status = status;
	}
}

static int pump_common(shell_state *st, tc_ssh_server *s, bool may_wait)
{
	/* A resize that arrived since last time. Cheap to check and it has to
	 * happen here, because the request is parsed inside the packet reader
	 * and nothing else runs between one packet and the next. */
	if (st->have_pty) {
		uint64_t gen = tc_ssh_server_pty_generation(s);
		if (gen != st->pty_gen) {
			st->pty_gen = gen;
			apply_winsize(st->master, tc_ssh_server_pty(s));
		}
	}

	drain_child(st);
	reap(st);
	return flush_out(st, s, may_wait);
}

/* The one the server calls while it waits for bytes. Never waits. */
static int pump(void *ctx, tc_ssh_server *s)
{
	return pump_common((shell_state *)ctx, s, false);
}

/* ---- the session -------------------------------------------------------- */

int tc_shell_serve(tc_ssh_server *s, const tc_shell_opts *opts)
{
	if (s == NULL || opts == NULL)
		return TC_ERR_INVAL;

	static tc_shell_opts local;
	local = *opts;

	const tc_ssh_pty *pty = tc_ssh_server_pty(s);

	shell_state *st = calloc(1, sizeof *st);
	if (st == NULL)
		return TC_ERR_NOSPACE;
	st->pty_gen = tc_ssh_server_pty_generation(s);

	int rc = start_child(st, &local, pty);
	if (rc != TC_OK) {
		free(st);
		return rc;
	}

	/* SIGPIPE would kill the server when the shell exits with bytes still
	 * on the way to it. Ignored for the session and restored after, rather
	 * than set once at startup, because this is the only place that needs
	 * it and a program-wide change is one the rest of the code has not been
	 * written against. */
	void (*old_pipe)(int) = signal(SIGPIPE, SIG_IGN);

	tc_ssh_server_set_idle(s, pump, st);

	for (;;) {
		/* Anything the shell has said, first: a client that sent EOF and is
		 * waiting for the last of the output must get it. */
		/* Non-waiting: the reader below is live, and it is what collects
		 * the window adjustments this would otherwise have to wait for. */
		rc = pump_common(st, s, false);
		if (rc != TC_OK)
			break;

		if (st->child_gone && st->q_len == 0 && st->master < 0)
			break; /* the shell is gone and everything it said has gone out */

		uint8_t buf[8192];
		size_t got = 0;
		rc = tc_ssh_server_read(s, buf, sizeof buf, &got);
		if (rc == TC_ERR_DONE || rc == TC_ERR_CLOSED) {
			/* The client will send no more. The shell keeps running until
			 * it notices its input has ended, so tell it, and stay here for
			 * whatever it says on the way out.
			 *
			 * The pump is unregistered first: from here on this loop is the
			 * only thing touching the queue, which is what lets it wait for
			 * a window. A waiting write reads packets, reading a packet
			 * runs the pump, and a pump that drained the pty into the queue
			 * mid-write would move the buffer the write is part way
			 * through. */
			if (st->master >= 0)
				(void)shutdown(st->master, SHUT_WR);
			tc_ssh_server_set_idle(s, NULL, NULL);
			rc = TC_OK;
			/* The test is on the *output*, not on the child: a shell that
			 * has already exited may have left tens of thousands of lines
			 * in the pty, and waiting only for the process is how
			 * `seq 1 200000` arrived as 45541 lines. */
			while (st->master >= 0 || st->q_len > 0) {
				int prc = pump_common(st, s, true);
				if (prc != TC_OK) {
					rc = prc;
					break;
				}
				if (st->master < 0 && st->q_len == 0)
					break;
				struct pollfd p;
				p.fd = st->master >= 0 ? st->master : -1;
				p.events = POLLIN;
				p.revents = 0;
				(void)poll(&p, 1, 20);
			}
			break;
		}
		if (rc != TC_OK)
			break;

		size_t off = 0;
		while (off < got && st->master >= 0) {
			ssize_t n = write(st->master, buf + off, got - off);
			if (n > 0) {
				off += (size_t)n;
				continue;
			}
			if (n < 0 && errno == EINTR)
				continue;
			/* The shell is gone. Not an error: the client typed something
			 * after `exit`, which is ordinary. */
			(void)close(st->master);
			st->master = -1;
			break;
		}
	}

	tc_ssh_server_set_idle(s, NULL, NULL);

	/* Wait for the child, but not forever: a shell that ignored its input
	 * ending is one we have to stop waiting for eventually, and the session
	 * is over either way. */
	if (!st->child_gone && st->child > 0) {
		for (int i = 0; i < 100 && !st->child_gone; i++) {
			reap(st);
			if (st->child_gone)
				break;
			struct timespec ts = { 0, 10 * 1000 * 1000 };
			(void)nanosleep(&ts, NULL);
		}
		if (!st->child_gone) {
			(void)kill(st->child, SIGHUP);
			(void)waitpid(st->child, &st->status, 0);
			st->child_gone = true;
		}
	}
	if (st->master >= 0)
		(void)close(st->master);

	(void)signal(SIGPIPE, old_pipe);

	if (rc == TC_OK) {
		int code = WIFEXITED(st->status) ? WEXITSTATUS(st->status) : 255;
		(void)tc_ssh_server_exit(s, (uint32_t)code);
	}
	free(st);
	return rc;
}
