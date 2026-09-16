/* SPDX-License-Identifier: BSD-3-Clause
 *
 * See proxy.h. Bytes between a tunnel connection and a host socket.
 *
 * The interesting part is not the copying, it is the closing. A proxy that
 * only forwards data works for anything request-response and fails for
 * everything that signals "I have finished speaking" with an EOF, which is
 * most of what a user would point this at.
 */

#include "tc/proxy.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Writing to a socket whose peer has gone raises SIGPIPE, and the default
 * disposition for that is to kill the process. A proxy meets exactly that
 * situation as a matter of routine -- a local service exiting mid-stream is
 * ordinary -- so it must be handled per call rather than by changing the
 * signal disposition of whatever program links this.
 *
 * MSG_NOSIGNAL does it on Linux and anything POSIX-2008. Where it does not
 * exist the socket option SO_NOSIGPIPE does the same job per socket, and
 * tc_proxy_add sets it; between them every target is covered. */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

typedef struct {
	tc_tcp_conn *tun;
	int fd;
	bool used;

	/* Out of the tunnel, waiting to go to the host socket. */
	uint8_t to_host[TC_PROXY_BUFSZ];
	size_t to_host_len;
	size_t to_host_off;

	/* Off the host socket, waiting to go into the tunnel. */
	uint8_t to_tun[TC_PROXY_BUFSZ];
	size_t to_tun_len;
	size_t to_tun_off;

	bool tun_eof;     /* the peer has finished sending */
	bool host_eof;    /* the local service has finished sending */
	bool host_shut;   /* we have shut down the host socket for writing */
	bool tun_shut;    /* we have sent FIN into the tunnel */
	bool failed;      /* an error, as opposed to an orderly finish */
	bool done;
} pair;

struct tc_proxy {
	pair *pairs;
	size_t cap;
	tc_proxy_stats stats;
};

tc_proxy *tc_proxy_new(size_t max_pairs)
{
	if (max_pairs == 0)
		return NULL;
	tc_proxy *p = (tc_proxy *)calloc(1, sizeof *p);
	if (p == NULL)
		return NULL;
	p->pairs = (pair *)calloc(max_pairs, sizeof *p->pairs);
	if (p->pairs == NULL) {
		free(p);
		return NULL;
	}
	p->cap = max_pairs;
	return p;
}

static void close_pair(tc_proxy *p, pair *pr)
{
	if (pr->fd >= 0)
		(void)close(pr->fd);
	memset(pr, 0, sizeof *pr);
	pr->fd = -1;
	(void)p;
}

void tc_proxy_free(tc_proxy *p)
{
	if (p == NULL)
		return;
	for (size_t i = 0; i < p->cap; i++) {
		if (p->pairs[i].used)
			close_pair(p, &p->pairs[i]);
	}
	free(p->pairs);
	free(p);
}

int tc_proxy_add(tc_proxy *p, tc_tcp_conn *tun, int fd)
{
	if (p == NULL || tun == NULL || fd < 0)
		return TC_ERR_INVAL;

	for (size_t i = 0; i < p->cap; i++) {
		if (p->pairs[i].used)
			continue;
		pair *pr = &p->pairs[i];
		memset(pr, 0, sizeof *pr);
		pr->tun = tun;
		pr->fd = fd;
		pr->used = true;

		/* Non-blocking here rather than at every call site: one socket left
		 * blocking would stall the WireGuard timers that share this loop,
		 * and the failure would look like an unrelated hang. */
		int fl = fcntl(fd, F_GETFL, 0);
		if (fl >= 0)
			(void)fcntl(fd, F_SETFL, (int)((unsigned)fl | (unsigned)O_NONBLOCK));

#ifdef SO_NOSIGPIPE
		/* For platforms without MSG_NOSIGNAL. Harmless where both exist. */
		int on = 1;
		(void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof on);
#endif

		p->stats.opened++;
		return TC_OK;
	}
	/* The caller keeps the socket, and can decide whether to refuse the
	 * connection politely or wait. Closing it here would take that away. */
	return TC_ERR_TOOMANY;
}

/* ---- one pair, one pass ------------------------------------------------ */

/* pump_tunnel_to_host drains the tunnel into the staging buffer and the
 * staging buffer into the socket. */
static bool pump_tunnel_to_host(tc_proxy *p, pair *pr)
{
	bool moved = false;

	if (!pr->tun_eof && pr->to_host_len == 0) {
		pr->to_host_off = 0;
		size_t n = 0;
		if (tc_tcp_read(pr->tun, pr->to_host, sizeof pr->to_host, &n) ==
		        TC_OK &&
		    n > 0) {
			pr->to_host_len = n;
			moved = true;
		}
		if (tc_tcp_read_closed(pr->tun)) {
			pr->tun_eof = true;
			moved = true;
		}
	}

	while (pr->to_host_off < pr->to_host_len) {
		ssize_t w = send(pr->fd, pr->to_host + pr->to_host_off,
		                 pr->to_host_len - pr->to_host_off, MSG_NOSIGNAL);
		if (w > 0) {
			pr->to_host_off += (size_t)w;
			p->stats.bytes_to_host += (uint64_t)w;
			moved = true;
			continue;
		}
		if (w < 0 && errno == EINTR)
			continue;
		if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			break; /* poll will say when there is room */
		/* EPIPE and ECONNRESET are the ordinary way a local service exits
		 * while its peer is still talking; they end this pair and nothing
		 * else. */
		pr->failed = true;
		return true;
	}
	if (pr->to_host_off == pr->to_host_len) {
		pr->to_host_off = 0;
		pr->to_host_len = 0;
	}

	/* The peer has finished and everything it said has been delivered, so
	 * the local service is told. A service waiting for EOF -- which is most
	 * of them -- hangs forever without this. */
	if (pr->tun_eof && pr->to_host_len == 0 && !pr->host_shut) {
		(void)shutdown(pr->fd, SHUT_WR);
		pr->host_shut = true;
		moved = true;
	}
	return moved;
}

static bool pump_host_to_tunnel(tc_proxy *p, pair *pr, uint64_t now_ms)
{
	bool moved = false;

	if (!pr->host_eof && pr->to_tun_len == 0) {
		pr->to_tun_off = 0;
		for (;;) {
			ssize_t r = recv(pr->fd, pr->to_tun, sizeof pr->to_tun,
			                 MSG_NOSIGNAL);
			if (r > 0) {
				pr->to_tun_len = (size_t)r;
				moved = true;
				break;
			}
			if (r == 0) {
				pr->host_eof = true;
				moved = true;
				break;
			}
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			pr->failed = true;
			return true;
		}
	}

	while (pr->to_tun_off < pr->to_tun_len) {
		size_t wrote = 0;
		if (tc_tcp_write(pr->tun, pr->to_tun + pr->to_tun_off,
		                 pr->to_tun_len - pr->to_tun_off, &wrote,
		                 now_ms) != TC_OK)
			break;
		if (wrote == 0)
			break; /* the send buffer is full; try again next pass */
		pr->to_tun_off += wrote;
		p->stats.bytes_to_tun += (uint64_t)wrote;
		moved = true;
	}
	if (pr->to_tun_off == pr->to_tun_len) {
		pr->to_tun_off = 0;
		pr->to_tun_len = 0;
	}

	if (pr->host_eof && pr->to_tun_len == 0 && !pr->tun_shut) {
		/* Only once everything read has been acknowledged, so the FIN cannot
		 * overtake data still in flight. */
		if (tc_tcp_send_unacked(pr->tun) == 0) {
			(void)tc_tcp_shutdown_write(pr->tun, now_ms);
			pr->tun_shut = true;
			moved = true;
		}
	}
	return moved;
}

size_t tc_proxy_pump(tc_proxy *p, uint64_t now_ms)
{
	if (p == NULL)
		return 0;
	size_t active = 0;

	for (size_t i = 0; i < p->cap; i++) {
		pair *pr = &p->pairs[i];
		if (!pr->used || pr->done)
			continue;

		bool moved = pump_tunnel_to_host(p, pr);
		if (pump_host_to_tunnel(p, pr, now_ms))
			moved = true;

		if (pr->failed) {
			pr->done = true;
			moved = true;
		} else if (tc_tcp_get_state(pr->tun) == TC_TCP_CLOSED) {
			/* The tunnel side is gone, orderly or not; there is nowhere left
			 * to put anything. */
			pr->done = true;
			moved = true;
		} else if (pr->tun_eof && pr->host_eof && pr->host_shut &&
		           pr->tun_shut && pr->to_host_len == 0 &&
		           pr->to_tun_len == 0) {
			/* Both directions said everything they had and both were told.
			 * Waiting for the tunnel's own close would hold the slot for a
			 * TIME_WAIT that the mux is already tracking. */
			pr->done = true;
			moved = true;
		}

		if (moved)
			active++;
	}
	return active;
}

size_t tc_proxy_reap(tc_proxy *p, uint64_t now_ms)
{
	(void)now_ms;
	if (p == NULL)
		return 0;
	size_t n = 0;
	for (size_t i = 0; i < p->cap; i++) {
		pair *pr = &p->pairs[i];
		if (!pr->used || !pr->done)
			continue;
		if (pr->failed)
			p->stats.failed++;
		p->stats.closed++;
		close_pair(p, pr);
		n++;
	}
	return n;
}

void tc_proxy_forget(tc_proxy *p, const tc_tcp_conn *tun)
{
	if (p == NULL || tun == NULL)
		return;
	for (size_t i = 0; i < p->cap; i++) {
		pair *pr = &p->pairs[i];
		if (!pr->used || pr->tun != tun)
			continue;
		p->stats.closed++;
		close_pair(p, pr);
		return;
	}
}

size_t tc_proxy_count(const tc_proxy *p)
{
	if (p == NULL)
		return 0;
	size_t n = 0;
	for (size_t i = 0; i < p->cap; i++)
		if (p->pairs[i].used)
			n++;
	return n;
}

bool tc_proxy_interest(const tc_proxy *p, size_t i, int *fd, bool *want_read,
                       bool *want_write)
{
	if (p == NULL || i >= p->cap || fd == NULL || want_read == NULL ||
	    want_write == NULL)
		return false;
	const pair *pr = &p->pairs[i];
	if (!pr->used || pr->done)
		return false;

	*fd = pr->fd;
	*want_read = !pr->host_eof && pr->to_tun_len == 0;
	*want_write = pr->to_host_off < pr->to_host_len;
	return true;
}

void tc_proxy_get_stats(const tc_proxy *p, tc_proxy_stats *out)
{
	if (out == NULL)
		return;
	if (p == NULL)
		memset(out, 0, sizeof *out);
	else
		*out = p->stats;
}
