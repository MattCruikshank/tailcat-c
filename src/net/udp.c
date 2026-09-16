/* SPDX-License-Identifier: BSD-3-Clause
 *
 * See udp.h.
 */

#include "tc/udp.h"

#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ---- sockaddr conversion ----------------------------------------------- */

/* to_sockaddr fills a sockaddr_storage; returns its length, or 0. */
static socklen_t to_sockaddr(struct sockaddr_storage *ss,
                             const tc_endpoint *ep)
{
	memset(ss, 0, sizeof *ss);
	if (ep->ip_len == 4) {
		struct sockaddr_in *a = (struct sockaddr_in *)ss;
		a->sin_family = (uint16_t)AF_INET;
		a->sin_port = htons(ep->port);
		memcpy(&a->sin_addr, ep->ip, 4);
		return sizeof *a;
	}
	if (ep->ip_len == 16) {
		struct sockaddr_in6 *a = (struct sockaddr_in6 *)ss;
		a->sin6_family = (uint16_t)AF_INET6;
		a->sin6_port = htons(ep->port);
		memcpy(&a->sin6_addr, ep->ip, 16);
		return sizeof *a;
	}
	return 0;
}

static bool from_sockaddr(tc_endpoint *ep, const struct sockaddr *sa)
{
	memset(ep, 0, sizeof *ep);
	if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *a = (const struct sockaddr_in *)sa;
		memcpy(ep->ip, &a->sin_addr, 4);
		ep->ip_len = 4;
		ep->port = ntohs(a->sin_port);
		return true;
	}
	if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)sa;
		memcpy(ep->ip, &a->sin6_addr, 16);
		ep->ip_len = 16;
		ep->port = ntohs(a->sin6_port);
		return true;
	}
	return false;
}

static void set_nonblocking(int fd)
{
	int fl = fcntl(fd, F_GETFL, 0);
	if (fl >= 0)
		(void)fcntl(fd, F_SETFL, (int)((unsigned)fl | (unsigned)O_NONBLOCK));
}

/* bound_port reads back what the kernel actually chose. */
static uint16_t bound_port(int fd)
{
	struct sockaddr_storage ss;
	socklen_t len = sizeof ss;
	if (getsockname(fd, (struct sockaddr *)&ss, &len) != 0)
		return 0;
	tc_endpoint ep;
	if (!from_sockaddr(&ep, (struct sockaddr *)&ss))
		return 0;
	return ep.port;
}

int tc_udp_open(tc_udp *u, uint16_t port)
{
	if (u == NULL)
		return TC_ERR_INVAL;
	memset(u, 0, sizeof *u);
	u->fd4 = -1;
	u->fd6 = -1;

	/* IPv4 first, so that with port 0 the kernel's choice becomes the port
	 * IPv6 then asks for. Doing it the other way round works equally well;
	 * what matters is that one of them leads and the other follows. */
	int fd4 = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd4 >= 0) {
		struct sockaddr_in a;
		memset(&a, 0, sizeof a);
		a.sin_family = (uint16_t)AF_INET;
		a.sin_addr.s_addr = htonl(INADDR_ANY);
		a.sin_port = htons(port);
		if (bind(fd4, (struct sockaddr *)&a, sizeof a) == 0) {
			set_nonblocking(fd4);
			u->fd4 = fd4;
			u->port = bound_port(fd4);
		} else {
			(void)close(fd4);
		}
	}

	uint16_t want6 = (u->port != 0) ? u->port : port;
	int fd6 = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd6 >= 0) {
		/* V6ONLY on purpose: the IPv4 socket handles IPv4, and a dual-stack
		 * socket would deliver the same packets to both with two spellings
		 * of every address. */
		int on = 1;
		(void)setsockopt(fd6, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof on);

		struct sockaddr_in6 a;
		memset(&a, 0, sizeof a);
		a.sin6_family = (uint16_t)AF_INET6;
		a.sin6_addr = in6addr_any;
		a.sin6_port = htons(want6);
		if (bind(fd6, (struct sockaddr *)&a, sizeof a) != 0 && want6 != 0) {
			/* The matching port was taken. A different one is worse -- a peer
			 * told one number now needs two -- but it beats no IPv6 at all. */
			a.sin6_port = 0;
			if (bind(fd6, (struct sockaddr *)&a, sizeof a) != 0) {
				(void)close(fd6);
				fd6 = -1;
			}
		}
		if (fd6 >= 0) {
			set_nonblocking(fd6);
			u->fd6 = fd6;
			if (u->port == 0)
				u->port = bound_port(fd6);
		}
	}

	if (u->fd4 < 0 && u->fd6 < 0)
		return TC_ERR_INVAL;
	return TC_OK;
}

void tc_udp_close(tc_udp *u)
{
	if (u == NULL)
		return;
	if (u->fd4 >= 0)
		(void)close(u->fd4);
	if (u->fd6 >= 0)
		(void)close(u->fd6);
	u->fd4 = -1;
	u->fd6 = -1;
	u->port = 0;
}

int tc_udp_send(tc_udp *u, const tc_endpoint *dst, const void *pkt, size_t len)
{
	if (u == NULL || dst == NULL || (pkt == NULL && len != 0))
		return TC_ERR_INVAL;

	int fd = (dst->ip_len == 4) ? u->fd4 : (dst->ip_len == 16) ? u->fd6 : -1;
	if (fd < 0)
		return TC_ERR_INVAL;

	struct sockaddr_storage ss;
	socklen_t slen = to_sockaddr(&ss, dst);
	if (slen == 0)
		return TC_ERR_INVAL;

	for (;;) {
		ssize_t n = sendto(fd, pkt, len, 0, (struct sockaddr *)&ss, slen);
		if (n >= 0)
			return TC_OK;
		if (errno == EINTR)
			continue;
		/* A datagram that will not go is loss, and everything above this
		 * already treats loss as ordinary. Reporting it as an error would
		 * make a transient ICMP unreachable look like a broken tunnel. */
		return TC_ERR_AGAIN;
	}
}

int tc_udp_recv(tc_udp *u, tc_endpoint *src, uint8_t *buf, size_t cap,
                size_t *out_len, int timeout_ms)
{
	if (u == NULL || src == NULL || buf == NULL || out_len == NULL)
		return TC_ERR_INVAL;
	*out_len = 0;

	struct pollfd pfds[2];
	nfds_t n = 0;
	if (u->fd4 >= 0) {
		pfds[n].fd = u->fd4;
		pfds[n].events = POLLIN;
		pfds[n].revents = 0;
		n++;
	}
	if (u->fd6 >= 0) {
		pfds[n].fd = u->fd6;
		pfds[n].events = POLLIN;
		pfds[n].revents = 0;
		n++;
	}
	if (n == 0)
		return TC_ERR_INVAL;

	int r = poll(pfds, n, timeout_ms);
	if (r == 0)
		return TC_ERR_TIMEOUT;
	if (r < 0)
		return (errno == EINTR) ? TC_ERR_TIMEOUT : TC_ERR_INVAL;

	for (nfds_t i = 0; i < n; i++) {
		if ((pfds[i].revents & POLLIN) == 0)
			continue;
		struct sockaddr_storage ss;
		socklen_t slen = sizeof ss;
		ssize_t got =
		    recvfrom(pfds[i].fd, buf, cap, 0, (struct sockaddr *)&ss, &slen);
		if (got < 0)
			continue;
		if (!from_sockaddr(src, (struct sockaddr *)&ss))
			continue;
		*out_len = (size_t)got;
		return TC_OK;
	}
	return TC_ERR_TIMEOUT;
}

size_t tc_udp_fds(const tc_udp *u, int *out, size_t cap)
{
	if (u == NULL || out == NULL)
		return 0;
	size_t n = 0;
	if (u->fd4 >= 0 && n < cap)
		out[n++] = u->fd4;
	if (u->fd6 >= 0 && n < cap)
		out[n++] = u->fd6;
	return n;
}

size_t tc_udp_local_endpoints(const tc_udp *u, tc_endpoint *out, size_t cap)
{
	if (u == NULL || out == NULL || cap == 0)
		return 0;

	struct ifaddrs *list = NULL;
	if (getifaddrs(&list) != 0 || list == NULL)
		return 0;

	size_t n = 0;
	for (struct ifaddrs *ifa = list; ifa != NULL && n < cap;
	     ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;
		if ((ifa->ifa_flags & IFF_UP) == 0)
			continue;

		tc_endpoint ep;
		if (!from_sockaddr(&ep, ifa->ifa_addr))
			continue;
		/* getifaddrs reports the interface address with no port; ours is
		 * whatever the socket bound to. */
		ep.port = u->port;
		if (!tc_endpoint_is_candidate(&ep))
			continue;

		/* A machine can report the same address on several interfaces, and a
		 * duplicate candidate is a duplicate probe. */
		bool seen = false;
		for (size_t i = 0; i < n && !seen; i++)
			seen = tc_endpoint_equal(&out[i], &ep);
		if (seen)
			continue;

		out[n++] = ep;
	}

	freeifaddrs(list);
	return n;
}
