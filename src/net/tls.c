/* SPDX-License-Identifier: BSD-3-Clause
 *
 * TCP and TLS transports behind the tc_stream interface.
 *
 * Cosmopolitan gives us BSD sockets on every target, so the TCP half is
 * ordinary POSIX. Note the deliberate use of getaddrinfo/poll rather than
 * anything epoll- or kqueue-flavoured: this has to compile once and run on
 * six operating systems.
 */

#include "tc/tls.h"

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* ---- shared helpers -------------------------------------------------- */

int tc_stream_fd(tc_stream *s)
{
	if (s == NULL || s->get_fd == NULL)
		return -1;
	return s->get_fd(s);
}

bool tc_stream_has_pending(tc_stream *s)
{
	return s != NULL && s->has_pending != NULL && s->has_pending(s);
}

int tc_stream_set_read_timeout(tc_stream *s, int ms)
{
	if (s == NULL)
		return TC_ERR_INVAL;
	if (s->set_read_timeout == NULL)
		return TC_ERR_UNSUPPORTED;
	return s->set_read_timeout(s, ms);
}

int tc_stream_read_full(tc_stream *s, uint8_t *buf, size_t len)
{
	/* A timeout partway through is NOT passed to the caller. The bytes
	 * already read have been consumed from the stream, so returning now
	 * would lose them and desynchronise whatever framing sits above -- the
	 * next read would start mid-frame. Since a timeout means "nothing more
	 * has arrived yet" rather than "this is broken", keep waiting for the
	 * rest of the item; a timeout is only reportable before any of it has
	 * been consumed.
	 *
	 * A peer that sends half an item and then stalls forever would otherwise
	 * block us forever, so that is bounded and reported as truncation, which
	 * is fatal to the connection -- correct, because the framing really is
	 * lost at that point. */
	enum { MAX_PARTIAL_STALLS = 100 };
	size_t got = 0;
	unsigned stalls = 0;

	while (got < len) {
		size_t n = 0;
		int rc = s->read_some(s, buf + got, len - got, &n);
		if (rc == TC_ERR_TIMEOUT) {
			if (got == 0)
				return TC_ERR_TIMEOUT;
			if (++stalls > MAX_PARTIAL_STALLS)
				return TC_ERR_TRUNC;
			continue;
		}
		if (rc != TC_OK)
			return rc;
		if (n == 0)
			return TC_ERR_TRUNC;
		got += n;
		stalls = 0;
	}
	return TC_OK;
}

/* Per-thread space for the last TLS error, so a handshake failure can say
 * what actually went wrong rather than just TC_ERR_INVAL. */
static _Thread_local char g_tls_err[192];

const char *tc_tls_error_string(void)
{
	return g_tls_err;
}

static void set_tls_err(const char *what, int mbed_rc)
{
	char detail[128];
	mbedtls_strerror(mbed_rc, detail, sizeof detail);
	(void)snprintf(g_tls_err, sizeof g_tls_err, "%s: %s (-0x%04x)", what,
	               detail, (unsigned)-mbed_rc);
}

/* ---- TCP ------------------------------------------------------------- */

typedef struct {
	int fd;
} tcp_ctx;

static int tcp_read_some(tc_stream *s, uint8_t *buf, size_t len, size_t *nread)
{
	tcp_ctx *c = (tcp_ctx *)s->ctx;
	for (;;) {
		ssize_t n = recv(c->fd, buf, len, 0);
		if (n > 0) {
			*nread = (size_t)n;
			return TC_OK;
		}
		if (n == 0)
			return TC_ERR_TRUNC; /* orderly shutdown */
		if (errno == EINTR)
			continue;
		/* SO_RCVTIMEO expiring looks exactly like a non-blocking socket
		 * with nothing to read; the socket is otherwise fine. */
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return TC_ERR_TIMEOUT;
		return TC_ERR_INVAL;
	}
}

static int tcp_write_all(tc_stream *s, const uint8_t *buf, size_t len)
{
	tcp_ctx *c = (tcp_ctx *)s->ctx;
	size_t off = 0;
	while (off < len) {
		ssize_t n = send(c->fd, buf + off, len - off, 0);
		if (n > 0) {
			off += (size_t)n;
			continue;
		}
		if (n < 0 && errno == EINTR)
			continue;
		return TC_ERR_INVAL;
	}
	return TC_OK;
}

static int tcp_set_read_timeout(tc_stream *s, int ms)
{
	tcp_ctx *c = (tcp_ctx *)s->ctx;
	struct timeval tv;
	tv.tv_sec = ms / 1000;
	tv.tv_usec = (ms % 1000) * 1000;
	if (setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, (const void *)&tv,
	               sizeof tv) != 0)
		return TC_ERR_INVAL;
	return TC_OK;
}

static int tcp_fd(tc_stream *s)
{
	tcp_ctx *c = (tcp_ctx *)s->ctx;
	return c == NULL ? -1 : c->fd;
}

static void tcp_close(tc_stream *s)
{
	tcp_ctx *c = (tcp_ctx *)s->ctx;
	if (c == NULL)
		return;
	if (c->fd >= 0)
		close(c->fd);
	c->fd = -1;
	free(c);
	s->ctx = NULL;
}

/* connect_with_timeout connects fd non-blocking, waits with poll, then
 * restores blocking mode. Done by hand because there is no portable
 * connect timeout. */
static int connect_with_timeout(int fd, const struct sockaddr *addr,
                                socklen_t addrlen, int timeout_ms)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0)
		return TC_ERR_INVAL;
	/* O_NONBLOCK is unsigned on some of the platforms this fat binary
	 * targets, so combine in unsigned and convert back deliberately rather
	 * than letting the sign of the result depend on the host. */
	int nonblock = (int)((unsigned)flags | (unsigned)O_NONBLOCK);
	if (fcntl(fd, F_SETFL, nonblock) < 0)
		return TC_ERR_INVAL;

	int rc = TC_ERR_INVAL;
	if (connect(fd, addr, addrlen) == 0) {
		rc = TC_OK;
	} else if (errno == EINPROGRESS || errno == EWOULDBLOCK) {
		struct pollfd pfd = { .fd = fd, .events = POLLOUT, .revents = 0 };
		int pr = poll(&pfd, 1, timeout_ms > 0 ? timeout_ms : -1);
		if (pr > 0) {
			int soerr = 0;
			socklen_t slen = sizeof soerr;
			if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) == 0 &&
			    soerr == 0)
				rc = TC_OK;
		}
	}

	/* Put the socket back into blocking mode either way: the rest of the
	 * code is written against blocking reads and writes. */
	(void)fcntl(fd, F_SETFL, flags);
	return rc;
}

int tc_net_tcp_connect(tc_stream *out, const char *host, uint16_t port,
                   int timeout_ms)
{
	if (out == NULL || host == NULL)
		return TC_ERR_INVAL;

	char portstr[8];
	(void)snprintf(portstr, sizeof portstr, "%u", (unsigned)port);

	struct addrinfo hints;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC; /* IPv4 or IPv6, whichever resolves */
	hints.ai_socktype = SOCK_STREAM;

	struct addrinfo *res = NULL;
	if (getaddrinfo(host, portstr, &hints, &res) != 0 || res == NULL)
		return TC_ERR_INVAL;

	int fd = -1;
	for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0)
			continue;
		if (connect_with_timeout(fd, ai->ai_addr, ai->ai_addrlen,
		                         timeout_ms) == TC_OK)
			break;
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);

	if (fd < 0)
		return TC_ERR_INVAL;

	/* DERP is a latency-sensitive relay carrying small packets; Nagle would
	 * add delay for no benefit. */
	int one = 1;
	(void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const void *)&one,
	                 sizeof one);

	tcp_ctx *c = (tcp_ctx *)calloc(1, sizeof *c);
	if (c == NULL) {
		close(fd);
		return TC_ERR_INVAL;
	}
	c->fd = fd;

	out->read_some = tcp_read_some;
	out->write_all = tcp_write_all;
	out->set_read_timeout = tcp_set_read_timeout;
	out->get_fd = tcp_fd;
	out->has_pending = NULL;
	out->close = tcp_close;
	out->ctx = c;
	return TC_OK;
}

/* ---- TLS ------------------------------------------------------------- */

typedef struct {
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt ca;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context drbg;
	tc_stream tcp; /* owned once the handshake succeeds */
	/* Set by the BIO when the underlying read timed out, so tls_read_some can
	 * tell that apart from an ordinary "no data yet". */
	bool timed_out;
} tls_ctx;

/* mbedTLS calls these to move bytes; they just forward to the TCP stream. */
static int tls_bio_send(void *p, const unsigned char *buf, size_t len)
{
	tls_ctx *t = (tls_ctx *)p;
	if (t->tcp.write_all(&t->tcp, buf, len) != TC_OK)
		return MBEDTLS_ERR_NET_SEND_FAILED;
	return (int)len;
}

static int tls_bio_recv(void *p, unsigned char *buf, size_t len)
{
	tls_ctx *t = (tls_ctx *)p;
	size_t n = 0;
	int rc = t->tcp.read_some(&t->tcp, buf, len, &n);
	if (rc == TC_ERR_TRUNC)
		return 0; /* clean EOF */
	if (rc == TC_ERR_TIMEOUT) {
		/* WANT_READ rather than an error: the record layer keeps whatever it
		 * has already consumed, so a later read resumes mid-record instead of
		 * tearing the session down. The flag tells tls_read_some to surface
		 * this to the caller rather than spin. */
		t->timed_out = true;
		return MBEDTLS_ERR_SSL_WANT_READ;
	}
	if (rc != TC_OK)
		return MBEDTLS_ERR_NET_RECV_FAILED;
	return (int)n;
}

static int tls_read_some(tc_stream *s, uint8_t *buf, size_t len, size_t *nread)
{
	tls_ctx *t = (tls_ctx *)s->ctx;
	for (;;) {
		int n = mbedtls_ssl_read(&t->ssl, buf, len);
		if (n > 0) {
			*nread = (size_t)n;
			return TC_OK;
		}
		if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) {
			if (t->timed_out) {
				t->timed_out = false;
				return TC_ERR_TIMEOUT;
			}
			continue;
		}
		if (n == 0 || n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
			return TC_ERR_TRUNC;
		set_tls_err("tls read", n);
		return TC_ERR_INVAL;
	}
}

static int tls_write_all(tc_stream *s, const uint8_t *buf, size_t len)
{
	tls_ctx *t = (tls_ctx *)s->ctx;
	size_t off = 0;
	while (off < len) {
		int n = mbedtls_ssl_write(&t->ssl, buf + off, len - off);
		if (n > 0) {
			off += (size_t)n;
			continue;
		}
		if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE)
			continue;
		set_tls_err("tls write", n);
		return TC_ERR_INVAL;
	}
	return TC_OK;
}

static void tls_free(tls_ctx *t)
{
	mbedtls_ssl_free(&t->ssl);
	mbedtls_ssl_config_free(&t->conf);
	mbedtls_x509_crt_free(&t->ca);
	mbedtls_ctr_drbg_free(&t->drbg);
	mbedtls_entropy_free(&t->entropy);
	free(t);
}

static int tls_set_read_timeout(tc_stream *s, int ms)
{
	tls_ctx *t = (tls_ctx *)s->ctx;
	return tc_stream_set_read_timeout(&t->tcp, ms);
}

static int tls_fd(tc_stream *s)
{
	tls_ctx *t = (tls_ctx *)s->ctx;
	return (t == NULL || t->tcp.get_fd == NULL) ? -1 : t->tcp.get_fd(&t->tcp);
}

/* tls_has_pending reports whether a whole record is already buffered inside
 * the TLS layer. poll() on the socket cannot see that, so without this an
 * event loop can block on a socket that has nothing left while a complete
 * message sits decrypted and waiting. */
static bool tls_has_pending(tc_stream *s)
{
	tls_ctx *t = (tls_ctx *)s->ctx;
	if (t == NULL)
		return false;
	return mbedtls_ssl_get_bytes_avail(&t->ssl) > 0 ||
	       mbedtls_ssl_check_pending(&t->ssl) != 0;
}

static void tls_close(tc_stream *s)
{
	tls_ctx *t = (tls_ctx *)s->ctx;
	if (t == NULL)
		return;
	(void)mbedtls_ssl_close_notify(&t->ssl);
	if (t->tcp.close != NULL)
		t->tcp.close(&t->tcp);
	tls_free(t);
	s->ctx = NULL;
}

int tc_tls_client(tc_stream *out, tc_stream *tcp, const tc_tls_config *cfg)
{
	if (out == NULL || tcp == NULL || cfg == NULL || out == tcp)
		return TC_ERR_INVAL;
	if (!cfg->insecure_skip_verify && cfg->server_name == NULL)
		return TC_ERR_INVAL;

	g_tls_err[0] = '\0';

	tls_ctx *t = (tls_ctx *)calloc(1, sizeof *t);
	if (t == NULL)
		return TC_ERR_INVAL;

	mbedtls_ssl_init(&t->ssl);
	mbedtls_ssl_config_init(&t->conf);
	mbedtls_x509_crt_init(&t->ca);
	mbedtls_entropy_init(&t->entropy);
	mbedtls_ctr_drbg_init(&t->drbg);
	t->tcp = *tcp;

	int rc;
	if ((rc = mbedtls_ctr_drbg_seed(&t->drbg, mbedtls_entropy_func,
	                                &t->entropy,
	                                (const unsigned char *)"tailcat-c tls",
	                                13)) != 0) {
		set_tls_err("drbg seed", rc);
		goto fail;
	}

	if ((rc = mbedtls_ssl_config_defaults(&t->conf, MBEDTLS_SSL_IS_CLIENT,
	                                      MBEDTLS_SSL_TRANSPORT_STREAM,
	                                      MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
		set_tls_err("config defaults", rc);
		goto fail;
	}

	mbedtls_ssl_conf_rng(&t->conf, mbedtls_ctr_drbg_random, &t->drbg);

	if (cfg->insecure_skip_verify) {
		mbedtls_ssl_conf_authmode(&t->conf, MBEDTLS_SSL_VERIFY_NONE);
	} else {
		/* mbedtls_x509_crt_parse wants the NUL counted for PEM input, which
		 * is why tc_ca_bundle_pem_len includes it. */
		rc = mbedtls_x509_crt_parse(&t->ca,
		                            (const unsigned char *)tc_ca_bundle_pem,
		                            tc_ca_bundle_pem_len);
		if (rc < 0) {
			set_tls_err("parse ca bundle", rc);
			goto fail;
		}
		if (cfg->extra_ca_pem != NULL && cfg->extra_ca_pem_len > 0) {
			rc = mbedtls_x509_crt_parse(
			    &t->ca, (const unsigned char *)cfg->extra_ca_pem,
			    cfg->extra_ca_pem_len);
			if (rc < 0) {
				set_tls_err("parse extra ca", rc);
				goto fail;
			}
		}
		mbedtls_ssl_conf_ca_chain(&t->conf, &t->ca, NULL);
		mbedtls_ssl_conf_authmode(&t->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
	}

	/* TLS 1.2 is both the floor and the ceiling here; see the note in
	 * third_party/mbedtls_config.h about TLS 1.3 needing the PSA layer. */
	mbedtls_ssl_conf_min_tls_version(&t->conf, MBEDTLS_SSL_VERSION_TLS1_2);
	mbedtls_ssl_conf_max_tls_version(&t->conf, MBEDTLS_SSL_VERSION_TLS1_2);

	if ((rc = mbedtls_ssl_setup(&t->ssl, &t->conf)) != 0) {
		set_tls_err("ssl setup", rc);
		goto fail;
	}

	/* SNI. Required by essentially every real host, and it is also the name
	 * the certificate is checked against. */
	if (cfg->server_name != NULL &&
	    (rc = mbedtls_ssl_set_hostname(&t->ssl, cfg->server_name)) != 0) {
		set_tls_err("set hostname", rc);
		goto fail;
	}

	mbedtls_ssl_set_bio(&t->ssl, t, tls_bio_send, tls_bio_recv, NULL);

	while ((rc = mbedtls_ssl_handshake(&t->ssl)) != 0) {
		if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE)
			continue;
		set_tls_err("handshake", rc);
		goto fail;
	}

	if (!cfg->insecure_skip_verify) {
		uint32_t flags = mbedtls_ssl_get_verify_result(&t->ssl);
		if (flags != 0) {
			char why[128];
			mbedtls_x509_crt_verify_info(why, sizeof why, "", flags);
			(void)snprintf(g_tls_err, sizeof g_tls_err,
			               "certificate verification failed: %s", why);
			goto fail;
		}
	}

	out->read_some = tls_read_some;
	out->write_all = tls_write_all;
	out->set_read_timeout = tls_set_read_timeout;
	out->get_fd = tls_fd;
	out->has_pending = tls_has_pending;
	out->close = tls_close;
	out->ctx = t;

	/* Ownership of the TCP stream has moved into the TLS context; blank the
	 * caller's copy so a stray close() on it cannot close our socket. */
	memset(tcp, 0, sizeof *tcp);
	return TC_OK;

fail:
	/* The TCP stream is left alone for the caller to close, so drop our copy
	 * before freeing. */
	memset(&t->tcp, 0, sizeof t->tcp);
	tls_free(t);
	return TC_ERR_INVAL;
}
