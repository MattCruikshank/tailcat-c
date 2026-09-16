/* SPDX-License-Identifier: BSD-3-Clause
 *
 * See http.h. One GET, over TLS, with a bounded response.
 */

#include "tc/http.h"

#include "tc/tls.h"

#include <stdio.h>
#include <string.h>

static _Thread_local char g_err[256];

const char *tc_http_error_string(void)
{
	return g_err;
}

#define FAILF(...)                                                            \
	do {                                                                      \
		(void)snprintf(g_err, sizeof g_err, __VA_ARGS__);                     \
	} while (0)

int tc_http_parse_url(const char *url, char *host, size_t host_cap,
                      uint16_t *port, char *path, size_t path_cap)
{
	if (url == NULL || host == NULL || port == NULL || path == NULL)
		return TC_ERR_INVAL;

	static const char kScheme[] = "https://";
	if (strncmp(url, kScheme, sizeof kScheme - 1) != 0) {
		FAILF("only https URLs are accepted");
		return TC_ERR_INVAL;
	}
	const char *p = url + sizeof kScheme - 1;

	/* The authority runs to the first '/', '?' or end. */
	size_t auth_len = strcspn(p, "/?");
	if (auth_len == 0)
		return TC_ERR_INVAL;

	/* Reject userinfo: it has no place here and is a phishing vector. */
	if (memchr(p, '@', auth_len) != NULL) {
		FAILF("URLs with userinfo are refused");
		return TC_ERR_INVAL;
	}

	const char *colon = memchr(p, ':', auth_len);
	size_t host_len = colon ? (size_t)(colon - p) : auth_len;
	if (host_len == 0 || host_len >= host_cap)
		return TC_ERR_NOSPACE;
	memcpy(host, p, host_len);
	host[host_len] = '\0';

	*port = 443;
	if (colon != NULL) {
		unsigned long v = 0;
		for (const char *q = colon + 1; q < p + auth_len; q++) {
			if (*q < '0' || *q > '9')
				return TC_ERR_INVAL;
			v = v * 10u + (unsigned long)(*q - '0');
			if (v > 65535u)
				return TC_ERR_RANGE;
		}
		if (v == 0)
			return TC_ERR_INVAL;
		*port = (uint16_t)v;
	}

	const char *rest = p + auth_len;
	if (*rest == '\0')
		rest = "/";
	if (strlen(rest) >= path_cap)
		return TC_ERR_NOSPACE;
	(void)snprintf(path, path_cap, "%s", rest);
	return TC_OK;
}

/* read_line reads one CRLF-terminated line into buf, without the CRLF. */
static int read_line(tc_stream *s, char *buf, size_t cap, size_t *len)
{
	size_t n = 0;
	for (;;) {
		if (n + 1 >= cap)
			return TC_ERR_TOOMANY;
		uint8_t c = 0;
		int rc = tc_stream_read_full(s, &c, 1);
		if (rc != TC_OK)
			return rc;
		if (c == '\n') {
			if (n > 0 && buf[n - 1] == '\r')
				n--;
			buf[n] = '\0';
			*len = n;
			return TC_OK;
		}
		buf[n++] = (char)c;
	}
}

static bool header_is(const char *line, const char *name, const char **value)
{
	size_t n = strlen(name);
	if (strncasecmp(line, name, n) != 0 || line[n] != ':')
		return false;
	const char *v = line + n + 1;
	while (*v == ' ' || *v == '\t')
		v++;
	*value = v;
	return true;
}

/* parse_hex_size reads a chunk size, refusing anything that would not fit. */
static int parse_hex_size(const char *s, size_t *out)
{
	uint64_t v = 0;
	size_t digits = 0;
	for (; *s != '\0' && *s != ';'; s++) {
		int d;
		if (*s >= '0' && *s <= '9')
			d = *s - '0';
		else if (*s >= 'a' && *s <= 'f')
			d = *s - 'a' + 10;
		else if (*s >= 'A' && *s <= 'F')
			d = *s - 'A' + 10;
		else if (*s == ' ' || *s == '\t')
			break;
		else
			return TC_ERR_INVAL;
		if (v > (UINT64_MAX - (uint64_t)d) / 16u)
			return TC_ERR_RANGE;
		v = v * 16u + (uint64_t)d;
		digits++;
	}
	if (digits == 0 || v > SIZE_MAX)
		return TC_ERR_INVAL;
	*out = (size_t)v;
	return TC_OK;
}

/* fetch_once does one request, reporting a redirect target if it gets one. */
static int fetch_once(const char *host, uint16_t port, const char *path,
                      uint8_t *out, size_t cap, size_t *out_len, int *status,
                      char *redirect, size_t redirect_cap,
                      const tc_http_options *opts)
{
	int timeout = (opts != NULL && opts->timeout_ms > 0) ? opts->timeout_ms
	                                                     : 15000;
	tc_stream tcp, tls;
	memset(&tcp, 0, sizeof tcp);
	memset(&tls, 0, sizeof tls);

	int rc = tc_net_tcp_connect(&tcp, host, port, timeout);
	if (rc != TC_OK) {
		FAILF("could not connect to %.120s port %u", host, (unsigned)port);
		return rc;
	}

	tc_tls_config cfg;
	memset(&cfg, 0, sizeof cfg);
	cfg.server_name = host;
	cfg.insecure_skip_verify = (opts != NULL && opts->insecure_skip_verify);

	rc = tc_tls_client(&tls, &tcp, &cfg);
	if (rc != TC_OK) {
		FAILF("TLS to %.80s failed: %s", host, tc_tls_error_string());
		tcp.close(&tcp);
		return rc;
	}
	(void)tc_stream_set_read_timeout(&tls, timeout);

	char req[1024];
	int reqlen = snprintf(req, sizeof req,
	                      "GET %s HTTP/1.1\r\n"
	                      "Host: %s\r\n"
	                      "User-Agent: tailcat-c/0.1\r\n"
	                      "Accept: application/json\r\n"
	                      "Connection: close\r\n"
	                      "\r\n",
	                      path, host);
	if (reqlen <= 0 || (size_t)reqlen >= sizeof req) {
		FAILF("request line too long");
		rc = TC_ERR_NOSPACE;
		goto done;
	}
	rc = tls.write_all(&tls, (const uint8_t *)req, (size_t)reqlen);
	if (rc != TC_OK) {
		FAILF("could not send the request");
		goto done;
	}

	char line[2048];
	size_t line_len = 0;
	rc = read_line(&tls, line, sizeof line, &line_len);
	if (rc != TC_OK) {
		FAILF("no response from %.120s", host);
		goto done;
	}
	if (strncmp(line, "HTTP/1.", 7) != 0 || line_len < 12) {
		FAILF("not an HTTP response: \"%.60s\"", line);
		rc = TC_ERR_INVAL;
		goto done;
	}
	*status = (line[9] - '0') * 100 + (line[10] - '0') * 10 + (line[11] - '0');

	bool chunked = false;
	bool have_len = false;
	size_t content_len = 0;
	size_t header_bytes = 0;

	for (;;) {
		rc = read_line(&tls, line, sizeof line, &line_len);
		if (rc != TC_OK) {
			FAILF("truncated headers");
			goto done;
		}
		header_bytes += line_len + 2;
		if (header_bytes > TC_HTTP_MAX_HEADERS) {
			FAILF("header block exceeded %d bytes", TC_HTTP_MAX_HEADERS);
			rc = TC_ERR_TOOMANY;
			goto done;
		}
		if (line_len == 0)
			break; /* end of headers */

		const char *v = NULL;
		if (header_is(line, "Transfer-Encoding", &v)) {
			if (strcasecmp(v, "chunked") == 0)
				chunked = true;
		} else if (header_is(line, "Content-Length", &v)) {
			uint64_t n = 0;
			for (; *v >= '0' && *v <= '9'; v++) {
				if (n > (UINT64_MAX - 9u) / 10u) {
					rc = TC_ERR_RANGE;
					goto done;
				}
				n = n * 10u + (uint64_t)(*v - '0');
			}
			content_len = (size_t)n;
			have_len = true;
		} else if (redirect != NULL && header_is(line, "Location", &v)) {
			(void)snprintf(redirect, redirect_cap, "%s", v);
		}
	}

	if (*status >= 300 && *status < 400 && redirect != NULL &&
	    redirect[0] != '\0') {
		rc = TC_OK;
		*out_len = 0;
		goto done;
	}

	size_t n = 0;
	if (chunked) {
		for (;;) {
			rc = read_line(&tls, line, sizeof line, &line_len);
			if (rc != TC_OK)
				goto done;
			size_t chunk = 0;
			rc = parse_hex_size(line, &chunk);
			if (rc != TC_OK) {
				FAILF("bad chunk size \"%.32s\"", line);
				goto done;
			}
			if (chunk == 0)
				break;
			if (chunk > cap - n) {
				FAILF("response body exceeds the %zu byte buffer", cap);
				rc = TC_ERR_TOOMANY;
				goto done;
			}
			rc = tc_stream_read_full(&tls, out + n, chunk);
			if (rc != TC_OK)
				goto done;
			n += chunk;
			/* Each chunk is followed by its own CRLF. */
			rc = read_line(&tls, line, sizeof line, &line_len);
			if (rc != TC_OK || line_len != 0) {
				FAILF("malformed chunk terminator");
				rc = TC_ERR_INVAL;
				goto done;
			}
		}
		/* Trailers, if any, run to a blank line. */
		for (;;) {
			rc = read_line(&tls, line, sizeof line, &line_len);
			if (rc != TC_OK || line_len == 0)
				break;
		}
		rc = TC_OK;
	} else if (have_len) {
		if (content_len > cap) {
			FAILF("response of %zu bytes exceeds the %zu byte buffer",
			      content_len, cap);
			rc = TC_ERR_TOOMANY;
			goto done;
		}
		if (content_len > 0) {
			rc = tc_stream_read_full(&tls, out, content_len);
			if (rc != TC_OK) {
				FAILF("truncated body");
				goto done;
			}
		}
		n = content_len;
	} else {
		/* No length and no chunking: read until the peer closes, which is
		 * what "Connection: close" invites. */
		for (;;) {
			size_t got = 0;
			if (n >= cap) {
				FAILF("response body exceeds the %zu byte buffer", cap);
				rc = TC_ERR_TOOMANY;
				goto done;
			}
			int r2 = tls.read_some(&tls, out + n, cap - n, &got);
			if (r2 == TC_ERR_TRUNC)
				break;
			if (r2 != TC_OK) {
				rc = r2;
				goto done;
			}
			n += got;
		}
		rc = TC_OK;
	}

	*out_len = n;

done:
	tls.close(&tls);
	return rc;
}

int tc_http_get(const char *url, uint8_t *out, size_t cap, size_t *out_len,
                int *status, const tc_http_options *opts)
{
	if (url == NULL || out == NULL || out_len == NULL || status == NULL)
		return TC_ERR_INVAL;

	g_err[0] = '\0';
	*out_len = 0;
	*status = 0;

	char current[1024];
	(void)snprintf(current, sizeof current, "%s", url);

	for (int hop = 0; hop <= TC_HTTP_MAX_REDIRECTS; hop++) {
		char host[256], path[768];
		uint16_t port = 443;
		int rc = tc_http_parse_url(current, host, sizeof host, &port, path,
		                           sizeof path);
		if (rc != TC_OK) {
			if (g_err[0] == '\0')
				FAILF("malformed URL");
			return rc;
		}

		char redirect[1024];
		redirect[0] = '\0';
		rc = fetch_once(host, port, path, out, cap, out_len, status, redirect,
		                sizeof redirect, opts);
		if (rc != TC_OK)
			return rc;

		if (*status >= 300 && *status < 400 && redirect[0] != '\0') {
			/* Only absolute https targets: a relative or http redirect
			 * would either need URL resolution or drop to cleartext. */
			if (strncmp(redirect, "https://", 8) != 0) {
				FAILF("refusing a redirect to \"%.60s\"", redirect);
				return TC_ERR_INVAL;
			}
			(void)snprintf(current, sizeof current, "%s", redirect);
			continue;
		}
		return TC_OK;
	}

	FAILF("too many redirects");
	return TC_ERR_TOOMANY;
}
