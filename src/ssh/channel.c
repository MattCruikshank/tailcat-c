/* SPDX-License-Identifier: BSD-3-Clause
 *
 * RFC 4254, one session channel. See tc/sshchan.h for the reasoning.
 */

#include "tc/sshchan.h"

#include "tc/sshwire.h"

#include <string.h>

void tc_ssh_channel_init(tc_ssh_channel *ch)
{
	if (ch == NULL)
		return;
	memset(ch, 0, sizeof *ch);
	/* Any local id will do with one channel; a fixed one makes a transcript
	 * reproducible, and there is nothing to guess about it -- the id is
	 * public and carries no authority. */
	ch->local_id = 0;
	ch->local_window = TC_SSH_CHAN_WINDOW;
}

int tc_ssh_channel_open_parse(tc_ssh_channel *ch, char *out_type,
                              size_t type_cap, const uint8_t *payload,
                              size_t len)
{
	if (ch == NULL || out_type == NULL || type_cap == 0 || payload == NULL)
		return TC_ERR_INVAL;

	tc_ssh_rbuf r;
	tc_ssh_rbuf_init(&r, payload, len);
	if (tc_ssh_get_byte(&r) != TC_SSH_MSG_CHANNEL_OPEN)
		return TC_ERR_INVAL;
	if (!tc_ssh_get_cstring(&r, out_type, type_cap))
		return TC_ERR_INVAL;

	uint32_t remote_id = tc_ssh_get_u32(&r);
	uint32_t window = tc_ssh_get_u32(&r);
	uint32_t max_packet = tc_ssh_get_u32(&r);
	if (!tc_ssh_rbuf_ok(&r))
		return TC_ERR_INVAL;

	/* A peer that says it will accept zero-byte packets has said something
	 * that cannot be satisfied; treat it as malformed rather than looping
	 * forever trying to send nothing. */
	if (max_packet == 0)
		return TC_ERR_INVAL;
	/* And one that offers more than we would ever send is fine, but we clamp
	 * what we believe so our own framing stays inside one packet. */
	if (max_packet > TC_SSH_MAX_PAYLOAD)
		max_packet = TC_SSH_MAX_PAYLOAD;

	ch->remote_id = remote_id;
	ch->remote_window = window;
	ch->remote_max_packet = max_packet;
	return TC_OK;
}

int tc_ssh_channel_confirm_build(uint8_t *out, size_t cap, size_t *out_len,
                                 const tc_ssh_channel *ch)
{
	if (out == NULL || ch == NULL)
		return TC_ERR_INVAL;
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, out, cap);
	tc_ssh_put_byte(&w, TC_SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
	tc_ssh_put_u32(&w, ch->remote_id);
	tc_ssh_put_u32(&w, ch->local_id);
	tc_ssh_put_u32(&w, ch->local_window);
	tc_ssh_put_u32(&w, TC_SSH_CHAN_MAX_PACKET);
	if (!tc_ssh_wbuf_ok(&w))
		return TC_ERR_NOSPACE;
	if (out_len != NULL)
		*out_len = tc_ssh_wbuf_len(&w);
	return TC_OK;
}

int tc_ssh_channel_open_failure_build(uint8_t *out, size_t cap,
                                      size_t *out_len, uint32_t remote_id,
                                      uint32_t reason, const char *message)
{
	if (out == NULL)
		return TC_ERR_INVAL;
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, out, cap);
	tc_ssh_put_byte(&w, TC_SSH_MSG_CHANNEL_OPEN_FAILURE);
	tc_ssh_put_u32(&w, remote_id);
	tc_ssh_put_u32(&w, reason);
	tc_ssh_put_cstring(&w, message != NULL ? message : "");
	tc_ssh_put_cstring(&w, ""); /* language tag */
	if (!tc_ssh_wbuf_ok(&w))
		return TC_ERR_NOSPACE;
	if (out_len != NULL)
		*out_len = tc_ssh_wbuf_len(&w);
	return TC_OK;
}

bool tc_ssh_channel_id_matches(const tc_ssh_channel *ch,
                               const uint8_t *payload, size_t len)
{
	if (ch == NULL || payload == NULL)
		return false;
	tc_ssh_rbuf r;
	tc_ssh_rbuf_init(&r, payload, len);
	(void)tc_ssh_get_byte(&r);
	uint32_t id = tc_ssh_get_u32(&r);
	return tc_ssh_rbuf_ok(&r) && id == ch->local_id;
}

int tc_ssh_channel_request_parse(tc_ssh_channel_request *out,
                                 const tc_ssh_channel *ch,
                                 const uint8_t *payload, size_t len)
{
	if (out == NULL || ch == NULL || payload == NULL)
		return TC_ERR_INVAL;
	memset(out, 0, sizeof *out);

	tc_ssh_rbuf r;
	tc_ssh_rbuf_init(&r, payload, len);
	if (tc_ssh_get_byte(&r) != TC_SSH_MSG_CHANNEL_REQUEST)
		return TC_ERR_INVAL;
	if (tc_ssh_get_u32(&r) != ch->local_id)
		return TC_ERR_INVAL;

	char type[64];
	if (!tc_ssh_get_cstring(&r, type, sizeof type)) {
		/* A request type too long to name is one we do not implement. The
		 * want_reply flag is unreachable now, so the caller cannot answer it
		 * specifically -- but a client sending a 64-byte request type is not
		 * one of the two we handle. */
		return TC_ERR_INVAL;
	}
	out->want_reply = tc_ssh_get_bool(&r);
	if (!tc_ssh_rbuf_ok(&r))
		return TC_ERR_INVAL;

	if (strcmp(type, "subsystem") == 0) {
		out->type = TC_SSH_REQ_SUBSYSTEM;
		if (!tc_ssh_get_cstring(&r, out->arg, sizeof out->arg))
			return TC_ERR_INVAL;
	} else if (strcmp(type, "exec") == 0) {
		out->type = TC_SSH_REQ_EXEC;
		if (!tc_ssh_get_cstring(&r, out->arg, sizeof out->arg))
			return TC_ERR_INVAL;
	} else if (strcmp(type, "shell") == 0) {
		/* No arguments at all: RFC 4254 6.5 has shell carry nothing. */
		out->type = TC_SSH_REQ_SHELL;
	} else if (strcmp(type, "pty-req") == 0) {
		out->type = TC_SSH_REQ_PTY;
		/* RFC 4254 6.2: TERM, then character and pixel dimensions, then the
		 * encoded terminal modes -- which are deliberately not read. They
		 * describe the client's terminal, and the client is the end that
		 * puts itself into raw mode; applying them to our pty would fight
		 * it. A TERM too long to fit is truncated to nothing rather than
		 * refused, because a nameless terminal is a working session with a
		 * dumb terminal and a refused pty-req is no session at all. */
		size_t tlen = 0;
		const uint8_t *term = tc_ssh_get_string(&r, SIZE_MAX, &tlen);
		if (term != NULL && tlen < sizeof out->pty.term &&
		    memchr(term, 0, tlen) == NULL)
			memcpy(out->pty.term, term, tlen);
		/* Otherwise TERM stays the empty string it was memset to. Read as a
		 * raw string rather than with get_cstring, because get_cstring
		 * latches the whole buffer on a name that does not fit and the four
		 * numbers after it matter more than the name does. */
		out->pty.cols = tc_ssh_get_u32(&r);
		out->pty.rows = tc_ssh_get_u32(&r);
		out->pty.width_px = tc_ssh_get_u32(&r);
		out->pty.height_px = tc_ssh_get_u32(&r);
		if (!tc_ssh_rbuf_ok(&r))
			return TC_ERR_INVAL;
	} else if (strcmp(type, "window-change") == 0) {
		/* RFC 4254 6.7: the four numbers and nothing else. It never wants a
		 * reply, but it is parsed rather than ignored so a resized terminal
		 * reaches the shell. */
		out->type = TC_SSH_REQ_WINDOW_CHANGE;
		out->pty.cols = tc_ssh_get_u32(&r);
		out->pty.rows = tc_ssh_get_u32(&r);
		out->pty.width_px = tc_ssh_get_u32(&r);
		out->pty.height_px = tc_ssh_get_u32(&r);
		if (!tc_ssh_rbuf_ok(&r))
			return TC_ERR_INVAL;
	} else {
		/* env, x11-req, signal, agent forwarding and the rest. The arguments
		 * are left unread: we are going to refuse, and parsing a request in
		 * order to decline it only adds surface. */
		out->type = TC_SSH_REQ_OTHER;
	}
	return TC_OK;
}

int tc_ssh_channel_reply_build(uint8_t *out, size_t cap, size_t *out_len,
                               uint32_t remote_id, bool success)
{
	if (out == NULL)
		return TC_ERR_INVAL;
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, out, cap);
	tc_ssh_put_byte(&w, success ? TC_SSH_MSG_CHANNEL_SUCCESS
	                            : TC_SSH_MSG_CHANNEL_FAILURE);
	tc_ssh_put_u32(&w, remote_id);
	if (!tc_ssh_wbuf_ok(&w))
		return TC_ERR_NOSPACE;
	if (out_len != NULL)
		*out_len = tc_ssh_wbuf_len(&w);
	return TC_OK;
}

int tc_ssh_channel_data_parse(tc_ssh_channel *ch, const uint8_t **out_data,
                              size_t *out_len, const uint8_t *payload,
                              size_t len)
{
	if (ch == NULL || out_data == NULL || out_len == NULL || payload == NULL)
		return TC_ERR_INVAL;
	*out_data = NULL;
	*out_len = 0;

	tc_ssh_rbuf r;
	tc_ssh_rbuf_init(&r, payload, len);
	if (tc_ssh_get_byte(&r) != TC_SSH_MSG_CHANNEL_DATA)
		return TC_ERR_INVAL;
	if (tc_ssh_get_u32(&r) != ch->local_id)
		return TC_ERR_INVAL;

	size_t n = 0;
	const uint8_t *data = tc_ssh_get_string(&r, TC_SSH_MAX_PAYLOAD, &n);
	if (data == NULL || !tc_ssh_rbuf_ok(&r))
		return TC_ERR_INVAL;

	/* Flow control, enforced rather than assumed. A peer that overruns its
	 * window is broken or hostile, and either way every buffer downstream
	 * was sized on the promise it just broke. */
	if (n > ch->local_window)
		return TC_ERR_TOOMANY;
	ch->local_window -= (uint32_t)n;

	*out_data = data;
	*out_len = n;
	return TC_OK;
}

int tc_ssh_channel_data_build(uint8_t *out, size_t cap, size_t *out_len,
                              tc_ssh_channel *ch, const void *data,
                              size_t data_len)
{
	if (out == NULL || ch == NULL || (data == NULL && data_len != 0))
		return TC_ERR_INVAL;
	if (data_len > ch->remote_window)
		return TC_ERR_AGAIN;
	if (data_len > ch->remote_max_packet)
		return TC_ERR_AGAIN;

	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, out, cap);
	tc_ssh_put_byte(&w, TC_SSH_MSG_CHANNEL_DATA);
	tc_ssh_put_u32(&w, ch->remote_id);
	tc_ssh_put_string(&w, data, data_len);
	if (!tc_ssh_wbuf_ok(&w))
		return TC_ERR_NOSPACE;

	/* Charged only once the packet is definitely built: an early deduction
	 * followed by a NOSPACE return would leak window on every retry. */
	ch->remote_window -= (uint32_t)data_len;
	if (out_len != NULL)
		*out_len = tc_ssh_wbuf_len(&w);
	return TC_OK;
}

bool tc_ssh_channel_window_needed(const tc_ssh_channel *ch,
                                  uint32_t *out_increment)
{
	if (ch == NULL || ch->local_window > TC_SSH_CHAN_WINDOW_LOW)
		return false;
	if (out_increment != NULL)
		*out_increment = TC_SSH_CHAN_WINDOW - ch->local_window;
	return true;
}

int tc_ssh_channel_window_adjust_build(uint8_t *out, size_t cap,
                                       size_t *out_len, tc_ssh_channel *ch,
                                       uint32_t increment)
{
	if (out == NULL || ch == NULL)
		return TC_ERR_INVAL;
	if (increment == 0)
		return TC_ERR_INVAL;
	if (increment > UINT32_MAX - ch->local_window)
		return TC_ERR_RANGE;

	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, out, cap);
	tc_ssh_put_byte(&w, TC_SSH_MSG_CHANNEL_WINDOW_ADJUST);
	tc_ssh_put_u32(&w, ch->remote_id);
	tc_ssh_put_u32(&w, increment);
	if (!tc_ssh_wbuf_ok(&w))
		return TC_ERR_NOSPACE;

	ch->local_window += increment;
	if (out_len != NULL)
		*out_len = tc_ssh_wbuf_len(&w);
	return TC_OK;
}

int tc_ssh_channel_window_adjust_parse(tc_ssh_channel *ch,
                                       const uint8_t *payload, size_t len)
{
	if (ch == NULL || payload == NULL)
		return TC_ERR_INVAL;
	tc_ssh_rbuf r;
	tc_ssh_rbuf_init(&r, payload, len);
	if (tc_ssh_get_byte(&r) != TC_SSH_MSG_CHANNEL_WINDOW_ADJUST)
		return TC_ERR_INVAL;
	if (tc_ssh_get_u32(&r) != ch->local_id)
		return TC_ERR_INVAL;
	uint32_t inc = tc_ssh_get_u32(&r);
	if (!tc_ssh_rbuf_ok(&r))
		return TC_ERR_INVAL;

	/* RFC 4254 5.2 caps the window at 2^32 - 1. Adding past it would wrap
	 * and hand us a window of nearly nothing, or of nearly everything. */
	if (inc > UINT32_MAX - ch->remote_window)
		return TC_ERR_RANGE;
	ch->remote_window += inc;
	return TC_OK;
}

int tc_ssh_channel_eof_build(uint8_t *out, size_t cap, size_t *out_len,
                             tc_ssh_channel *ch)
{
	if (out == NULL || ch == NULL)
		return TC_ERR_INVAL;
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, out, cap);
	tc_ssh_put_byte(&w, TC_SSH_MSG_CHANNEL_EOF);
	tc_ssh_put_u32(&w, ch->remote_id);
	if (!tc_ssh_wbuf_ok(&w))
		return TC_ERR_NOSPACE;
	ch->eof_sent = true;
	if (out_len != NULL)
		*out_len = tc_ssh_wbuf_len(&w);
	return TC_OK;
}

int tc_ssh_channel_close_build(uint8_t *out, size_t cap, size_t *out_len,
                               tc_ssh_channel *ch)
{
	if (out == NULL || ch == NULL)
		return TC_ERR_INVAL;
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, out, cap);
	tc_ssh_put_byte(&w, TC_SSH_MSG_CHANNEL_CLOSE);
	tc_ssh_put_u32(&w, ch->remote_id);
	if (!tc_ssh_wbuf_ok(&w))
		return TC_ERR_NOSPACE;
	ch->closed = true;
	if (out_len != NULL)
		*out_len = tc_ssh_wbuf_len(&w);
	return TC_OK;
}

int tc_ssh_channel_exit_status_build(uint8_t *out, size_t cap, size_t *out_len,
                                     const tc_ssh_channel *ch, uint32_t status)
{
	if (out == NULL || ch == NULL)
		return TC_ERR_INVAL;
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, out, cap);
	tc_ssh_put_byte(&w, TC_SSH_MSG_CHANNEL_REQUEST);
	tc_ssh_put_u32(&w, ch->remote_id);
	tc_ssh_put_cstring(&w, "exit-status");
	/* RFC 4254 6.10: never wants a reply, and a client that got one would
	 * have nothing to match it against. */
	tc_ssh_put_bool(&w, false);
	tc_ssh_put_u32(&w, status);
	if (!tc_ssh_wbuf_ok(&w))
		return TC_ERR_NOSPACE;
	if (out_len != NULL)
		*out_len = tc_ssh_wbuf_len(&w);
	return TC_OK;
}

/* ---- the client half --------------------------------------------------- */

int tc_ssh_channel_open_build(uint8_t *out, size_t cap, size_t *out_len,
                              const tc_ssh_channel *ch)
{
	if (out == NULL || ch == NULL)
		return TC_ERR_INVAL;
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, out, cap);
	tc_ssh_put_byte(&w, TC_SSH_MSG_CHANNEL_OPEN);
	tc_ssh_put_cstring(&w, "session");
	tc_ssh_put_u32(&w, ch->local_id);
	tc_ssh_put_u32(&w, ch->local_window);
	tc_ssh_put_u32(&w, TC_SSH_CHAN_MAX_PACKET);
	if (!tc_ssh_wbuf_ok(&w))
		return TC_ERR_NOSPACE;
	if (out_len != NULL)
		*out_len = tc_ssh_wbuf_len(&w);
	return TC_OK;
}

int tc_ssh_channel_confirm_parse(tc_ssh_channel *ch, const uint8_t *payload,
                                 size_t len)
{
	if (ch == NULL || payload == NULL)
		return TC_ERR_INVAL;
	tc_ssh_rbuf r;
	tc_ssh_rbuf_init(&r, payload, len);
	if (tc_ssh_get_byte(&r) != TC_SSH_MSG_CHANNEL_OPEN_CONFIRMATION)
		return TC_ERR_INVAL;
	/* The recipient id is ours; a confirmation for a channel we did not open
	 * is a confused server and not something to adopt. */
	if (tc_ssh_get_u32(&r) != ch->local_id)
		return TC_ERR_INVAL;
	uint32_t remote_id = tc_ssh_get_u32(&r);
	uint32_t window = tc_ssh_get_u32(&r);
	uint32_t max_packet = tc_ssh_get_u32(&r);
	if (!tc_ssh_rbuf_ok(&r))
		return TC_ERR_INVAL;
	if (max_packet == 0)
		return TC_ERR_INVAL;
	if (max_packet > TC_SSH_MAX_PAYLOAD)
		max_packet = TC_SSH_MAX_PAYLOAD;

	ch->remote_id = remote_id;
	ch->remote_window = window;
	ch->remote_max_packet = max_packet;
	ch->open = true;
	return TC_OK;
}

int tc_ssh_channel_subsystem_build(uint8_t *out, size_t cap, size_t *out_len,
                                   const tc_ssh_channel *ch, const char *name)
{
	if (out == NULL || ch == NULL || name == NULL)
		return TC_ERR_INVAL;
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, out, cap);
	tc_ssh_put_byte(&w, TC_SSH_MSG_CHANNEL_REQUEST);
	tc_ssh_put_u32(&w, ch->remote_id);
	tc_ssh_put_cstring(&w, "subsystem");
	tc_ssh_put_bool(&w, true);
	tc_ssh_put_cstring(&w, name);
	if (!tc_ssh_wbuf_ok(&w))
		return TC_ERR_NOSPACE;
	if (out_len != NULL)
		*out_len = tc_ssh_wbuf_len(&w);
	return TC_OK;
}
