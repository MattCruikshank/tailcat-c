/* SPDX-License-Identifier: BSD-3-Clause
 *
 * The connection layer: one session channel, flow control, and the requests
 * we refuse.
 *
 * Flow control is where the interesting bugs are, and they come in two
 * shapes. Sending past the peer's window is loud -- OpenSSH treats it as a
 * protocol error and drops the connection. Never *extending* the peer's
 * window is quiet: the first windowful transfers perfectly and everything
 * after it hangs, so small tests pass and real transfers stall. Both have
 * tests here, and the second is the one worth having.
 */

#include "tc/sshchan.h"

#include "tc/sshwire.h"

#include "tctest.h"

#include <string.h>

#define BUFSZ 2048

/* open_session drives a channel to the point a real one reaches after
 * CHANNEL_OPEN and its confirmation. */
static void open_session(tc_ssh_channel *ch, uint32_t remote_id,
                         uint32_t window, uint32_t max_packet)
{
	uint8_t msg[BUFSZ];
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, msg, sizeof msg);
	tc_ssh_put_byte(&w, TC_SSH_MSG_CHANNEL_OPEN);
	tc_ssh_put_cstring(&w, "session");
	tc_ssh_put_u32(&w, remote_id);
	tc_ssh_put_u32(&w, window);
	tc_ssh_put_u32(&w, max_packet);
	TCT_TRUE(tc_ssh_wbuf_ok(&w));

	tc_ssh_channel_init(ch);
	char type[32];
	TCT_EQ_INT(tc_ssh_channel_open_parse(ch, type, sizeof type, msg,
	                                     tc_ssh_wbuf_len(&w)),
	           TC_OK);
	TCT_EQ_STR(type, "session");
	ch->open = true;
}

static void test_open_and_confirm(void)
{
	TCT_CASE("a session open is parsed and confirmed");
	tc_ssh_channel ch;
	open_session(&ch, 0x1234, 1000, 4096);
	TCT_EQ_INT((int)ch.remote_id, 0x1234);
	TCT_EQ_INT((int)ch.remote_window, 1000);
	TCT_EQ_INT((int)ch.remote_max_packet, 4096);
	TCT_EQ_INT((int)ch.local_window, TC_SSH_CHAN_WINDOW);

	uint8_t msg[BUFSZ];
	size_t len = 0;
	TCT_EQ_INT(tc_ssh_channel_confirm_build(msg, sizeof msg, &len, &ch),
	           TC_OK);
	tc_ssh_rbuf r;
	tc_ssh_rbuf_init(&r, msg, len);
	TCT_EQ_INT(tc_ssh_get_byte(&r), TC_SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
	/* The recipient id must be theirs and the sender id ours; swapping them
	 * is a channel that works until the first message either side sends. */
	TCT_EQ_INT((int)tc_ssh_get_u32(&r), 0x1234);
	TCT_EQ_INT((int)tc_ssh_get_u32(&r), (int)ch.local_id);
	TCT_EQ_INT((int)tc_ssh_get_u32(&r), (int)TC_SSH_CHAN_WINDOW);
	TCT_EQ_INT((int)tc_ssh_get_u32(&r), (int)TC_SSH_CHAN_MAX_PACKET);
	TCT_TRUE(tc_ssh_rbuf_ok(&r));

	TCT_CASE("a peer offering a zero maximum packet is refused");
	/* Nothing can be sent in packets of zero bytes, so this is malformed
	 * rather than a very small window. */
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, msg, sizeof msg);
	tc_ssh_put_byte(&w, TC_SSH_MSG_CHANNEL_OPEN);
	tc_ssh_put_cstring(&w, "session");
	tc_ssh_put_u32(&w, 1);
	tc_ssh_put_u32(&w, 1000);
	tc_ssh_put_u32(&w, 0);
	char type[32];
	tc_ssh_channel other;
	tc_ssh_channel_init(&other);
	TCT_TRUE(tc_ssh_channel_open_parse(&other, type, sizeof type, msg,
	                                   tc_ssh_wbuf_len(&w)) != TC_OK);

	TCT_CASE("an absurd maximum packet is clamped, not believed");
	tc_ssh_wbuf_init(&w, msg, sizeof msg);
	tc_ssh_put_byte(&w, TC_SSH_MSG_CHANNEL_OPEN);
	tc_ssh_put_cstring(&w, "session");
	tc_ssh_put_u32(&w, 1);
	tc_ssh_put_u32(&w, 1000);
	tc_ssh_put_u32(&w, 0xffffffffu);
	tc_ssh_channel_init(&other);
	TCT_EQ_INT(tc_ssh_channel_open_parse(&other, type, sizeof type, msg,
	                                     tc_ssh_wbuf_len(&w)),
	           TC_OK);
	TCT_TRUE(other.remote_max_packet <= TC_SSH_MAX_PAYLOAD);

	TCT_CASE("a non-session channel type is reported as itself");
	tc_ssh_wbuf_init(&w, msg, sizeof msg);
	tc_ssh_put_byte(&w, TC_SSH_MSG_CHANNEL_OPEN);
	tc_ssh_put_cstring(&w, "direct-tcpip");
	tc_ssh_put_u32(&w, 1);
	tc_ssh_put_u32(&w, 1000);
	tc_ssh_put_u32(&w, 4096);
	tc_ssh_channel_init(&other);
	TCT_EQ_INT(tc_ssh_channel_open_parse(&other, type, sizeof type, msg,
	                                     tc_ssh_wbuf_len(&w)),
	           TC_OK);
	TCT_EQ_STR(type, "direct-tcpip");
}

static void test_sending_respects_the_window(void)
{
	TCT_CASE("sending past the peer's window is refused");
	tc_ssh_channel ch;
	open_session(&ch, 7, 100, 4096);

	uint8_t data[256], msg[BUFSZ];
	memset(data, 0xab, sizeof data);
	size_t len = 0;
	TCT_EQ_INT(tc_ssh_channel_data_build(msg, sizeof msg, &len, &ch, data,
	                                     101),
	           TC_ERR_AGAIN);
	/* And the refusal must not have spent any window. */
	TCT_EQ_INT((int)ch.remote_window, 100);

	TCT_CASE("sending exactly the window is allowed, once");
	TCT_EQ_INT(tc_ssh_channel_data_build(msg, sizeof msg, &len, &ch, data,
	                                     100),
	           TC_OK);
	TCT_EQ_INT((int)ch.remote_window, 0);
	TCT_EQ_INT(tc_ssh_channel_data_build(msg, sizeof msg, &len, &ch, data, 1),
	           TC_ERR_AGAIN);

	TCT_CASE("sending past the peer's maximum packet is refused");
	open_session(&ch, 7, 100000, 64);
	TCT_EQ_INT(tc_ssh_channel_data_build(msg, sizeof msg, &len, &ch, data, 65),
	           TC_ERR_AGAIN);
	TCT_EQ_INT(tc_ssh_channel_data_build(msg, sizeof msg, &len, &ch, data, 64),
	           TC_OK);

	TCT_CASE("a buffer too small spends no window either");
	/* An early deduction followed by a NOSPACE return would leak window on
	 * every retry, and the connection would stall with no error anywhere. */
	open_session(&ch, 7, 100000, 4096);
	uint32_t before = ch.remote_window;
	TCT_EQ_INT(tc_ssh_channel_data_build(msg, 8, &len, &ch, data, 256),
	           TC_ERR_NOSPACE);
	TCT_EQ_INT((int)ch.remote_window, (int)before);
}

static void test_receiving_respects_the_window(void)
{
	TCT_CASE("data within our window is accepted and charged");
	tc_ssh_channel ch;
	open_session(&ch, 9, 1000, 4096);

	uint8_t payload[BUFSZ], body[512];
	memset(body, 0x5a, sizeof body);
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, payload, sizeof payload);
	tc_ssh_put_byte(&w, TC_SSH_MSG_CHANNEL_DATA);
	tc_ssh_put_u32(&w, ch.local_id);
	tc_ssh_put_string(&w, body, sizeof body);
	TCT_TRUE(tc_ssh_wbuf_ok(&w));

	const uint8_t *got = NULL;
	size_t got_len = 0;
	TCT_EQ_INT(tc_ssh_channel_data_parse(&ch, &got, &got_len, payload,
	                                     tc_ssh_wbuf_len(&w)),
	           TC_OK);
	TCT_EQ_INT((int)got_len, (int)sizeof body);
	TCT_EQ_MEM(got, body, sizeof body);
	TCT_EQ_INT((int)ch.local_window, (int)(TC_SSH_CHAN_WINDOW - sizeof body));

	TCT_CASE("a peer that overruns its window is refused");
	/* Every buffer downstream was sized on the promise the peer just broke,
	 * so this has to be an error and not a clamp. */
	ch.local_window = 10;
	TCT_EQ_INT(tc_ssh_channel_data_parse(&ch, &got, &got_len, payload,
	                                     tc_ssh_wbuf_len(&w)),
	           TC_ERR_TOOMANY);

	TCT_CASE("data for another channel is refused");
	/* One channel is still not an excuse to skip the id check: acting on a
	 * message for a channel that does not exist corrupts the one that
	 * does. */
	open_session(&ch, 9, 1000, 4096);
	tc_ssh_wbuf_init(&w, payload, sizeof payload);
	tc_ssh_put_byte(&w, TC_SSH_MSG_CHANNEL_DATA);
	tc_ssh_put_u32(&w, ch.local_id + 1);
	tc_ssh_put_string(&w, body, 16);
	TCT_TRUE(tc_ssh_channel_data_parse(&ch, &got, &got_len, payload,
	                                   tc_ssh_wbuf_len(&w)) != TC_OK);
	TCT_TRUE(!tc_ssh_channel_id_matches(&ch, payload, tc_ssh_wbuf_len(&w)));
}

static void test_the_window_is_replenished(void)
{
	/* The quiet failure: a server that never extends the peer's window works
	 * perfectly until the first windowful is spent and then hangs for ever. */
	TCT_CASE("a full window needs no extension");
	tc_ssh_channel ch;
	open_session(&ch, 3, 1000, 4096);
	uint32_t inc = 0;
	TCT_TRUE(!tc_ssh_channel_window_needed(&ch, &inc));

	TCT_CASE("a window past halfway does");
	ch.local_window = TC_SSH_CHAN_WINDOW_LOW;
	TCT_TRUE(tc_ssh_channel_window_needed(&ch, &inc));
	TCT_EQ_INT((int)inc, (int)(TC_SSH_CHAN_WINDOW - TC_SSH_CHAN_WINDOW_LOW));

	TCT_CASE("and extending it restores the full window");
	uint8_t msg[BUFSZ];
	size_t len = 0;
	TCT_EQ_INT(tc_ssh_channel_window_adjust_build(msg, sizeof msg, &len, &ch,
	                                              inc),
	           TC_OK);
	TCT_EQ_INT((int)ch.local_window, (int)TC_SSH_CHAN_WINDOW);
	tc_ssh_rbuf r;
	tc_ssh_rbuf_init(&r, msg, len);
	TCT_EQ_INT(tc_ssh_get_byte(&r), TC_SSH_MSG_CHANNEL_WINDOW_ADJUST);
	TCT_EQ_INT((int)tc_ssh_get_u32(&r), 3);
	TCT_EQ_INT((int)tc_ssh_get_u32(&r), (int)inc);

	TCT_CASE("a peer's extension credits our send window");
	open_session(&ch, 3, 100, 4096);
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, msg, sizeof msg);
	tc_ssh_put_byte(&w, TC_SSH_MSG_CHANNEL_WINDOW_ADJUST);
	tc_ssh_put_u32(&w, ch.local_id);
	tc_ssh_put_u32(&w, 900);
	TCT_EQ_INT(tc_ssh_channel_window_adjust_parse(&ch, msg,
	                                              tc_ssh_wbuf_len(&w)),
	           TC_OK);
	TCT_EQ_INT((int)ch.remote_window, 1000);

	TCT_CASE("an extension that would overflow the window is refused");
	/* RFC 4254 5.2 caps the window at 2^32 - 1. Wrapping it would hand us a
	 * window of almost nothing, or of almost everything. */
	ch.remote_window = UINT32_MAX - 5;
	tc_ssh_wbuf_init(&w, msg, sizeof msg);
	tc_ssh_put_byte(&w, TC_SSH_MSG_CHANNEL_WINDOW_ADJUST);
	tc_ssh_put_u32(&w, ch.local_id);
	tc_ssh_put_u32(&w, 6);
	TCT_EQ_INT(tc_ssh_channel_window_adjust_parse(&ch, msg,
	                                              tc_ssh_wbuf_len(&w)),
	           TC_ERR_RANGE);
	TCT_EQ_INT((int)ch.remote_window, (int)(UINT32_MAX - 5));
}

static void test_requests(void)
{
	tc_ssh_channel ch;
	open_session(&ch, 5, 1000, 4096);
	uint8_t msg[BUFSZ];
	tc_ssh_wbuf w;
	tc_ssh_channel_request req;

	TCT_CASE("a subsystem request is recognised with its name");
	tc_ssh_wbuf_init(&w, msg, sizeof msg);
	tc_ssh_put_byte(&w, TC_SSH_MSG_CHANNEL_REQUEST);
	tc_ssh_put_u32(&w, ch.local_id);
	tc_ssh_put_cstring(&w, "subsystem");
	tc_ssh_put_bool(&w, true);
	tc_ssh_put_cstring(&w, "sftp");
	TCT_EQ_INT(tc_ssh_channel_request_parse(&req, &ch, msg,
	                                        tc_ssh_wbuf_len(&w)),
	           TC_OK);
	TCT_EQ_INT((int)req.type, (int)TC_SSH_REQ_SUBSYSTEM);
	TCT_TRUE(req.want_reply);
	TCT_EQ_STR(req.arg, "sftp");

	TCT_CASE("an exec request carries its command");
	tc_ssh_wbuf_init(&w, msg, sizeof msg);
	tc_ssh_put_byte(&w, TC_SSH_MSG_CHANNEL_REQUEST);
	tc_ssh_put_u32(&w, ch.local_id);
	tc_ssh_put_cstring(&w, "exec");
	tc_ssh_put_bool(&w, true);
	tc_ssh_put_cstring(&w, "uptime -p");
	TCT_EQ_INT(tc_ssh_channel_request_parse(&req, &ch, msg,
	                                        tc_ssh_wbuf_len(&w)),
	           TC_OK);
	TCT_EQ_INT((int)req.type, (int)TC_SSH_REQ_EXEC);
	TCT_EQ_STR(req.arg, "uptime -p");

	TCT_CASE("shell carries nothing");
	tc_ssh_wbuf_init(&w, msg, sizeof msg);
	tc_ssh_put_byte(&w, TC_SSH_MSG_CHANNEL_REQUEST);
	tc_ssh_put_u32(&w, ch.local_id);
	tc_ssh_put_cstring(&w, "shell");
	tc_ssh_put_bool(&w, true);
	TCT_EQ_INT(tc_ssh_channel_request_parse(&req, &ch, msg,
	                                        tc_ssh_wbuf_len(&w)),
	           TC_OK);
	TCT_EQ_INT((int)req.type, (int)TC_SSH_REQ_SHELL);
	TCT_TRUE(req.want_reply);

	TCT_CASE("pty-req carries a terminal and its size");
	tc_ssh_wbuf_init(&w, msg, sizeof msg);
	tc_ssh_put_byte(&w, TC_SSH_MSG_CHANNEL_REQUEST);
	tc_ssh_put_u32(&w, ch.local_id);
	tc_ssh_put_cstring(&w, "pty-req");
	tc_ssh_put_bool(&w, true);
	tc_ssh_put_cstring(&w, "xterm-256color");
	tc_ssh_put_u32(&w, 120);
	tc_ssh_put_u32(&w, 40);
	tc_ssh_put_u32(&w, 960);
	tc_ssh_put_u32(&w, 640);
	/* The encoded terminal modes, which must be skipped rather than
	 * mis-parsed as something else. A real client always sends some. */
	tc_ssh_put_string(&w, "\x01\x00\x00\x00\x03\x00", 6);
	TCT_EQ_INT(tc_ssh_channel_request_parse(&req, &ch, msg,
	                                        tc_ssh_wbuf_len(&w)),
	           TC_OK);
	TCT_EQ_INT((int)req.type, (int)TC_SSH_REQ_PTY);
	TCT_EQ_STR(req.pty.term, "xterm-256color");
	TCT_EQ_INT(req.pty.cols, 120);
	TCT_EQ_INT(req.pty.rows, 40);
	TCT_EQ_INT(req.pty.width_px, 960);
	TCT_EQ_INT(req.pty.height_px, 640);

	TCT_CASE("a truncated pty-req is refused, not half-read");
	/* Four numbers are promised and three are sent. Accepting it would put
	 * an uninitialised height into the struct, and a terminal of 120x0 is
	 * a shell that behaves very strangely for reasons nobody can see. */
	tc_ssh_wbuf_init(&w, msg, sizeof msg);
	tc_ssh_put_byte(&w, TC_SSH_MSG_CHANNEL_REQUEST);
	tc_ssh_put_u32(&w, ch.local_id);
	tc_ssh_put_cstring(&w, "pty-req");
	tc_ssh_put_bool(&w, true);
	tc_ssh_put_cstring(&w, "vt100");
	tc_ssh_put_u32(&w, 80);
	tc_ssh_put_u32(&w, 24);
	TCT_TRUE(tc_ssh_channel_request_parse(&req, &ch, msg,
	                                      tc_ssh_wbuf_len(&w)) != TC_OK);

	TCT_CASE("a pty-req with an oversized TERM still works");
	/* Truncated to nothing rather than refused: a nameless terminal is a
	 * working session with a dumb one, and a refused pty-req is no session
	 * at all. The size must still come through. */
	{
		char huge[200];
		memset(huge, 'x', sizeof huge - 1);
		huge[sizeof huge - 1] = '\0';
		tc_ssh_wbuf_init(&w, msg, sizeof msg);
		tc_ssh_put_byte(&w, TC_SSH_MSG_CHANNEL_REQUEST);
		tc_ssh_put_u32(&w, ch.local_id);
		tc_ssh_put_cstring(&w, "pty-req");
		tc_ssh_put_bool(&w, true);
		tc_ssh_put_cstring(&w, huge);
		tc_ssh_put_u32(&w, 80);
		tc_ssh_put_u32(&w, 24);
		tc_ssh_put_u32(&w, 0);
		tc_ssh_put_u32(&w, 0);
		tc_ssh_put_string(&w, "", 0);
		TCT_EQ_INT(tc_ssh_channel_request_parse(&req, &ch, msg,
		                                        tc_ssh_wbuf_len(&w)),
		           TC_OK);
		TCT_EQ_INT((int)req.type, (int)TC_SSH_REQ_PTY);
		TCT_EQ_STR(req.pty.term, "");
		TCT_EQ_INT(req.pty.cols, 80);
		TCT_EQ_INT(req.pty.rows, 24);
	}

	TCT_CASE("window-change is four numbers and no terminal");
	tc_ssh_wbuf_init(&w, msg, sizeof msg);
	tc_ssh_put_byte(&w, TC_SSH_MSG_CHANNEL_REQUEST);
	tc_ssh_put_u32(&w, ch.local_id);
	tc_ssh_put_cstring(&w, "window-change");
	tc_ssh_put_bool(&w, false);
	tc_ssh_put_u32(&w, 100);
	tc_ssh_put_u32(&w, 30);
	tc_ssh_put_u32(&w, 0);
	tc_ssh_put_u32(&w, 0);
	TCT_EQ_INT(tc_ssh_channel_request_parse(&req, &ch, msg,
	                                        tc_ssh_wbuf_len(&w)),
	           TC_OK);
	TCT_EQ_INT((int)req.type, (int)TC_SSH_REQ_WINDOW_CHANGE);
	TCT_EQ_INT(req.pty.cols, 100);
	TCT_EQ_INT(req.pty.rows, 30);
	TCT_EQ_STR(req.pty.term, ""); /* never resent, so never claimed */

	TCT_CASE("everything else is something to refuse, with want_reply kept");
	/* The flag has to survive parsing even for a request we will not serve:
	 * a client that set it and hears nothing waits, which looks like a hung
	 * server rather than a refused feature. */
	static const char *const others[] = { "env", "x11-req", "signal",
		                                  "auth-agent-req@openssh.com" };
	for (size_t i = 0; i < sizeof others / sizeof *others; i++) {
		tc_ssh_wbuf_init(&w, msg, sizeof msg);
		tc_ssh_put_byte(&w, TC_SSH_MSG_CHANNEL_REQUEST);
		tc_ssh_put_u32(&w, ch.local_id);
		tc_ssh_put_cstring(&w, others[i]);
		tc_ssh_put_bool(&w, true);
		TCT_EQ_INT(tc_ssh_channel_request_parse(&req, &ch, msg,
		                                        tc_ssh_wbuf_len(&w)),
		           TC_OK);
		if (req.type != TC_SSH_REQ_OTHER)
			TCT_FAILF("%s was not refused", others[i]);
		if (!req.want_reply)
			TCT_FAILF("%s lost its want_reply flag", others[i]);
	}
	tct_checks++;

	TCT_CASE("a request naming another channel is refused");
	tc_ssh_wbuf_init(&w, msg, sizeof msg);
	tc_ssh_put_byte(&w, TC_SSH_MSG_CHANNEL_REQUEST);
	tc_ssh_put_u32(&w, ch.local_id + 1);
	tc_ssh_put_cstring(&w, "subsystem");
	tc_ssh_put_bool(&w, true);
	tc_ssh_put_cstring(&w, "sftp");
	TCT_TRUE(tc_ssh_channel_request_parse(&req, &ch, msg,
	                                      tc_ssh_wbuf_len(&w)) != TC_OK);

	TCT_CASE("success and failure replies name the peer's channel");
	size_t len = 0;
	TCT_EQ_INT(tc_ssh_channel_reply_build(msg, sizeof msg, &len,
	                                      ch.remote_id, true),
	           TC_OK);
	TCT_EQ_INT(msg[0], TC_SSH_MSG_CHANNEL_SUCCESS);
	TCT_EQ_INT(tc_ssh_channel_reply_build(msg, sizeof msg, &len,
	                                      ch.remote_id, false),
	           TC_OK);
	TCT_EQ_INT(msg[0], TC_SSH_MSG_CHANNEL_FAILURE);
}

static void test_teardown(void)
{
	tc_ssh_channel ch;
	open_session(&ch, 11, 1000, 4096);
	uint8_t msg[BUFSZ];
	size_t len = 0;

	TCT_CASE("EOF and close name the peer's channel and set our state");
	TCT_EQ_INT(tc_ssh_channel_eof_build(msg, sizeof msg, &len, &ch), TC_OK);
	TCT_EQ_INT(msg[0], TC_SSH_MSG_CHANNEL_EOF);
	TCT_TRUE(ch.eof_sent);
	TCT_EQ_INT(tc_ssh_channel_close_build(msg, sizeof msg, &len, &ch), TC_OK);
	TCT_EQ_INT(msg[0], TC_SSH_MSG_CHANNEL_CLOSE);
	TCT_TRUE(ch.closed);

	TCT_CASE("the exit status is a request that wants no reply");
	/* RFC 4254 6.10. A client that got a reply would have nothing to match
	 * it against. */
	TCT_EQ_INT(tc_ssh_channel_exit_status_build(msg, sizeof msg, &len, &ch,
	                                            0),
	           TC_OK);
	tc_ssh_rbuf r;
	tc_ssh_rbuf_init(&r, msg, len);
	TCT_EQ_INT(tc_ssh_get_byte(&r), TC_SSH_MSG_CHANNEL_REQUEST);
	TCT_EQ_INT((int)tc_ssh_get_u32(&r), 11);
	TCT_TRUE(tc_ssh_get_string_eq(&r, "exit-status"));
	TCT_TRUE(!tc_ssh_get_bool(&r));
	TCT_EQ_INT((int)tc_ssh_get_u32(&r), 0);
	TCT_TRUE(tc_ssh_rbuf_ok(&r));
	TCT_EQ_INT((int)tc_ssh_rbuf_remaining(&r), 0);
}

static void test_truncation(void)
{
	TCT_CASE("every channel message is refused at every truncation");
	tc_ssh_channel ch;
	uint8_t msg[BUFSZ];
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, msg, sizeof msg);
	tc_ssh_put_byte(&w, TC_SSH_MSG_CHANNEL_OPEN);
	tc_ssh_put_cstring(&w, "session");
	tc_ssh_put_u32(&w, 1);
	tc_ssh_put_u32(&w, 1000);
	tc_ssh_put_u32(&w, 4096);
	size_t full = tc_ssh_wbuf_len(&w);

	char type[32];
	for (size_t cut = 0; cut < full; cut++) {
		tc_ssh_channel_init(&ch);
		if (tc_ssh_channel_open_parse(&ch, type, sizeof type, msg, cut) ==
		    TC_OK)
			TCT_FAILF("an open truncated to %zu bytes was accepted", cut);
	}
	tct_checks++;

	TCT_CASE("and a data message likewise");
	open_session(&ch, 1, 1000, 4096);
	tc_ssh_wbuf_init(&w, msg, sizeof msg);
	tc_ssh_put_byte(&w, TC_SSH_MSG_CHANNEL_DATA);
	tc_ssh_put_u32(&w, ch.local_id);
	uint8_t body[64];
	memset(body, 1, sizeof body);
	tc_ssh_put_string(&w, body, sizeof body);
	full = tc_ssh_wbuf_len(&w);
	const uint8_t *got = NULL;
	size_t got_len = 0;
	for (size_t cut = 0; cut < full; cut++) {
		open_session(&ch, 1, 1000, 4096);
		if (tc_ssh_channel_data_parse(&ch, &got, &got_len, msg, cut) == TC_OK)
			TCT_FAILF("data truncated to %zu bytes was accepted", cut);
	}
	tct_checks++;
}

int main(void)
{
	test_open_and_confirm();
	test_sending_respects_the_window();
	test_receiving_respects_the_window();
	test_the_window_is_replenished();
	test_requests();
	test_teardown();
	test_truncation();
	return tct_report("sshchan");
}
