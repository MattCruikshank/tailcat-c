/* SPDX-License-Identifier: BSD-3-Clause
 *
 * The SFTP version 3 codec.
 *
 * SFTP runs inside an SSH channel, which is a byte stream, so the framing is
 * where this layer can go wrong in a way nothing else notices: one packet may
 * arrive across several reads and several may arrive in one. A codec that
 * assumed a read gave it exactly one packet works perfectly against a slow
 * client and corrupts the stream against a fast one -- and scp is a fast one.
 *
 * So tc_sftp_packet_len is tested byte by byte, at every prefix length, and
 * the parse is tested at every truncation.
 */

#include "tc/sftp.h"

#include "tc/sshwire.h"

#include "tctest.h"

#include <string.h>

#define BUFSZ 4096

static void test_framing(void)
{
	TCT_CASE("a length is not reported until four bytes are present");
	/* The caller uses this as "do I have a packet yet?", so it has to be
	 * right at every prefix and not merely at zero. */
	static const uint8_t pkt[] = { 0, 0, 0, 5, TC_SFTP_OPEN, 1, 2, 3, 4 };
	size_t total = 0;
	for (size_t avail = 0; avail < 4; avail++)
		TCT_EQ_INT(tc_sftp_packet_len(pkt, avail, &total), TC_ERR_AGAIN);

	TCT_CASE("and then it is the whole packet including the prefix");
	TCT_EQ_INT(tc_sftp_packet_len(pkt, 4, &total), TC_OK);
	TCT_EQ_INT((int)total, 9);
	/* More bytes available than the packet needs must not change it: the
	 * next packet's bytes are in the buffer too. */
	TCT_EQ_INT(tc_sftp_packet_len(pkt, sizeof pkt, &total), TC_OK);
	TCT_EQ_INT((int)total, 9);

	TCT_CASE("a zero-length packet is refused");
	/* It would name no request, and a caller looping on it would never
	 * advance. */
	static const uint8_t empty[] = { 0, 0, 0, 0 };
	TCT_TRUE(tc_sftp_packet_len(empty, 4, &total) != TC_OK);

	TCT_CASE("an enormous length is refused before anything is allocated");
	/* The number arrives before anything has vouched for it. */
	static const uint8_t huge[] = { 0xff, 0xff, 0xff, 0xff };
	TCT_EQ_INT(tc_sftp_packet_len(huge, 4, &total), TC_ERR_TOOMANY);
	static const uint8_t over[] = { 0x00, 0x01, 0x00, 0x00 }; /* 65536 */
	TCT_EQ_INT(tc_sftp_packet_len(over, 4, &total), TC_ERR_TOOMANY);
}

static void test_parse_write(void)
{
	TCT_CASE("a WRITE round trips through the parser");
	uint8_t pkt[BUFSZ];
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, pkt, sizeof pkt);
	tc_ssh_put_u32(&w, 0); /* length, patched below */
	tc_ssh_put_byte(&w, TC_SFTP_WRITE);
	tc_ssh_put_u32(&w, 4242);
	uint8_t handle[TC_SFTP_HANDLE_LEN] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	tc_ssh_put_string(&w, handle, sizeof handle);
	tc_ssh_put_u64(&w, 0x0102030405060708ull);
	static const char body[] = "hello drop box";
	tc_ssh_put_string(&w, body, sizeof body - 1);
	TCT_TRUE(tc_ssh_wbuf_ok(&w));
	size_t len = tc_ssh_wbuf_len(&w);
	uint32_t blen = (uint32_t)(len - 4);
	pkt[0] = (uint8_t)(blen >> 24);
	pkt[1] = (uint8_t)(blen >> 16);
	pkt[2] = (uint8_t)(blen >> 8);
	pkt[3] = (uint8_t)blen;

	tc_sftp_request req;
	TCT_EQ_INT(tc_sftp_parse(&req, pkt, len), TC_OK);
	TCT_EQ_INT(req.type, TC_SFTP_WRITE);
	TCT_EQ_INT((int)req.id, 4242);
	TCT_TRUE(req.has_handle);
	TCT_EQ_MEM(req.handle, handle, sizeof handle);
	TCT_TRUE(req.offset == 0x0102030405060708ull);
	TCT_EQ_INT((int)req.data_len, (int)(sizeof body - 1));
	TCT_EQ_MEM(req.data, body, sizeof body - 1);

	TCT_CASE("a packet handed over short or long is refused");
	/* Exactly one packet, not a prefix of the stream: accepting "at least
	 * this much" would read the next request's bytes as this one's. */
	TCT_TRUE(tc_sftp_parse(&req, pkt, len - 1) != TC_OK);
	TCT_TRUE(tc_sftp_parse(&req, pkt, len + 1) != TC_OK);

	TCT_CASE("and at every truncation");
	for (size_t cut = 0; cut < len; cut++)
		if (tc_sftp_parse(&req, pkt, cut) == TC_OK)
			TCT_FAILF("a WRITE truncated to %zu bytes parsed", cut);
	tct_checks++;
}

static void test_parse_open(void)
{
	TCT_CASE("an OPEN carries its flags and attributes");
	uint8_t pkt[BUFSZ];
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, pkt, sizeof pkt);
	tc_ssh_put_u32(&w, 0);
	tc_ssh_put_byte(&w, TC_SFTP_OPEN);
	tc_ssh_put_u32(&w, 7);
	tc_ssh_put_cstring(&w, "some/path/file.txt");
	tc_ssh_put_u32(&w, TC_SFTP_FXF_WRITE | TC_SFTP_FXF_CREAT);
	tc_ssh_put_u32(&w, TC_SFTP_ATTR_SIZE | TC_SFTP_ATTR_PERMISSIONS);
	tc_ssh_put_u64(&w, 1234);
	tc_ssh_put_u32(&w, 0644);
	size_t len = tc_ssh_wbuf_len(&w);
	uint32_t blen = (uint32_t)(len - 4);
	pkt[0] = (uint8_t)(blen >> 24);
	pkt[1] = (uint8_t)(blen >> 16);
	pkt[2] = (uint8_t)(blen >> 8);
	pkt[3] = (uint8_t)blen;

	tc_sftp_request req;
	TCT_EQ_INT(tc_sftp_parse(&req, pkt, len), TC_OK);
	TCT_EQ_INT(req.type, TC_SFTP_OPEN);
	TCT_EQ_STR(req.path, "some/path/file.txt");
	TCT_EQ_INT((int)req.pflags, TC_SFTP_FXF_WRITE | TC_SFTP_FXF_CREAT);
	TCT_TRUE(req.attrs.size == 1234);
	TCT_EQ_INT((int)req.attrs.permissions, 0644);

	TCT_CASE("an embedded NUL in a path is refused, not truncated");
	/* A path that means one thing to the parser and another to open(2) is
	 * the entire problem this server exists to avoid. */
	tc_ssh_wbuf_init(&w, pkt, sizeof pkt);
	tc_ssh_put_u32(&w, 0);
	tc_ssh_put_byte(&w, TC_SFTP_OPEN);
	tc_ssh_put_u32(&w, 8);
	tc_ssh_put_string(&w, "safe.txt\0/etc/passwd", 20);
	tc_ssh_put_u32(&w, TC_SFTP_FXF_WRITE);
	tc_ssh_put_u32(&w, 0);
	len = tc_ssh_wbuf_len(&w);
	blen = (uint32_t)(len - 4);
	pkt[0] = (uint8_t)(blen >> 24);
	pkt[1] = (uint8_t)(blen >> 16);
	pkt[2] = (uint8_t)(blen >> 8);
	pkt[3] = (uint8_t)blen;
	TCT_TRUE(tc_sftp_parse(&req, pkt, len) != TC_OK);
}

static void test_attrs_extended(void)
{
	TCT_CASE("an absurd extended-attribute count is refused");
	/* The count is the sender's to choose and each pair costs bytes it may
	 * not have sent; a loop that trusted it would spin on a short packet. */
	uint8_t pkt[BUFSZ];
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, pkt, sizeof pkt);
	tc_ssh_put_u32(&w, 0);
	tc_ssh_put_byte(&w, TC_SFTP_OPEN);
	tc_ssh_put_u32(&w, 1);
	tc_ssh_put_cstring(&w, "f.txt");
	tc_ssh_put_u32(&w, TC_SFTP_FXF_WRITE);
	tc_ssh_put_u32(&w, TC_SFTP_ATTR_EXTENDED);
	tc_ssh_put_u32(&w, 0x0fffffffu); /* pairs that are not there */
	size_t len = tc_ssh_wbuf_len(&w);
	uint32_t blen = (uint32_t)(len - 4);
	pkt[0] = (uint8_t)(blen >> 24);
	pkt[1] = (uint8_t)(blen >> 16);
	pkt[2] = (uint8_t)(blen >> 8);
	pkt[3] = (uint8_t)blen;

	tc_sftp_request req;
	TCT_TRUE(tc_sftp_parse(&req, pkt, len) != TC_OK);

	TCT_CASE("but a real one is read and discarded");
	tc_ssh_wbuf_init(&w, pkt, sizeof pkt);
	tc_ssh_put_u32(&w, 0);
	tc_ssh_put_byte(&w, TC_SFTP_OPEN);
	tc_ssh_put_u32(&w, 1);
	tc_ssh_put_cstring(&w, "f.txt");
	tc_ssh_put_u32(&w, TC_SFTP_FXF_WRITE);
	tc_ssh_put_u32(&w, TC_SFTP_ATTR_EXTENDED);
	tc_ssh_put_u32(&w, 1);
	tc_ssh_put_cstring(&w, "x@example.com");
	tc_ssh_put_cstring(&w, "value");
	len = tc_ssh_wbuf_len(&w);
	blen = (uint32_t)(len - 4);
	pkt[0] = (uint8_t)(blen >> 24);
	pkt[1] = (uint8_t)(blen >> 16);
	pkt[2] = (uint8_t)(blen >> 8);
	pkt[3] = (uint8_t)blen;
	TCT_EQ_INT(tc_sftp_parse(&req, pkt, len), TC_OK);
	TCT_EQ_STR(req.path, "f.txt");
}

static void test_unknown_requests_keep_their_id(void)
{
	TCT_CASE("an unknown request type still yields its id");
	/* A refusal has to be addressed to something. Refusing to parse it would
	 * leave nothing to put in the status. */
	uint8_t pkt[BUFSZ];
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, pkt, sizeof pkt);
	tc_ssh_put_u32(&w, 0);
	tc_ssh_put_byte(&w, 200); /* not a version 3 request */
	tc_ssh_put_u32(&w, 31337);
	tc_ssh_put_cstring(&w, "whatever");
	size_t len = tc_ssh_wbuf_len(&w);
	uint32_t blen = (uint32_t)(len - 4);
	pkt[0] = (uint8_t)(blen >> 24);
	pkt[1] = (uint8_t)(blen >> 16);
	pkt[2] = (uint8_t)(blen >> 8);
	pkt[3] = (uint8_t)blen;

	tc_sftp_request req;
	TCT_EQ_INT(tc_sftp_parse(&req, pkt, len), TC_OK);
	TCT_EQ_INT(req.type, 200);
	TCT_EQ_INT((int)req.id, 31337);
}

static void test_builders(void)
{
	uint8_t out[BUFSZ];
	size_t len = 0;

	TCT_CASE("every response carries a length prefix that matches its body");
	/* The prefix is backfilled after the body is written, which is the kind
	 * of thing that is right until someone adds a field. */
	TCT_EQ_INT(tc_sftp_build_version(out, sizeof out, &len), TC_OK);
	size_t total = 0;
	TCT_EQ_INT(tc_sftp_packet_len(out, len, &total), TC_OK);
	TCT_EQ_INT((int)total, (int)len);
	TCT_EQ_INT(out[4], TC_SFTP_VERSION_MSG);

	TCT_EQ_INT(tc_sftp_build_status(out, sizeof out, &len, 5,
	                                TC_SFTP_FX_PERMISSION_DENIED, "no"),
	           TC_OK);
	TCT_EQ_INT(tc_sftp_packet_len(out, len, &total), TC_OK);
	TCT_EQ_INT((int)total, (int)len);

	uint8_t handle[TC_SFTP_HANDLE_LEN] = { 9, 8, 7, 6, 5, 4, 3, 2 };
	TCT_EQ_INT(tc_sftp_build_handle(out, sizeof out, &len, 6, handle), TC_OK);
	TCT_EQ_INT(tc_sftp_packet_len(out, len, &total), TC_OK);
	TCT_EQ_INT((int)total, (int)len);

	tc_sftp_attrs a;
	memset(&a, 0, sizeof a);
	a.flags = TC_SFTP_ATTR_SIZE;
	a.size = 99;
	TCT_EQ_INT(tc_sftp_build_attrs(out, sizeof out, &len, 7, &a), TC_OK);
	TCT_EQ_INT(tc_sftp_packet_len(out, len, &total), TC_OK);
	TCT_EQ_INT((int)total, (int)len);

	TCT_EQ_INT(tc_sftp_build_name(out, sizeof out, &len, 8, "/", "/", &a),
	           TC_OK);
	TCT_EQ_INT(tc_sftp_packet_len(out, len, &total), TC_OK);
	TCT_EQ_INT((int)total, (int)len);

	TCT_CASE("a buffer too small is refused rather than half-written");
	for (size_t cap = 0; cap < 24; cap++)
		TCT_TRUE(tc_sftp_build_status(out, cap, &len, 1, 0, "hello") !=
		         TC_OK);
	tct_checks++;

	TCT_CASE("the extended flag is never emitted");
	/* We have nothing to put in it, and an empty block is still a field the
	 * client has to parse. */
	memset(&a, 0, sizeof a);
	a.flags = TC_SFTP_ATTR_SIZE | TC_SFTP_ATTR_EXTENDED;
	a.size = 1;
	TCT_EQ_INT(tc_sftp_build_attrs(out, sizeof out, &len, 9, &a), TC_OK);
	uint32_t flags = (uint32_t)out[9] << 24 | (uint32_t)out[10] << 16 |
	                 (uint32_t)out[11] << 8 | out[12];
	TCT_TRUE((flags & TC_SFTP_ATTR_EXTENDED) == 0);
	TCT_TRUE((flags & TC_SFTP_ATTR_SIZE) != 0);
}

/* ---- the client half --------------------------------------------------- */

/* patch_len backfills the length prefix of a hand-built packet. */
static void patch_len(uint8_t *pkt, size_t len)
{
	uint32_t body = (uint32_t)(len - 4);
	pkt[0] = (uint8_t)(body >> 24);
	pkt[1] = (uint8_t)(body >> 16);
	pkt[2] = (uint8_t)(body >> 8);
	pkt[3] = (uint8_t)body;
}

static void test_handles_are_the_servers_to_choose(void)
{
	/* A handle is opaque and entirely the server's: ours are eight bytes,
	 * Go's pkg/sftp uses its own, OpenSSH uses four. A client that insisted
	 * on its own server's length would work against itself and nothing
	 * else -- which is what it did, and it got as far as a successful stat
	 * before failing on the first opendir against a real Go server.
	 */
	TCT_CASE("a handle of any length is accepted");
	static const size_t lens[] = { 1, 3, 4, 8, 17, 64, 255, TC_SFTP_MAX_HANDLE };
	for (size_t i = 0; i < sizeof lens / sizeof *lens; i++) {
		uint8_t pkt[BUFSZ];
		tc_ssh_wbuf w;
		tc_ssh_wbuf_init(&w, pkt, sizeof pkt);
		tc_ssh_put_u32(&w, 0);
		tc_ssh_put_byte(&w, TC_SFTP_HANDLE);
		tc_ssh_put_u32(&w, 77);
		uint8_t h[TC_SFTP_MAX_HANDLE];
		for (size_t j = 0; j < lens[i]; j++)
			h[j] = (uint8_t)(j + 1);
		tc_ssh_put_string(&w, h, lens[i]);
		TCT_TRUE(tc_ssh_wbuf_ok(&w));
		size_t len = tc_ssh_wbuf_len(&w);
		patch_len(pkt, len);

		tc_sftp_response resp;
		if (tc_sftp_parse_response(&resp, pkt, len) != TC_OK) {
			TCT_FAILF("a %zu-byte handle was refused", lens[i]);
			continue;
		}
		tct_checks++;
		TCT_EQ_INT((int)resp.handle_len, (int)lens[i]);
		TCT_EQ_MEM(resp.handle, h, lens[i]);

		TCT_CASE("and is echoed back exactly");
		uint8_t req[BUFSZ];
		size_t req_len = 0;
		TCT_EQ_INT(tc_sftp_build_handle_request(req, sizeof req, &req_len,
		                                        TC_SFTP_READDIR, 78,
		                                        resp.handle, resp.handle_len),
		           TC_OK);
		tc_ssh_rbuf r;
		tc_ssh_rbuf_init(&r, req + 4, req_len - 4);
		TCT_EQ_INT(tc_ssh_get_byte(&r), TC_SFTP_READDIR);
		TCT_EQ_INT((int)tc_ssh_get_u32(&r), 78);
		size_t got = 0;
		const uint8_t *back = tc_ssh_get_string(&r, TC_SFTP_MAX_HANDLE, &got);
		TCT_TRUE(back != NULL && got == lens[i]);
		TCT_EQ_MEM(back, h, lens[i]);
	}

	TCT_CASE("but an absurd one is still refused");
	uint8_t pkt[BUFSZ];
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, pkt, sizeof pkt);
	tc_ssh_put_u32(&w, 0);
	tc_ssh_put_byte(&w, TC_SFTP_HANDLE);
	tc_ssh_put_u32(&w, 1);
	uint8_t big[TC_SFTP_MAX_HANDLE + 1];
	memset(big, 7, sizeof big);
	tc_ssh_put_string(&w, big, sizeof big);
	size_t len = tc_ssh_wbuf_len(&w);
	patch_len(pkt, len);
	tc_sftp_response resp;
	TCT_TRUE(tc_sftp_parse_response(&resp, pkt, len) != TC_OK);
}

static void test_name_listings(void)
{
	TCT_CASE("a multi-entry NAME response is walked to the end");
	/* READDIR is answered in batches, so a client that read one entry and
	 * stopped would list a directory as having one file in it. */
	uint8_t pkt[BUFSZ];
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, pkt, sizeof pkt);
	tc_ssh_put_u32(&w, 0);
	tc_ssh_put_byte(&w, TC_SFTP_NAME);
	tc_ssh_put_u32(&w, 5);
	tc_ssh_put_u32(&w, 3);
	static const char *const names[] = { "alpha.txt", "bravo.bin", "sub" };
	for (int i = 0; i < 3; i++) {
		tc_ssh_put_cstring(&w, names[i]);
		tc_ssh_put_cstring(&w, "-rw-r--r-- 1 0 0 6 Jan 1 00:00 x");
		tc_ssh_put_u32(&w, TC_SFTP_ATTR_SIZE | TC_SFTP_ATTR_PERMISSIONS);
		tc_ssh_put_u64(&w, (uint64_t)(100 + i));
		tc_ssh_put_u32(&w, i == 2 ? 040755u : 0100644u);
	}
	TCT_TRUE(tc_ssh_wbuf_ok(&w));
	size_t len = tc_ssh_wbuf_len(&w);
	patch_len(pkt, len);

	tc_sftp_response resp;
	TCT_EQ_INT(tc_sftp_parse_response(&resp, pkt, len), TC_OK);
	TCT_EQ_INT(resp.type, TC_SFTP_NAME);
	TCT_EQ_INT((int)resp.count, 3);

	tc_sftp_name_iter it;
	tc_sftp_name_begin(&it, &resp);
	char name[256], longname[512];
	tc_sftp_attrs a;
	int seen = 0;
	while (tc_sftp_name_next(&it, name, sizeof name, longname,
	                         sizeof longname, &a)) {
		TCT_EQ_STR(name, names[seen]);
		TCT_TRUE(a.size == (uint64_t)(100 + seen));
		seen++;
	}
	TCT_EQ_INT(seen, 3);
	TCT_CASE("and the iterator reports that it finished cleanly");
	/* A batch that ran out mid-entry is a short read, not an empty
	 * directory, and a caller that could not tell them apart would print a
	 * truncated listing as a complete one. */
	TCT_TRUE(tc_sftp_name_ok(&it));

	TCT_CASE("a count larger than the entries present is refused");
	tc_ssh_wbuf_init(&w, pkt, sizeof pkt);
	tc_ssh_put_u32(&w, 0);
	tc_ssh_put_byte(&w, TC_SFTP_NAME);
	tc_ssh_put_u32(&w, 5);
	tc_ssh_put_u32(&w, 0x1000000u); /* entries that are not there */
	tc_ssh_put_cstring(&w, "only.txt");
	len = tc_ssh_wbuf_len(&w);
	patch_len(pkt, len);
	TCT_TRUE(tc_sftp_parse_response(&resp, pkt, len) != TC_OK);

	TCT_CASE("and one truncated mid-entry is reported, not silently short");
	tc_ssh_wbuf_init(&w, pkt, sizeof pkt);
	tc_ssh_put_u32(&w, 0);
	tc_ssh_put_byte(&w, TC_SFTP_NAME);
	tc_ssh_put_u32(&w, 5);
	tc_ssh_put_u32(&w, 2);
	tc_ssh_put_cstring(&w, "first.txt");
	tc_ssh_put_cstring(&w, "longname");
	tc_ssh_put_u32(&w, 0); /* no attribute flags */
	tc_ssh_put_cstring(&w, "second.txt"); /* and then it stops */
	len = tc_ssh_wbuf_len(&w);
	patch_len(pkt, len);
	TCT_EQ_INT(tc_sftp_parse_response(&resp, pkt, len), TC_OK);
	tc_sftp_name_begin(&it, &resp);
	seen = 0;
	while (tc_sftp_name_next(&it, name, sizeof name, longname,
	                         sizeof longname, &a))
		seen++;
	TCT_EQ_INT(seen, 1);
	TCT_TRUE(!tc_sftp_name_ok(&it));
}

static void test_client_responses(void)
{
	uint8_t pkt[BUFSZ];
	tc_ssh_wbuf w;
	tc_sftp_response resp;

	TCT_CASE("a VERSION with extensions still parses");
	/* Servers advertise posix-rename and the statvfs pair. We use none of
	 * them, and refusing a server for offering them would be absurd. */
	tc_ssh_wbuf_init(&w, pkt, sizeof pkt);
	tc_ssh_put_u32(&w, 0);
	tc_ssh_put_byte(&w, TC_SFTP_VERSION_MSG);
	tc_ssh_put_u32(&w, 3);
	tc_ssh_put_cstring(&w, "posix-rename@openssh.com");
	tc_ssh_put_cstring(&w, "1");
	size_t len = tc_ssh_wbuf_len(&w);
	patch_len(pkt, len);
	TCT_EQ_INT(tc_sftp_parse_response(&resp, pkt, len), TC_OK);
	TCT_EQ_INT(resp.type, TC_SFTP_VERSION_MSG);
	TCT_EQ_INT((int)resp.version, 3);

	TCT_CASE("a STATUS carries its code");
	tc_ssh_wbuf_init(&w, pkt, sizeof pkt);
	tc_ssh_put_u32(&w, 0);
	tc_ssh_put_byte(&w, TC_SFTP_STATUS);
	tc_ssh_put_u32(&w, 9);
	tc_ssh_put_u32(&w, TC_SFTP_FX_EOF);
	len = tc_ssh_wbuf_len(&w);
	patch_len(pkt, len);
	TCT_EQ_INT(tc_sftp_parse_response(&resp, pkt, len), TC_OK);
	TCT_EQ_INT((int)resp.status, TC_SFTP_FX_EOF);
	TCT_EQ_INT((int)resp.id, 9);

	TCT_CASE("a STATUS with no message is accepted");
	/* Version 3 servers in the wild omit the message and language, and a
	 * client that required them would reject a legitimate EOF. */
	TCT_EQ_INT(resp.type, TC_SFTP_STATUS);

	TCT_CASE("every response is refused at every truncation");
	tc_ssh_wbuf_init(&w, pkt, sizeof pkt);
	tc_ssh_put_u32(&w, 0);
	tc_ssh_put_byte(&w, TC_SFTP_ATTRS);
	tc_ssh_put_u32(&w, 3);
	tc_ssh_put_u32(&w, TC_SFTP_ATTR_SIZE | TC_SFTP_ATTR_ACMODTIME);
	tc_ssh_put_u64(&w, 4096);
	tc_ssh_put_u32(&w, 111);
	tc_ssh_put_u32(&w, 222);
	len = tc_ssh_wbuf_len(&w);
	patch_len(pkt, len);
	TCT_EQ_INT(tc_sftp_parse_response(&resp, pkt, len), TC_OK);
	TCT_TRUE(resp.attrs.size == 4096);
	TCT_EQ_INT((int)resp.attrs.mtime, 222);
	for (size_t cut = 0; cut < len; cut++)
		if (tc_sftp_parse_response(&resp, pkt, cut) == TC_OK)
			TCT_FAILF("an ATTRS truncated to %zu bytes parsed", cut);
	tct_checks++;
}

int main(void)
{
	test_framing();
	test_parse_write();
	test_parse_open();
	test_attrs_extended();
	test_unknown_requests_keep_their_id();
	test_builders();
	test_handles_are_the_servers_to_choose();
	test_name_listings();
	test_client_responses();
	return tct_report("sftp");
}
