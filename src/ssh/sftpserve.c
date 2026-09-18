/* SPDX-License-Identifier: BSD-3-Clause
 *
 * See include/tc/sftpserve.h.
 */
#include "tc/sftpserve.h"

#include <stdlib.h>
#include <string.h>

int tc_sftp_serve(tc_ssh_server *s, tc_sftp_handler_fn handle,
                  void *ctx)
{
	if (s == NULL || handle == NULL)
		return TC_ERR_INVAL;

	/* Heap rather than stack: nearly 120KB between the two, and this may run
	 * on a thread or inside an event loop whose stack is not ours to spend. */
	uint8_t *buf = malloc(TC_SFTP_MAX_PACKET * 2);
	uint8_t *reply = malloc(TC_SFTP_MAX_PACKET);
	if (buf == NULL || reply == NULL) {
		free(buf);
		free(reply);
		return TC_ERR_NOSPACE;
	}
	size_t have = 0;
	int rc = TC_OK;

	for (;;) {
		/* Everything already buffered, before reading more: a single read may
		 * have brought several packets. */
		bool stop = false;
		for (;;) {
			size_t total = 0;
			int lr = tc_sftp_packet_len(buf, have, &total);
			if (lr == TC_ERR_AGAIN)
				break; /* not even a length yet */
			if (lr != TC_OK) {
				rc = lr;
				stop = true;
				break;
			}
			if (have < total)
				break; /* length known, body still arriving */

			tc_sftp_request req;
			size_t reply_len = 0;
			rc = tc_sftp_parse(&req, buf, total);
			if (rc == TC_OK)
				rc = handle(ctx, &req, reply, TC_SFTP_MAX_PACKET,
				            &reply_len);
			if (rc != TC_OK) {
				stop = true;
				break;
			}
			rc = tc_ssh_server_write(s, reply, reply_len);
			if (rc != TC_OK) {
				stop = true;
				break;
			}

			memmove(buf, buf + total, have - total);
			have -= total;
		}
		if (stop)
			break;

		if (have == TC_SFTP_MAX_PACKET * 2) {
			/* Unreachable: tc_sftp_packet_len caps a packet at half this, so
			 * a full buffer means the accounting above is wrong rather than
			 * that a client is large. */
			rc = TC_ERR_TOOMANY;
			break;
		}

		size_t got = 0;
		rc = tc_ssh_server_read(s, buf + have, TC_SFTP_MAX_PACKET * 2 - have,
		                        &got);
		if (rc == TC_ERR_DONE || rc == TC_ERR_CLOSED) {
			rc = TC_OK;
			break;
		}
		if (rc != TC_OK)
			break;
		have += got;
	}

	free(buf);
	free(reply);

	/* Without this a client reports a failure for a transfer that worked: it
	 * reads the subsystem's exit status, and a channel that closes without
	 * one looks like a server that died part way through. */
	if (rc == TC_OK)
		(void)tc_ssh_server_exit(s, 0);
	return rc;
}
