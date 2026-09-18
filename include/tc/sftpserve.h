/* SPDX-License-Identifier: BSD-3-Clause
 *
 * The SFTP framing loop, shared by every policy that sits behind it.
 *
 * tc/sftp.h is the wire format and has no opinions. tc/dropbox.h and
 * tc/fileserv.h are two sets of opinions about what a client may do. This is
 * the part in between, which neither of them should have a copy of: read a
 * length-prefixed packet off the SSH channel, parse it, hand it to whoever is
 * deciding, write the answer back.
 *
 * It was inside the drop box until the file server needed the same loop.
 * Copying it would have meant two framing implementations that could drift,
 * and framing is where a subtly different length check becomes a subtly
 * different attack surface -- so it moved here instead, unchanged.
 */
#ifndef TC_SFTPSERVE_H_
#define TC_SFTPSERVE_H_

#include "tc/sftp.h"
#include "tc/sshserver.h"

/* Decides what one request is allowed to do and writes the reply.
 *
 * Returning anything but TC_OK ends the session, so a policy that means
 * "refused" must say so *in the reply* -- with TC_SFTP_STATUS -- and return
 * TC_OK. A client told "permission denied" reports something useful; one that
 * is hung up on reports a network error. */
typedef int (*tc_sftp_handler_fn)(void *ctx, const tc_sftp_request *req,
                                  uint8_t *out, size_t cap, size_t *out_len);

/* tc_sftp_serve runs the loop until the channel closes or the client sends
 * something the framing cannot make sense of. */
int tc_sftp_serve(tc_ssh_server *s, tc_sftp_handler_fn handle, void *ctx);

#endif /* TC_SFTPSERVE_H_ */
