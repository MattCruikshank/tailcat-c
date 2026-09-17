/* SPDX-License-Identifier: BSD-3-Clause
 *
 * SFTP version 3 (draft-ietf-secsh-filexfer-02), the codec only.
 *
 * Version 3 and not a later one because 3 is what OpenSSH implements, and
 * OpenSSH's sftp and scp are the clients this has to serve. The later drafts
 * are better specified and nothing speaks them.
 *
 * This file is the wire format and nothing else: parsing requests, building
 * responses, no files and no policy. What may be done is tc/dropbox.h's
 * question, and keeping the two apart is deliberate -- a codec that also
 * decides permissions is one where a parsing change quietly becomes a
 * permissions change.
 *
 * ---- SFTP runs inside a channel, which has its own framing ---------------
 *
 * An SFTP packet is a uint32 length followed by that many bytes, carried over
 * an SSH channel that is a byte stream. The channel's own message boundaries
 * mean nothing here: one SFTP packet may arrive in several CHANNEL_DATA
 * messages, and several may arrive in one. tc_sftp_packet_len exists so a
 * caller can accumulate bytes until a whole packet is present rather than
 * assuming a read gave it one.
 */
#ifndef TC_SFTP_H_
#define TC_SFTP_H_

#include "tc/tc.h"

/* The version we speak. */
#define TC_SFTP_VERSION 3

/* Requests. */
#define TC_SFTP_INIT 1
#define TC_SFTP_VERSION_MSG 2
#define TC_SFTP_OPEN 3
#define TC_SFTP_CLOSE 4
#define TC_SFTP_READ 5
#define TC_SFTP_WRITE 6
#define TC_SFTP_LSTAT 7
#define TC_SFTP_FSTAT 8
#define TC_SFTP_SETSTAT 9
#define TC_SFTP_FSETSTAT 10
#define TC_SFTP_OPENDIR 11
#define TC_SFTP_READDIR 12
#define TC_SFTP_REMOVE 13
#define TC_SFTP_MKDIR 14
#define TC_SFTP_RMDIR 15
#define TC_SFTP_REALPATH 16
#define TC_SFTP_STAT 17
#define TC_SFTP_RENAME 18
#define TC_SFTP_READLINK 19
#define TC_SFTP_SYMLINK 20

/* Responses. */
#define TC_SFTP_STATUS 101
#define TC_SFTP_HANDLE 102
#define TC_SFTP_DATA 103
#define TC_SFTP_NAME 104
#define TC_SFTP_ATTRS 105

/* Status codes. */
#define TC_SFTP_FX_OK 0
#define TC_SFTP_FX_EOF 1
#define TC_SFTP_FX_NO_SUCH_FILE 2
#define TC_SFTP_FX_PERMISSION_DENIED 3
#define TC_SFTP_FX_FAILURE 4
#define TC_SFTP_FX_BAD_MESSAGE 5
#define TC_SFTP_FX_OP_UNSUPPORTED 8

/* Open flags. */
#define TC_SFTP_FXF_READ 0x01u
#define TC_SFTP_FXF_WRITE 0x02u
#define TC_SFTP_FXF_APPEND 0x04u
#define TC_SFTP_FXF_CREAT 0x08u
#define TC_SFTP_FXF_TRUNC 0x10u
#define TC_SFTP_FXF_EXCL 0x20u

/* Attribute flags. */
#define TC_SFTP_ATTR_SIZE 0x01u
#define TC_SFTP_ATTR_UIDGID 0x02u
#define TC_SFTP_ATTR_PERMISSIONS 0x04u
#define TC_SFTP_ATTR_ACMODTIME 0x08u
#define TC_SFTP_ATTR_EXTENDED 0x80000000u

/* The largest packet we will accept. OpenSSH's sftp uses 32KB writes by
 * default and negotiates nothing, so this is comfortably above what any
 * client sends while staying inside one SSH channel packet. */
#define TC_SFTP_MAX_PACKET 40000
#define TC_SFTP_MAX_PATH 1024
#define TC_SFTP_HANDLE_LEN 8

/* File attributes, as much of them as version 3 has. */
typedef struct {
	uint32_t flags;
	uint64_t size;
	uint32_t uid, gid;
	uint32_t permissions;
	uint32_t atime, mtime;
} tc_sftp_attrs;

typedef struct {
	uint8_t type;
	uint32_t id; /* undefined for INIT, which carries a version instead */
	uint32_t version;

	/* For the path-taking requests. NUL-terminated, and an embedded NUL in
	 * the wire string is refused rather than truncated -- a path that means
	 * one thing here and another to open(2) is the whole problem. */
	char path[TC_SFTP_MAX_PATH];
	char path2[TC_SFTP_MAX_PATH]; /* RENAME's second argument */

	uint8_t handle[TC_SFTP_HANDLE_LEN];
	bool has_handle;

	uint64_t offset;
	uint32_t length; /* READ */

	const uint8_t *data; /* WRITE; points into the caller's buffer */
	size_t data_len;

	uint32_t pflags; /* OPEN */
	tc_sftp_attrs attrs;
} tc_sftp_request;

/* tc_sftp_packet_len reads the length prefix from at least four buffered
 * bytes and reports the whole packet's size, prefix included.
 *
 * Returns TC_ERR_AGAIN when fewer than four bytes are available, so a caller
 * can use it directly as "do I have a packet yet?". A length over
 * TC_SFTP_MAX_PACKET is TC_ERR_TOOMANY: the number is attacker-controlled and
 * arrives before anything has authenticated it as reasonable. */
int tc_sftp_packet_len(const uint8_t *buf, size_t avail, size_t *out_total);

/* tc_sftp_parse reads one complete packet, prefix included. */
int tc_sftp_parse(tc_sftp_request *out, const uint8_t *pkt, size_t len);

/* Builders. Each writes a complete packet with its length prefix. */
int tc_sftp_build_version(uint8_t *out, size_t cap, size_t *out_len);
int tc_sftp_build_status(uint8_t *out, size_t cap, size_t *out_len,
                         uint32_t id, uint32_t code, const char *message);
int tc_sftp_build_handle(uint8_t *out, size_t cap, size_t *out_len,
                         uint32_t id,
                         const uint8_t handle[TC_SFTP_HANDLE_LEN]);
int tc_sftp_build_data(uint8_t *out, size_t cap, size_t *out_len, uint32_t id,
                       const void *data, size_t data_len);
int tc_sftp_build_attrs(uint8_t *out, size_t cap, size_t *out_len,
                        uint32_t id, const tc_sftp_attrs *attrs);

/* tc_sftp_build_name writes a one-entry NAME response, which is all
 * REALPATH needs. A listing would need more, and this server does not list.
 */
int tc_sftp_build_name(uint8_t *out, size_t cap, size_t *out_len, uint32_t id,
                       const char *filename, const char *longname,
                       const tc_sftp_attrs *attrs);

#endif /* TC_SFTP_H_ */
