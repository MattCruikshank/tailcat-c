/* SPDX-License-Identifier: BSD-3-Clause
 *
 * SFTP version 3 codec. See tc/sftp.h.
 */

#include "tc/sftp.h"

#include "tc/sshwire.h"

#include <string.h>

int tc_sftp_packet_len(const uint8_t *buf, size_t avail, size_t *out_total)
{
	if (buf == NULL || out_total == NULL)
		return TC_ERR_INVAL;
	if (avail < 4)
		return TC_ERR_AGAIN;

	uint32_t body = (uint32_t)buf[0] << 24 | (uint32_t)buf[1] << 16 |
	                (uint32_t)buf[2] << 8 | (uint32_t)buf[3];
	/* An empty packet has no type byte, so it names no request. */
	if (body < 1)
		return TC_ERR_INVAL;
	if (body > TC_SFTP_MAX_PACKET)
		return TC_ERR_TOOMANY;

	*out_total = 4 + (size_t)body;
	return TC_OK;
}

/* read_attrs reads a version 3 ATTRS structure.
 *
 * The extended block is read and discarded rather than refused: a client that
 * attaches one is not misbehaving, and version 3 puts it last so skipping it
 * is well defined. Refusing would break clients for a field we simply have no
 * use for. */
static bool read_attrs(tc_ssh_rbuf *r, tc_sftp_attrs *a)
{
	memset(a, 0, sizeof *a);
	a->flags = tc_ssh_get_u32(r);
	if (a->flags & TC_SFTP_ATTR_SIZE)
		a->size = tc_ssh_get_u64(r);
	if (a->flags & TC_SFTP_ATTR_UIDGID) {
		a->uid = tc_ssh_get_u32(r);
		a->gid = tc_ssh_get_u32(r);
	}
	if (a->flags & TC_SFTP_ATTR_PERMISSIONS)
		a->permissions = tc_ssh_get_u32(r);
	if (a->flags & TC_SFTP_ATTR_ACMODTIME) {
		a->atime = tc_ssh_get_u32(r);
		a->mtime = tc_ssh_get_u32(r);
	}
	if (a->flags & TC_SFTP_ATTR_EXTENDED) {
		uint32_t count = tc_ssh_get_u32(r);
		/* Bounded against the bytes remaining rather than against a
		 * constant: each pair costs at least eight bytes, so a count that
		 * could not fit is refused before the loop rather than by it. */
		if (!tc_ssh_rbuf_ok(r) || (size_t)count * 8 > tc_ssh_rbuf_remaining(r))
			return false;
		for (uint32_t i = 0; i < count; i++) {
			(void)tc_ssh_get_string(r, SIZE_MAX, NULL);
			(void)tc_ssh_get_string(r, SIZE_MAX, NULL);
		}
	}
	return tc_ssh_rbuf_ok(r);
}

static void write_attrs(tc_ssh_wbuf *w, const tc_sftp_attrs *a)
{
	/* Only the fields the flags claim, and never the extended block: we
	 * have nothing to put in it and an empty one is still a field a client
	 * has to parse. */
	uint32_t flags = a->flags & ~TC_SFTP_ATTR_EXTENDED;
	tc_ssh_put_u32(w, flags);
	if (flags & TC_SFTP_ATTR_SIZE)
		tc_ssh_put_u64(w, a->size);
	if (flags & TC_SFTP_ATTR_UIDGID) {
		tc_ssh_put_u32(w, a->uid);
		tc_ssh_put_u32(w, a->gid);
	}
	if (flags & TC_SFTP_ATTR_PERMISSIONS)
		tc_ssh_put_u32(w, a->permissions);
	if (flags & TC_SFTP_ATTR_ACMODTIME) {
		tc_ssh_put_u32(w, a->atime);
		tc_ssh_put_u32(w, a->mtime);
	}
}

static bool read_handle(tc_ssh_rbuf *r, tc_sftp_request *out)
{
	size_t n = 0;
	const uint8_t *h = tc_ssh_get_string(r, TC_SFTP_HANDLE_LEN, &n);
	if (h == NULL || n != TC_SFTP_HANDLE_LEN)
		return false;
	memcpy(out->handle, h, TC_SFTP_HANDLE_LEN);
	out->has_handle = true;
	return true;
}

int tc_sftp_parse(tc_sftp_request *out, const uint8_t *pkt, size_t len)
{
	if (out == NULL || pkt == NULL)
		return TC_ERR_INVAL;
	memset(out, 0, sizeof *out);

	size_t want = 0;
	int rc = tc_sftp_packet_len(pkt, len, &want);
	if (rc != TC_OK)
		return rc;
	/* Exactly one packet, not a prefix of the stream: a parser that accepted
	 * "at least this much" would read the next request's bytes as this
	 * one's payload. */
	if (len != want)
		return TC_ERR_INVAL;

	tc_ssh_rbuf r;
	tc_ssh_rbuf_init(&r, pkt + 4, len - 4);
	out->type = tc_ssh_get_byte(&r);

	if (out->type == TC_SFTP_INIT) {
		/* INIT is the one request with no id: the version takes its place. */
		out->version = tc_ssh_get_u32(&r);
		return tc_ssh_rbuf_ok(&r) ? TC_OK : TC_ERR_INVAL;
	}

	out->id = tc_ssh_get_u32(&r);
	if (!tc_ssh_rbuf_ok(&r))
		return TC_ERR_INVAL;

	switch (out->type) {
	case TC_SFTP_OPEN:
		if (!tc_ssh_get_cstring(&r, out->path, sizeof out->path))
			return TC_ERR_INVAL;
		out->pflags = tc_ssh_get_u32(&r);
		if (!read_attrs(&r, &out->attrs))
			return TC_ERR_INVAL;
		break;

	case TC_SFTP_CLOSE:
	case TC_SFTP_FSTAT:
	case TC_SFTP_READDIR:
		if (!read_handle(&r, out))
			return TC_ERR_INVAL;
		break;

	case TC_SFTP_READ:
		if (!read_handle(&r, out))
			return TC_ERR_INVAL;
		out->offset = tc_ssh_get_u64(&r);
		out->length = tc_ssh_get_u32(&r);
		break;

	case TC_SFTP_WRITE:
		if (!read_handle(&r, out))
			return TC_ERR_INVAL;
		out->offset = tc_ssh_get_u64(&r);
		out->data = tc_ssh_get_string(&r, TC_SFTP_MAX_PACKET, &out->data_len);
		if (out->data == NULL)
			return TC_ERR_INVAL;
		break;

	case TC_SFTP_FSETSTAT:
		if (!read_handle(&r, out))
			return TC_ERR_INVAL;
		if (!read_attrs(&r, &out->attrs))
			return TC_ERR_INVAL;
		break;

	case TC_SFTP_SETSTAT:
	case TC_SFTP_MKDIR:
		if (!tc_ssh_get_cstring(&r, out->path, sizeof out->path))
			return TC_ERR_INVAL;
		if (!read_attrs(&r, &out->attrs))
			return TC_ERR_INVAL;
		break;

	case TC_SFTP_RENAME:
	case TC_SFTP_SYMLINK:
		if (!tc_ssh_get_cstring(&r, out->path, sizeof out->path))
			return TC_ERR_INVAL;
		if (!tc_ssh_get_cstring(&r, out->path2, sizeof out->path2))
			return TC_ERR_INVAL;
		break;

	case TC_SFTP_LSTAT:
	case TC_SFTP_STAT:
	case TC_SFTP_OPENDIR:
	case TC_SFTP_REMOVE:
	case TC_SFTP_RMDIR:
	case TC_SFTP_REALPATH:
	case TC_SFTP_READLINK:
		if (!tc_ssh_get_cstring(&r, out->path, sizeof out->path))
			return TC_ERR_INVAL;
		break;

	default:
		/* An unknown request still has an id, which is all a caller needs to
		 * answer it with OP_UNSUPPORTED. Refusing to parse it would leave
		 * nothing to address the refusal to. */
		return TC_OK;
	}

	return tc_ssh_rbuf_ok(&r) ? TC_OK : TC_ERR_INVAL;
}

/* ---- builders ---------------------------------------------------------- */

/* finish backfills the length prefix once the body is known. */
static int finish(tc_ssh_wbuf *w, uint8_t *out, size_t *out_len)
{
	if (!tc_ssh_wbuf_ok(w))
		return TC_ERR_NOSPACE;
	size_t total = tc_ssh_wbuf_len(w);
	uint32_t body = (uint32_t)(total - 4);
	out[0] = (uint8_t)(body >> 24);
	out[1] = (uint8_t)(body >> 16);
	out[2] = (uint8_t)(body >> 8);
	out[3] = (uint8_t)body;
	if (out_len != NULL)
		*out_len = total;
	return TC_OK;
}

int tc_sftp_build_version(uint8_t *out, size_t cap, size_t *out_len)
{
	if (out == NULL)
		return TC_ERR_INVAL;
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, out, cap);
	tc_ssh_put_u32(&w, 0); /* length, filled in by finish */
	tc_ssh_put_byte(&w, TC_SFTP_VERSION_MSG);
	tc_ssh_put_u32(&w, TC_SFTP_VERSION);
	/* No extensions. posix-rename and the statvfs pair are the ones clients
	 * look for; a drop box implements none of them, and advertising an
	 * extension we do not serve is worse than staying quiet. */
	return finish(&w, out, out_len);
}

int tc_sftp_build_status(uint8_t *out, size_t cap, size_t *out_len,
                         uint32_t id, uint32_t code, const char *message)
{
	if (out == NULL)
		return TC_ERR_INVAL;
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, out, cap);
	tc_ssh_put_u32(&w, 0);
	tc_ssh_put_byte(&w, TC_SFTP_STATUS);
	tc_ssh_put_u32(&w, id);
	tc_ssh_put_u32(&w, code);
	tc_ssh_put_cstring(&w, message != NULL ? message : "");
	tc_ssh_put_cstring(&w, ""); /* language tag */
	return finish(&w, out, out_len);
}

int tc_sftp_build_handle(uint8_t *out, size_t cap, size_t *out_len,
                         uint32_t id, const uint8_t handle[TC_SFTP_HANDLE_LEN])
{
	if (out == NULL || handle == NULL)
		return TC_ERR_INVAL;
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, out, cap);
	tc_ssh_put_u32(&w, 0);
	tc_ssh_put_byte(&w, TC_SFTP_HANDLE);
	tc_ssh_put_u32(&w, id);
	tc_ssh_put_string(&w, handle, TC_SFTP_HANDLE_LEN);
	return finish(&w, out, out_len);
}

int tc_sftp_build_data(uint8_t *out, size_t cap, size_t *out_len, uint32_t id,
                       const void *data, size_t data_len)
{
	if (out == NULL || (data == NULL && data_len != 0))
		return TC_ERR_INVAL;
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, out, cap);
	tc_ssh_put_u32(&w, 0);
	tc_ssh_put_byte(&w, TC_SFTP_DATA);
	tc_ssh_put_u32(&w, id);
	tc_ssh_put_string(&w, data, data_len);
	return finish(&w, out, out_len);
}

int tc_sftp_build_attrs(uint8_t *out, size_t cap, size_t *out_len, uint32_t id,
                        const tc_sftp_attrs *attrs)
{
	if (out == NULL || attrs == NULL)
		return TC_ERR_INVAL;
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, out, cap);
	tc_ssh_put_u32(&w, 0);
	tc_ssh_put_byte(&w, TC_SFTP_ATTRS);
	tc_ssh_put_u32(&w, id);
	write_attrs(&w, attrs);
	return finish(&w, out, out_len);
}

int tc_sftp_build_name(uint8_t *out, size_t cap, size_t *out_len, uint32_t id,
                       const char *filename, const char *longname,
                       const tc_sftp_attrs *attrs)
{
	if (out == NULL || filename == NULL || attrs == NULL)
		return TC_ERR_INVAL;
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, out, cap);
	tc_ssh_put_u32(&w, 0);
	tc_ssh_put_byte(&w, TC_SFTP_NAME);
	tc_ssh_put_u32(&w, id);
	tc_ssh_put_u32(&w, 1); /* one entry */
	tc_ssh_put_cstring(&w, filename);
	tc_ssh_put_cstring(&w, longname != NULL ? longname : filename);
	write_attrs(&w, attrs);
	return finish(&w, out, out_len);
}
