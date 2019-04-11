/*
 * Copyright (C) 2019 Dream Property GmbH, Germany
 *                    https://dreambox.de/
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <tpmd.h>
#include "tpmd_socket.h"

struct tpmd_context {
	int fd;
	unsigned int protocol_version;
	unsigned int tpm_generation;
};

static void send_cmd(int fd, enum tpmd_cmd cmd, const void *data, unsigned int len)
{
	unsigned char buf[len + 4];

	buf[0] = (cmd >> 8) & 0xff;
	buf[1] = (cmd >> 0) & 0xff;
	buf[2] = (len >> 8) & 0xff;
	buf[3] = (len >> 0) & 0xff;
	memcpy(&buf[4], data, len);

	if (write(fd, buf, sizeof(buf)) != (ssize_t)sizeof(buf))
		fprintf(stderr, "%s: incomplete write: %s\n", __func__, strerror(errno));
}

static void *recv_cmd(int fd, unsigned int *tag, unsigned int *len)
{
	unsigned char buf[4];
	void *val;

	if (read(fd, buf, 4) != 4)
		fprintf(stderr, "%s: incomplete read: %s\n", __func__, strerror(errno));

	*tag = (buf[0] << 8) | buf[1];
	*len = (buf[2] << 8) | buf[3];

	val = malloc(*len);
	if (read(fd, val, *len) != (ssize_t)*len)
		fprintf(stderr, "%s: incomplete read: %s\n", __func__, strerror(errno));

	return val;
}

static void parse_data(struct tpmd_context *ctx, enum tpmd_cmd cmd, const unsigned char *data, unsigned int datalen,
	struct buffer **ica, struct buffer **leaf)
{
	unsigned int tag, len;
	const unsigned char *val;
	unsigned int i;

	for (i = 0; i < datalen; i += len) {
		tag = data[i++];
		if (cmd == TPMD_CMD_GET_DATA)
			len = 0;
		else
			len = data[i++] << 8;
		len |= data[i++];
		val = &data[i];

		switch (tag) {
		case TPMD_DT_PROTOCOL_VERSION:
			if (len != 1)
				break;
			ctx->protocol_version = val[0];
			break;
		case TPMD_DT_TPM_VERSION:
			if (len != 1)
				break;
			ctx->tpm_generation = val[0];
			break;
		case TPMD_DT_LEVEL2_CERT:
			if (ica != NULL)
				buffer_copy(ica, val, len);
			break;
		case TPMD_DT_LEVEL3_CERT:
			if (leaf != NULL)
				buffer_copy(leaf, val, len);
			break;
		}
	}
}

struct tpmd_context *tpmd_connect(void)
{
	struct tpmd_context *ctx;
	struct sockaddr_un addr;

	ctx = calloc(1, sizeof(struct tpmd_context));
	if (ctx == NULL)
		return NULL;

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, TPMD_SOCKET);

	ctx->fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (ctx->fd < 0) {
		free(ctx);
		return NULL;
	}

	if (connect(ctx->fd, (const struct sockaddr *)&addr, SUN_LEN(&addr)) < 0) {
		close(ctx->fd);
		free(ctx);
		return NULL;
	}

	return ctx;
}

void tpmd_disconnect(struct tpmd_context *ctx)
{
	if (ctx != NULL) {
		close(ctx->fd);
		free(ctx);
	}
}

bool tpmd_read_certificates(struct tpmd_context *ctx, struct buffer **ica, struct buffer **leaf)
{
	unsigned int tag, len;
	unsigned char buf[2];
	enum tpmd_cmd cmd;
	void *val;

	buf[0] = TPMD_DT_PROTOCOL_VERSION;
	buf[1] = TPMD_DT_TPM_VERSION;
	send_cmd(ctx->fd, TPMD_CMD_GET_DATA, buf, 2);
	val = recv_cmd(ctx->fd, &tag, &len);
	if (val == NULL)
		return false;

	assert(tag == TPMD_CMD_GET_DATA);
	parse_data(ctx, tag, val, len, NULL, NULL);
	free(val);

	buf[0] = TPMD_DT_LEVEL2_CERT;
	buf[1] = TPMD_DT_LEVEL3_CERT;
	cmd = (ctx->protocol_version >= 3) ? TPMD_CMD_GET_DATA_V2 : TPMD_CMD_GET_DATA;
	send_cmd(ctx->fd, cmd, buf, 2);
	val = recv_cmd(ctx->fd, &tag, &len);
	if (val == NULL)
		return false;

	assert(tag == cmd);
	parse_data(ctx, tag, val, len, ica, leaf);
	free(val);

	return true;
}

bool tpmd_compute_signature(struct tpmd_context *ctx, const struct buffer *buf, struct buffer **signature)
{
	unsigned int tag, len;
	void *val;

	send_cmd(ctx->fd, TPMD_CMD_COMPUTE_SIGNATURE, buf->data, buf->size);
	val = recv_cmd(ctx->fd, &tag, &len);
	if (val == NULL)
		return false;

	assert(tag == TPMD_CMD_COMPUTE_SIGNATURE);
	buffer_copy(signature, val, len);
	free(val);

	return true;
}

unsigned int tpmd_get_generation(struct tpmd_context *ctx)
{
	return ctx->tpm_generation;
}

size_t tpmd_get_signature_size(struct tpmd_context *ctx)
{
	return (ctx->tpm_generation == 1) ? 8 : 32;
}
