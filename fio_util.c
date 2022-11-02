// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2022, Foundries.io Ltd.
 * Author: Jorge Ramirez-Ortiz <jorge@foundries.io>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

int fio_util_hex2bin(const unsigned char *in, unsigned char *out,
		     size_t *outlen)
{
	const char *separators = " :";
	size_t left = *outlen;
	int need_nibble = 0;
	unsigned char byte = 0;
	int r = 0;

	if (in == NULL || out == NULL || outlen == NULL)
		return -1;

	while (*in != '\0' && 0 != left) {
		char c = *in++;
		unsigned char nibble;
		if      ('0' <= c && c <= '9')
			nibble = c - '0';
		else if ('a' <= c && c <= 'f')
			nibble = c - 'a' + 10;
		else if ('A' <= c && c <= 'F')
			nibble = c - 'A' + 10;
		else {
			if (strchr(separators, (int)c)) {
				if (need_nibble) {
					r = -1;
					goto err;
				}
				continue;
			}
			r = -1;
			goto err;
		}

		if (need_nibble) {
			byte |= nibble;
			*out++ = (unsigned char)byte;
			left--;
			need_nibble = 0;
		} else {
			byte = nibble << 4;
			need_nibble = 1;
		}
	}

	if (left == *outlen && 1 == need_nibble && 0 != left) {
		*out = (unsigned char)byte >> 4;
		left--;
		need_nibble = 0;
	}

	if (need_nibble) {
		r = -1;
		goto err;
	}

	while (*in != '\0') {
		if (NULL == strchr(separators, (int)*in))
			break;
		in++;
	}

	if (*in != '\0') {
		r = -1;
		goto err;
	}
err:
	*outlen -= left;

	return r;
}

int fio_util_read_file(unsigned char *name, unsigned char **out, size_t *len)
{
	struct stat st = { };
	FILE *file = NULL;

	if (!name)
		return -1;

	stat((const char *)name, &st);
	if (!st.st_size)
		return -1;

	file = fopen((char *)name, "rb");
	if (!file)
		return -1;

	*out = malloc(st.st_size);
	if (!*out)
		return -1;

	*len = fread(*out, 1, st.st_size, file);
	if (*len != st.st_size) {
		free(*out);
		return -1;
	}

	fclose(file);

	return 0;
}
