// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2022, Foundries.io Ltd.
 * Author: Jorge Ramirez-Ortiz <jorge@foundries.io>
 */
#ifndef FIO_UTIL_H
#define FIO_UTIL_H

#define bswap32(v)                                          \
    (((v) << 24) ^ ((v) >> 24) ^                            \
    (((v) & 0x0000ff00) << 8) ^ (((v) & 0x00ff0000) >> 8))

int fio_util_hex2bin(const unsigned char *in, unsigned char *out,
		     size_t *outlen);
int fio_util_read_file(unsigned char *name, unsigned char **out,
		       size_t *outlen);
int fio_util_barray2str(unsigned char *in, size_t in_len,char *def, char **out);

#endif