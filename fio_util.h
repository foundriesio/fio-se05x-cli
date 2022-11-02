// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2022, Foundries.io Ltd.
 * Author: Jorge Ramirez-Ortiz <jorge@foundries.io>
 */
#ifndef FIO_UTIL_H
#define FIO_UTIL_H

int fio_util_hex2bin(const unsigned char *in, unsigned char *out, size_t *outlen);
int fio_util_read_file(unsigned char *name, unsigned char **out, size_t *outlen);

#endif