// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2022, Foundries.io Ltd.
 * Author: Jorge Ramirez-Ortiz <jorge@foundries.io>
 */
#ifndef FIO_SSL_H
#define FIO_SSL_H

struct fio_cert_info {
	struct {
		unsigned char data[1024];
		size_t len;
	} subject;

	struct {
		unsigned char data[1024];
		size_t len;
	} issuer;

	struct {
		unsigned char data[1024];
		size_t len;
	} serial;
};

int fio_ssl_get_cert_info(struct fio_cert_info *info, unsigned char *der, size_t len);
int fio_ssl_print_cert(unsigned char *der, size_t len);

#endif
