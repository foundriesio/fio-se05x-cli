// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2022, Foundries.io Ltd.
 * Author: Jorge Ramirez-Ortiz <jorge@foundries.io>
 */
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <string.h>

#include "fio_ssl.h"

int fio_ssl_get_cert_info(struct fio_cert_info *info, uint8_t *der, size_t len)
{
	X509 *x = NULL;

	if (!info || !der || len == 0)
		return -1;

	x = d2i_X509(NULL, (const unsigned char **)&der, len);
	if (!x)
		return -1;

	/* Get subject */
	info->subject.len = i2d_X509_NAME(X509_get_subject_name(x), NULL);
	if (info->subject.len < 0 ||
	    info->subject.len > sizeof(info->subject.data))
		return -1;
	i2d_X509_NAME(X509_get_subject_name(x),
		      (unsigned char **)&info->subject.data);

	/* Get issuer */
	info->issuer.len = i2d_X509_NAME(X509_get_issuer_name(x), NULL);
	if (info->issuer.len < 0 ||
	    info->issuer.len > sizeof(info->issuer.data))
		return -1;
	i2d_X509_NAME(X509_get_issuer_name(x),
		      (unsigned char **)&info->issuer.data);

	/* Get serial */
	info->serial.len = i2d_ASN1_INTEGER(X509_get_serialNumber(x), NULL);
	if (info->serial.len < 0 ||
	    info->serial.len > sizeof(info->serial.data))
		return -1;
	i2d_ASN1_INTEGER(X509_get_serialNumber(x),
			 (unsigned char **)&info->serial.data);

	return 0;
}

int fio_ssl_print_cert(uint8_t *der, size_t len)
{
	X509 *x = NULL;
	BIO *b = NULL;

	x = d2i_X509(NULL, (const unsigned char **)&der, len);
	if (!x)
		return -1;

	b = BIO_new_fp(stdout, 0);
	if (!b)
		return -1;

	X509_print_ex(b, x,
		      XN_FLAG_SEP_CPLUS_SPC | ASN1_STRFLGS_UTF8_CONVERT, 0);

	BIO_free_all(b);

	return 0;
}
