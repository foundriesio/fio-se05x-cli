// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2022, Foundries.io Ltd.
 * Author: Jorge Ramirez-Ortiz <jorge@foundries.io>
 */
#ifndef fio_pkcs11_h
#define fio_pkcs11_h

int fio_pkcs11_import_cert(unsigned char *token_label, unsigned char *id,
			   unsigned char *label, unsigned char *der,
			   size_t der_len);

int fio_pkcs11_import_key(unsigned char *token_label, unsigned char *nxp_id,
			  unsigned char *id, unsigned char *pin,
			  unsigned char *type);

#endif
