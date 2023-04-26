// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2022, Foundries.io Ltd.
 * Author: Jorge Ramirez-Ortiz <jorge@foundries.io>
 */
#ifndef fio_pkcs11_h
#define fio_pkcs11_h

struct fio_key_info {
	unsigned char *val;
	size_t len;
	unsigned char *label;
};

struct fio_pkcs11_keys {
	struct fio_key_info *ec[100];
	struct fio_key_info *rsa[100];
};

extern struct fio_pkcs11_keys pkcs11_keys;
extern size_t pkcs11_rsa_idx;
extern size_t pkcs11_ec_idx;

int fio_pkcs11_import_cert(unsigned char *token_label, unsigned char *id,
			   unsigned char *label, unsigned char *der,
			   size_t der_len);

int fio_pkcs11_import_key(unsigned char *token_label, unsigned char *nxp_id,
			  unsigned char *id, unsigned char *pin,
			  unsigned char *type);

int fio_pkcs11_create_key_list(unsigned char *token, unsigned char *pin);

#endif
