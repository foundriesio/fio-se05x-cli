// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2022, Foundries.io Ltd.
 * Author: Jorge Ramirez-Ortiz <jorge@foundries.io>
 */
#ifndef fio_pkcs11_h
#define fio_pkcs11_h

#include <stdbool.h>
#include "list.h"

#define EMPTY_STR "--"
struct fio_key_info {
	LIST_ENTRY(fio_key_info) link;
	unsigned char *val;
	size_t len;
	char *label;
	char *id;
};

LIST_HEAD(fio_key_list, fio_key_info);
extern struct fio_key_list rsa_list;
extern struct fio_key_list ec_list;

static inline bool pkcs11_info_available(void)
{
	return !LIST_EMPTY(&rsa_list) || !LIST_EMPTY(&ec_list);
}

static inline void pkcs11_free_info(struct fio_key_info *info)
{
	if (memcmp(info->label, EMPTY_STR, strlen(info->label)))
		free(info->label);
	if (memcmp(info->id, EMPTY_STR, strlen(info->id)))
		free(info->id);
	free(info);
}

static inline void pkcs11_info2pad(char *pad, struct fio_key_info *info)
{
	/* pushes (label, id) pairs */
	strcat((char *)pad, "(");
	strcat((char *)pad, (char *)info->label);
	strcat(pad, ", ");
	strcat((char *)pad, (char *)info->id);
	strcat(pad, ") ");
}

int fio_pkcs11_import_cert(unsigned char *token_label, unsigned char *id,
			   unsigned char *label, unsigned char *der,
			   size_t der_len);

int fio_pkcs11_import_key(unsigned char *token_label, unsigned char *nxp_id,
			  unsigned char *id, unsigned char *pin,
			  unsigned char *type);

int fio_pkcs11_create_key_list(unsigned char *token, unsigned char *pin);

#endif
