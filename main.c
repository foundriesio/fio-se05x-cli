// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2022, Foundries.io Ltd.
 * Author: Jorge Ramirez-Ortiz <jorge@foundries.io>
 */
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fio_pkcs11.h"
#include "fio_util.h"
#include "fio_ssl.h"
#include "isoc_7816.h"
#include "se_tee.h"
#include "se05x.h"

#define BINARY_WRITE_MAX_LEN 500

size_t BUF_SIZE_CMD;
size_t BUF_SIZE_RSP;

static int object_exist(uint32_t oid, bool *exist)
{
	uint8_t hdr[] = SE05X_OBJ_EXIST_HEADER;
	uint8_t *cmd = malloc(BUF_SIZE_CMD);
	uint8_t *rsp = malloc(BUF_SIZE_RSP);
	uint8_t *p = cmd;
	size_t rsp_len = BUF_SIZE_RSP;
	size_t rsp_idx = 0;
	size_t cmd_len = 0;
	size_t result_len = 1;
	uint8_t result = 0;

	if (!cmd || !rsp)
		return -ENOMEM;

	if (tlvSet_u32(SE05x_TAG_1, &p, &cmd_len, oid)) {
		fprintf(stderr,"error, cant form command\n");
		goto error;
	}

	if (se_apdu_request(SE_APDU_CASE_4,
			    hdr, sizeof(hdr),
			    cmd, cmd_len,
			    rsp, &rsp_len)) {
		fprintf(stderr,"error, cant communicate with TEE core\n");
		goto error;
	}

	if (tlvGet_u8buf(SE05x_TAG_1, &rsp_idx, rsp, rsp_len,
			 &result, &result_len)) {
		goto error;
	}

	*exist = result == kSE05x_Result_SUCCESS ? true : false;

	free(cmd);
	free(rsp);

	return 0;
error:
	free(cmd);
	free(rsp);

	return -EINVAL;
}

static int object_size(uint32_t oid, uint16_t *len)
{
	uint8_t hdr[] = SE05X_OBJ_SIZE_HEADER;
	uint8_t *cmd = malloc(BUF_SIZE_CMD);
	uint8_t *rsp = malloc(BUF_SIZE_RSP);
	uint8_t *p = cmd;
	size_t rsp_len = BUF_SIZE_RSP;
	size_t rsp_idx = 0;
	size_t cmd_len = 0;

	if (!cmd || !rsp)
		return -ENOMEM;

	if (tlvSet_u32(SE05x_TAG_1, &p, &cmd_len, oid)) {
		fprintf(stderr,"error, cant form command\n");
		goto error;
	}

	if (se_apdu_request(SE_APDU_CASE_4,
			    hdr, sizeof(hdr),
			    cmd, cmd_len,
			    rsp, &rsp_len)) {
		fprintf(stderr,"error, cant communicate with TEE core\n");
		goto error;
	}

	if (tlvGet_u16(SE05x_TAG_1, &rsp_idx, rsp, rsp_len, len)) {
		fprintf(stderr,"error, cant get response\n");
		goto error;
	}
	free(cmd);
	free(rsp);

	return 0;
error:
	free(cmd);
	free(rsp);

	return -EINVAL;
}

static int object_delete(uint32_t oid)
{
	uint8_t hdr[] = SE05X_OBJ_DEL_HEADER;
	uint8_t *cmd = malloc(BUF_SIZE_CMD);
	uint8_t *rsp = malloc(BUF_SIZE_RSP);
	uint8_t *p = cmd;
	size_t rsp_len = BUF_SIZE_RSP;
	size_t cmd_len = 0;

	if (!cmd || !rsp)
		return -ENOMEM;

	if (tlvSet_u32(SE05x_TAG_1, &p, &cmd_len, oid)) {
		fprintf(stderr, "error, cant form command\n");
		goto error;
	}

	if (se_apdu_request(SE_APDU_CASE_3,
			    hdr, sizeof(hdr),
			    cmd, cmd_len,
			    rsp, &rsp_len))
		goto error;

	free(cmd);
	free(rsp);

	return 0;
error:
	free(cmd);
	free(rsp);

	return -EINVAL;
}

static int object_type(uint32_t oid, uint32_t *oid_type, bool *is_binary)
{
	uint8_t hdr[] = SE05X_OBJ_TYPE_HEADER;
	uint8_t *cmd = malloc(BUF_SIZE_CMD);
	uint8_t *rsp = malloc(BUF_SIZE_RSP);
	uint8_t *p = cmd;
	size_t rsp_len = BUF_SIZE_RSP;
	size_t cmd_len = 0;
	size_t rsp_idx = 0;
	uint8_t type = 0;

	if (!cmd || !rsp)
		return -ENOMEM;

	if (tlvSet_u32(SE05x_TAG_1, &p, &cmd_len, oid)) {
		fprintf(stderr,"Error, cant form command\n");
		goto error;
	}

	if (se_apdu_request(SE_APDU_CASE_4,
			    hdr, sizeof(hdr),
			    cmd, cmd_len,
			    rsp, &rsp_len)) {
		fprintf(stderr,"Error, cant communicate with TEE core\n");
		goto error;
	}

	if (tlvGet_u8(SE05x_TAG_1, &rsp_idx, rsp,  rsp_len, &type)) {
		fprintf(stderr,"Error, cant read type\n");
		goto error;
	}

	if (is_binary)
		*is_binary = type ==  BINARY_FILE ? true : false;

	if (oid_type)
		*oid_type = type;

	free(cmd);
	free(rsp);

	return 0;
error:
	free(cmd);
	free(rsp);

	return -EINVAL;
}

static int object_list(uint8_t *list, size_t *list_len)
{
	uint8_t hdr[] = SE05X_OBJ_GET_LIST;
	uint8_t *cmd = malloc(BUF_SIZE_CMD);
	uint8_t *rsp = malloc(BUF_SIZE_RSP);
	uint8_t *p = cmd;
	size_t rsp_len = BUF_SIZE_RSP;
	size_t rsp_idx = 0;
	size_t cmd_len = 0;
	uint8_t more = 0;

	if (tlvSet_u16(SE05x_TAG_1, &p, &cmd_len, 0))
		goto error;

	if (tlvSet_u8(SE05x_TAG_2, &p, &cmd_len, 0xff))
		goto error;

	if (se_apdu_request(SE_APDU_CASE_4E,
			    hdr, sizeof(hdr),
			    cmd, cmd_len,
			    rsp, &rsp_len)) {
		fprintf(stderr, "Error, cant communicate with TEE core\n");
		goto error;
	}

	if (tlvGet_u8(SE05x_TAG_1, &rsp_idx, rsp, rsp_len, &more))
		goto error;

	if (tlvGet_u8buf(SE05x_TAG_2, &rsp_idx, rsp, rsp_len, list, list_len)) {
		fprintf(stderr, "Error, cant get the list\n");
		goto error;
	}

	free(cmd);
	free(rsp);

	return 0;
error:
	free(cmd);
	free(rsp);

	return -EINVAL;
}

static int object_get(uint32_t oid, uint16_t offset, uint16_t len,
		      uint8_t *buf, size_t *buf_len)
{
	uint8_t hdr[] = SE05X_OBJ_GET_HEADER;
	uint8_t *cmd = malloc(BUF_SIZE_CMD);
	uint8_t *rsp = malloc(BUF_SIZE_RSP);
	uint8_t *p = cmd;
	size_t rsp_len = BUF_SIZE_RSP;
	size_t rsp_idx = 0;
	size_t cmd_len = 0;

	if (!cmd || !rsp)
		return -ENOMEM;

	if (tlvSet_u32(SE05x_TAG_1, &p, &cmd_len, oid))
		goto error;

	if (offset && tlvSet_u16(SE05x_TAG_2, &p, &cmd_len, offset))
		goto error;

	if (len && tlvSet_u16(SE05x_TAG_3, &p, &cmd_len, len))
		goto error;

	if (se_apdu_request(SE_APDU_CASE_4E,
			    hdr, sizeof(hdr),
			    cmd, cmd_len,
			    rsp, &rsp_len)) {
		fprintf(stderr,"Error, cant communicate with TEE core\n");
		goto error;
	}

	if (tlvGet_u8buf(SE05x_TAG_1, &rsp_idx, rsp, rsp_len, buf, buf_len)){
		fprintf(stderr,("Error, cant get the binary data\n"));
		goto error;
	}

	free(cmd);
	free(rsp);

	return 0;
error:
	free(cmd);
	free(rsp);

	return -EINVAL;
}

static int get_certificate(uint32_t oid, unsigned char **der, size_t *der_len)
{
	bool is_binary = false;
	bool found = false;
	size_t offset = 0;
	uint16_t len = 0;

	if (object_exist(oid, &found) || !found) {
		fprintf(stderr,"Error, no object found!\n");
		return -EINVAL;
	}

	if (object_type(oid, NULL, &is_binary) || !is_binary) {
		fprintf(stderr,"Error, not binary type!\n");
		return -EINVAL;
	}

	if (object_size(oid, &len) || !len) {
		fprintf(stderr,"Error, invalid size!\n");
		return -EINVAL;
	}

	*der = calloc(1, len);
	if (!*der) {
		fprintf(stderr,"Error, not enough memory\n");
		return -ENOMEM;
	}

	*der_len = len;

	offset = 0;
	do {
		size_t rcv = len > BINARY_WRITE_MAX_LEN ?
			     BINARY_WRITE_MAX_LEN : len;

		if (object_get(oid, offset, rcv, *der + offset, &rcv)) {
			fprintf(stderr,"Object 0x%x cant be retrieved!\n", oid);

			*der_len = 0;
			free(*der);
			return -EINVAL;
		}
		offset += rcv;
		len -= rcv;
	} while (len);

	return 0;
}

static int do_certificate(bool import, bool show, unsigned char *token,
			  uint32_t nxp, unsigned char *id, unsigned char *label)
{
	unsigned char *der = NULL;
	size_t der_len = 0;
	int ret = 0;

	if (get_certificate(nxp, &der, &der_len)) {
		fprintf(stderr, "APDU import certificate failed\n");
		return -1;
	}

	if (import) {
		ret = fio_pkcs11_import_cert(token, id, label, der, der_len);
		if (ret)
			fprintf(stderr, "Import certificate error %d\n", ret);
	}

	if (show) {
		ret = fio_ssl_print_cert(der, der_len);
		if (ret)
			fprintf(stderr, "Can't print the certificate\n");
	}

	free(der);

	return ret;
}

static int do_key(unsigned char *token, unsigned char *nxp_id,
		  unsigned char *id, unsigned char *pin,
		  unsigned char *key_type)
{
	uint32_t oid = strtoul((char *)nxp_id, NULL, 16);
	bool is_binary = false;
	bool found = false;
	uint16_t len = 0;

	if (object_exist(oid, &found) || !found) {
		fprintf(stderr, "Error, no object found!\n");
		return -EINVAL;
	}

	if (object_type(oid, NULL, &is_binary) || is_binary) {
		fprintf(stderr, "Error, binary type!\n");
		return -EINVAL;
	}

	if (object_size(oid, &len) || !len) {
		fprintf(stderr, "Error, invalid size!\n");
		return -EINVAL;
	}

	if (fio_pkcs11_import_key(token, nxp_id, id, pin, key_type)) {
		fprintf(stderr, "Error importing the key\n");
		return -EINVAL;
	}

	return 0;
}

static int do_list(void)
{
	uint8_t *list = malloc(4096);
	size_t length = 4096;
	uint32_t type = 0;
	uint16_t size = 0;
	uint32_t *p = (uint32_t *)list;

	if (object_list(list, &length)) {
		free(list);
		return -EINVAL;
	}

	for (size_t i = 0; i < length / sizeof(uint32_t); i++, p++) {
		uint32_t id = bswap32(*p);

		if (object_type(id, &type, NULL))
			continue;

		if (object_size(id, &size))
			continue;

		fprintf(stderr, "Key-Id: 0x%x\t%-30s [%5d bits] %c\n",
			id, get_name(type), 8 * size, TEE_OID(id) ? '*' : ' ');
	}

	free(list);

	return 0;
}

static int do_delete(unsigned char *nxp_id)
{
	uint8_t *list = malloc(4096);
	uint32_t *p = (uint32_t *)list;
	size_t length = 4096;
	uint32_t oid = 0;

	if (strncmp((char *)nxp_id, "all", strlen("all")))
		oid = strtoul((char *)nxp_id, NULL, 16);

	if (object_list(list, &length)) {
		free(list);
		return -EINVAL;
	}

	for (size_t i = 0; i < length / sizeof(uint32_t); i++, p++) {
		uint32_t id = bswap32(*p);

		/* Only objects created by the OP-TEE driver */
		if (!TEE_OID(id) || (oid && (oid != id)))
		    continue;

		fprintf(stderr, "Key-Id: 0x%x [%s]\n", id,
			object_delete(id) ?  "delete error" : "deleted");
	}

	free(list);

	return 0;
}

static const struct option options[] = {
	{
#define help_opt 0
		.name = "help",
		.has_arg = 0,
		.flag = NULL,
	},
	{
#define token_label_opt 1
		.name = "token-label",
		.has_arg = 1,
		.flag = NULL,
	},
	{
#define import_key_opt 2
		.name = "import-key",
		.has_arg = 1,
		.flag = NULL,
	},
	{
#define import_cert_opt 3
		.name = "import-cert",
		.has_arg = 1,
		.flag = NULL,
	},
	{
#define show_cert_opt 4
		.name = "show-cert",
		.has_arg = 1,
		.flag = NULL,
	},
	{
#define id_opt 5
		.name = "id",
		.has_arg = 1,
		.flag = NULL,
	},
	{
#define pin_opt 6
		.name = "pin",
		.has_arg = 1,
		.flag = NULL,
	},
	{
#define label_opt 7
		.name = "label",
		.has_arg = 1,
		.flag = NULL,
	},
	{
#define key_type_opt 8
		.name = "key-type",
		.has_arg = 1,
		.flag = NULL,
	},
	{
#define list_objects_opt 9
		.name = "list-objects",
		.has_arg = 0,
		.flag = NULL,
	},
	{
#define delete_objects_opt 10
		.name = "delete-objects",
		.has_arg = 1,
		.flag = NULL,
	},
	{
#define se050_opt 11
		.name = "se050",
		.has_arg = 0,
		.flag = NULL,
	},
	{
		.name = NULL,
	},
};

static void usage(void)
{
	fprintf(stderr, "This tool imports keys and certficates from the NXP "
			"SE050/1 into the OP-TEE PKCS#11 token\n");
	fprintf(stderr, "Use the --se050 optional flag if the device is not an SE051\n\n");

	fprintf(stderr, "Usage: with:\n");
	fprintf(stderr, "--help \t\tDisplay this menu\n\n");

	fprintf(stderr, "Import an RSA or an EC Key to the PKCS#11 OP-TEE token:\n"
		"\t--token-label <arg>\tThe PKCS#11 token to use\n"
		"\t--import-key <arg>\tThe Secure Element object identifier, i.e: 0xF0000000\n"
		"\t--pin <arg>\t\tUser PIN\n"
		"\t--id <arg>>\t\tID of the object\n"
		"\t--key-type <arg>\tType (RSA or ECC) and length of the key to create, for example rsa:1024 or EC:prime256v1\n"
		"\t[--se050]\t\tSet if the element is an SE050\n\n");

	fprintf(stderr, "Import a Certificate to the PKCS#11 OP-TEE token:\n"
		"\t--token-label <arg>\tThe PKCS#11 token to use\n"
		"\t--import-cert <arg>\tThe Secure Element object identifier, i.e: 0xF0000000\n"
		"\t--id <arg>\n"
		"\t--label <arg>\n "
		"\t[--se050]\n\n");

	fprintf(stderr, "Read a Certificate to the console:\n"
		"\t--show-cert <arg>\tThe Secure Element object identifier, i.e: 0xF0000000\n"
		"\t[--se050]\n\n");

	fprintf(stderr, "List all objects available in the Secure Element NVM:\n"
		"\t--list-objects\\n"
		"\t[--se050]\n\n");

	fprintf(stderr, "Delete OP-TEE created objects from the Secure Element NVM:\n"
		"\t--delete-objects <arg>\tEither an object identifier to delete a single element (i.e: 0xF0000000) or \"all\" (to delete all)\n"
		"\t[--se050]\n\n");


}

int main(int argc, char *argv[])
{
	unsigned char *label = NULL, *pin = NULL, *id = NULL, *nxp_id = NULL;
	unsigned char *token = NULL;
	unsigned char *key_type = NULL;
	bool do_delete_objects = false;
	bool do_list_objects = false;
	bool do_import_cert = false;
	bool do_import_key = false;
	bool do_show_cert = false;
	int lindex, opt;

	/* Initialize TLV size */
	TLV_SIZE_CMD = SE051_MAX_BUF_SIZE_CMD;

	/* Initialize the expected sizes*/
	BUF_SIZE_CMD = SE051_MAX_BUF_SIZE_CMD;
	BUF_SIZE_RSP = SE051_MAX_BUF_SIZE_CMD;

	for (;;) {
		lindex = -EINVAL;
		opt = getopt_long_only(argc, argv, "", options, &lindex);
		if (opt == EOF)
			break;

		switch (lindex) {
		case help_opt:
			usage();
			exit(0);
		case token_label_opt:
			token = (unsigned char *)optarg;
			break;
		case import_key_opt:
			do_import_key = true;
			nxp_id = (unsigned char *)optarg;
			break;
		case import_cert_opt:
			do_import_cert = true;
			nxp_id = (unsigned char *)optarg;
			break;
		case show_cert_opt:
			do_show_cert = true;
			nxp_id = (unsigned char *)optarg;
			break;
		case id_opt:
			id = (unsigned char *)optarg;
			break;
		case pin_opt:
			pin = (unsigned char *)optarg;
			break;
		case label_opt:
			label = (unsigned char *)optarg;
			break;
		case key_type_opt:
			key_type = (unsigned char *)optarg;
			break;
		case list_objects_opt:
			do_list_objects = true;
			break;
		case delete_objects_opt:
			do_delete_objects = true;
			nxp_id = (unsigned char *)optarg;
			break;
		case se050_opt:
			BUF_SIZE_CMD = SE050_MAX_BUF_SIZE_CMD;
			BUF_SIZE_RSP = SE050_MAX_BUF_SIZE_RSP;
			TLV_SIZE_CMD = SE050_MAX_BUF_SIZE_CMD;
			break;
		default:
			usage();
			exit(1);
		}
	}

	if (do_list_objects)
		return do_list();

	if (do_delete_objects)
		return do_delete(nxp_id);

	if ((do_import_cert && id && nxp_id && label && token) ||
	    (do_show_cert && nxp_id))
		return do_certificate(do_import_cert, do_show_cert, token,
				      strtoul((char *)nxp_id, NULL, 16),
				      id, label);

	if (do_import_key && id && pin && nxp_id && key_type && token)
		return do_key(token, nxp_id, id, pin, key_type);

	usage();

	exit(1);
}
