// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2022, Foundries.io Ltd.
 * Author: Jorge Ramirez-Ortiz <jorge@foundries.io>
 */
#define _GNU_SOURCE
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

	if (tlvGet_u16(SE05x_TAG_1, &rsp_idx, rsp, rsp_len, len)) {
		fprintf(stderr,"Error, cant get response\n");
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

static int object_rsa_get(uint32_t oid, uint16_t offset, uint16_t len,
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

	/* RSA key component module = 0x00 */
	if (tlvSet_u8(SE05x_TAG_4, &p, &cmd_len, 0x00))
		goto error;

	if (se_apdu_request(SE_APDU_CASE_4E,
			    hdr, sizeof(hdr),
			    cmd, cmd_len,
			    rsp, &rsp_len)) {
		fprintf(stderr, "Error, cant communicate with TEE core\n");
		goto error;
	}

	if (tlvGet_u8buf(SE05x_TAG_1, &rsp_idx, rsp, rsp_len, buf, buf_len)) {
		fprintf(stderr, ("Error, cant get the binary data\n"));
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

static void get_pkcs11_info(uint32_t oid, uint32_t type, uint16_t len,
			    unsigned char **label)
{
	struct fio_key_list *list = NULL;
	struct fio_key_info *info = NULL;
	struct fio_key_info *safe = NULL;
	char pad[4096] = { '\0' };
	unsigned char *buf = NULL;
	size_t der_offset = 0;
	size_t buf_len = 0;

	if (type == EC_KEY_PAIR) {
		/* EC point is retrieved in DER format, we need to skip tag */
		buf_len = 10 * len;
		der_offset = 2;
		list = &ec_list;
	}
	else if (type == RSA_KEY_PAIR) {
		buf_len = len;
		list = &rsa_list;
	}
	else
		return;

	if (LIST_EMPTY(list))
		return;

	buf = calloc(1, buf_len);
	if (!buf) {
		fprintf(stderr, "Error, not enough memory\n");
		return;
	}

	if (type == EC_KEY_PAIR) {
		if (object_get(oid, 0, 0, buf, &buf_len)) {
			fprintf(stderr, "Object 0x%x cant be retrieved\n", oid);
			free(buf);
			return;
		}
	} else {
		if (object_rsa_get(oid, 0, 0, buf, &buf_len)) {
			fprintf(stderr, "Object 0x%x cant be retrieved\n", oid);
			free(buf);
			return;
		}
	}

	/* Allow removing items for the list */
	LIST_FOREACH_SAFE(info, list, link, safe) {
		/*
		 * WARNING:
		 * Remove DER header info (might vary, 2 chosen empirically)
		 */
		if (!memcmp(&info->val[der_offset], buf, info->len)) {
			/* Push information */
			pkcs11_info2pad(pad, info);

			LIST_REMOVE(info, link);
			pkcs11_free_info(info);
			continue;
		}

		/* SE PKCS11 imported keys */
		if (!info->label || memcmp(info->label, "SE_", 3))
			continue;
		/*
		 * SE PKCS#11 imported keys must have SE_ in the label followed
		 * by the OID
		 */
		if (oid == strtoul((void *)(info->label) + 3, NULL, 16)) {
			/* Push information */
			pkcs11_info2pad(pad, info);

			LIST_REMOVE(info, link);
			pkcs11_free_info(info);
			continue;
		}
	}

	if (strlen(pad))
		asprintf((char **)label, "PKCS#11 (lbl,id): %s", pad);

	free(buf);
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

static int do_list(unsigned char *nxp_id, unsigned char *token_label,
		   unsigned char *pin)
{
	uint8_t *list = malloc(4096);
	size_t length = 4096;
	uint32_t type = 0;
	uint16_t size = 0;
	uint32_t *p = (uint32_t *)list;
	unsigned char *pkcs11_str = NULL;
	uint32_t oid = strtoul((char *)nxp_id, NULL, 16);

	if (!strncmp((char *)nxp_id, "all", strlen("all")))
		oid = 0;

	if (fio_pkcs11_create_key_list(token_label, pin)) {
		fprintf(stderr, "Cant create the pkcs11 EC/RSA list\n");
		return -EINVAL;
	}

	if (object_list(list, &length)) {
		fprintf(stderr, "Cant create the SE05X list\n");
		free(list);
		return -EINVAL;
	}

	for (size_t i = 0; i < length / sizeof(uint32_t); i++, p++) {
		uint32_t id = bswap32(*p);
		pkcs11_str = NULL;
		size = 0;

		if (oid && (oid != id))
			continue;

		if (object_type(id, &type, NULL))
			continue;

		if ((type != UserID) && object_size(id, &size))
			continue;

		if (pkcs11_info_available())
			get_pkcs11_info(id, type, size, &pkcs11_str);

		fprintf(stderr, "Key-Id: 0x%x\t%-20s [%5d bits] %c %s\n",
			id, get_name(type), 8 * size,
			TEE_OID(id) ? '*' : ' ',
			pkcs11_str ? pkcs11_str : (unsigned char *)" ");

		free(pkcs11_str);
	}

	free(list);

	return 0;
}

static int do_delete(unsigned char *nxp_id)
{
	uint8_t *list = malloc(4096);
	uint32_t *p = (uint32_t *)list;
	size_t length = 4096;
	bool reset = false;
	bool all = false;
	uint32_t oid = 0;
	int err = 0;
	int cnt = 0;

	/* Factory reset */
	reset = !!!strncmp((char *)nxp_id, "reset", strlen("reset"));

	if (reset)
		goto init;

	/* Every TEE created objects */
	all = !!!strncmp((char *)nxp_id, "all", strlen("all"));
	if (all)
		goto init;

	/* One TEE created object*/
	oid = strtoul((char *)nxp_id, NULL, 16);

	if (TEE_OID(oid))
		goto init;

	fprintf(stderr, "Invalid object 0x%x, not in TEE range\n", oid);
	return -EINVAL;

init:
	if (object_list(list, &length)) {
		free(list);
		return -EINVAL;
	}

	if (reset)
		fprintf(stderr, "NXP SE05X Secure Element Factory Reset\n");

	for (size_t i = 0; i < length / sizeof(uint32_t); i++, p++) {
		uint32_t id = bswap32(*p);

		/* Everything must go */
		if (reset)
			goto delete;

		/*
		 * Delete objects _only_ created by the OP-TEE crypto
		 * driver.
		 *
		 * APDU PTA created objects (i.e. EL2G service) will not
		 * be deleted without a --factory-reset
		 */
		if (all) {
			if (TEE_OID(id))
				goto delete;

			continue;
		}

		/* OID specified in command line */
		if (oid != id)
			continue;
delete:
		/* Plug-and-Trust stack prevents these objects from deletion */
		if (se05x_oid_reserved(id))
			continue;

		err = object_delete(id);
		if (!err)
			cnt++;

		fprintf(stderr, "Key-Id: 0x%x [%s] %s\n", id,
			err ? (TEE_OID(id) ?  "delete error" : "persistent") :
			 "deleted",
			/* We should not fail deleting a TEE created object */
			err && TEE_OID(id) ? "WARNING, OID in TEE range" : "");
	}

	if (reset || all)  {
		fprintf(stderr, "\nRemoved %d objects\n", cnt);
	} else {
		/* Single object */
		if (cnt)
			fprintf(stderr, "\nObject Removed\n");
		else if (!err)
			fprintf(stderr, "\nObject %s, (oid 0x%x) not found\n",
				nxp_id, oid);
		else
			fprintf(stderr, "\nObject %s can't be removed\n",
				nxp_id);
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
		.has_arg = 1,
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
#define factory_reset_opt 12
		.name = "factory-reset",
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

	fprintf(stderr, "List all objects available in the Secure Element NVM and show their association with PKCS11 (optional):\n"
		"\t--list-objects <arg>\tEither an object identifier (i.e 0x50121331) or \"all\" to list all the objects\n"
		"\t[--token-label <arg>]\tThe PKCS#11 token to use (optional)\n"
		"\t[--pin <arg>]\t\tUser PIN (optional)\n"
		"\t[--se050]\n\n");

	fprintf(stderr, "Delete OP-TEE created objects from the Secure Element NVM:\n"
		"\t--delete-objects <arg>\tEither an object identifier to delete a single element (i.e: 0xF0000000) or \"all\" (to delete all)\n"
		"\t[--se050]\n\n");

	fprintf(stderr, "Reset the Secure Element to its Factory Settings. \n"
		"\t--factory-reset \tThis option will delete OPTEE and EL2G created keys and certificates\n"
		"\t[--se050]\n\n");


}

int main(int argc, char *argv[])
{
	unsigned char *label = NULL, *pin = NULL, *id = NULL, *nxp_id = NULL;
	unsigned char *token = NULL;
	unsigned char *key_type = NULL;
	bool do_delete_objects = false;
	bool do_factory_reset = false;
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
			nxp_id = (unsigned char *)optarg;
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
		case factory_reset_opt:
			do_factory_reset = true;
			nxp_id = (unsigned char *)"reset";
			break;
		default:
			usage();
			exit(1);
		}
	}

	if (do_list_objects)
		return do_list(nxp_id, token, pin);

	if (do_delete_objects || do_factory_reset)
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
