// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2022, Foundries.io Ltd.
 * Author: Jorge Ramirez-Ortiz <jorge@foundries.io>
 */
#ifndef SE05X_H
#define SE05X_H

/* Plug and Trust does not delete these objects during factory reset */
#define SE05X_OBJID_TP_MASK(_x)			(0xFFFFFFFCu & (_x))
#define SE05X_OBJID_SE05X_APPLET_RES_START      (0x7FFF0000u)
#define SE05X_OBJID_SE05X_APPLET_RES_MASK(_x)	(0xFFFF0000u & (_x))
#define EX_SSS_OBJID_DEMO_AUTH_START            (0x7DA00000u)
#define EX_SSS_OBJID_DEMO_AUTH_MASK(_x)		(0xFFFF0000u & (_x))
#define EX_SSS_OBJID_IOT_HUB_A_START            (0xF0000000u)
#define EX_SSS_OBJID_IOT_HUB_A_MASK(_x)		(0xF0000000u & (_x))

/* The Unique ID object */
#define SE05X_UNIQUE_ID				0x7FFF0206
#define SE050_UNIQUE_ID_LEN			18

/* OP-TEE: range of values created by the OP-TEE driver */
#define TEE_OID_MIN	((uint32_t)(0x00000001))
#define TEE_OID_MAX	((uint32_t)(TEE_OID_MIN + 0x7BFFFFFE))
#define TEE_OID(x)	(bool)(((x) >= TEE_OID_MIN) && ((x) <= TEE_OID_MAX))

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))
#define STRX(x) #x
#define STR(x) STRX(x)

#define SE050_MAX_BUF_SIZE_CMD (892)
#define SE050_MAX_BUF_SIZE_RSP (892)
#define SE051_MAX_BUF_SIZE_CMD (1024)
#define SE051_MAX_BUF_SIZE_RSP (1024)

enum se05x_oid_type {
	NA = 0x00,
	EC_KEY_PAIR = 0x01,
	EC_PRIV_KEY = 0x02,
	EC_PUB_KEY = 0x03,
	RSA_KEY_PAIR = 0x04,
	RSA_KEY_PAIR_CRT = 0x05,
	RSA_PRIV_KEY = 0x06,
	RSA_PRIV_KEY_CRT = 0x07,
	RSA_PUB_KEY = 0x08,
	AES_KEY = 0x09,
	DES_KEY = 0x0A,
	BINARY_FILE = 0x0B,
	UserID = 0x0C,
	COUNTER = 0x0D,
	PCR = 0x0F,
	CURVE = 0x10,
	HMAC_KEY = 0x11,
	EC_KEY_PAIR_NIST_P192 = 0x21,
	EC_PRIV_KEY_NIST_P192 = 0x22,
	EC_PUB_KEY_NIST_P192 = 0x23,
	EC_KEY_PAIR_NIST_P224 = 0x25,
	EC_PRIV_KEY_NIST_P224 = 0x26,
	EC_PUB_KEY_NIST_P224 = 0x27,
	EC_KEY_PAIR_NIST_P256 = 0x29,
	EC_PRIV_KEY_NIST_P256 = 0x2A,
	EC_PUB_KEY_NIST_P256 = 0x2B,
	EC_KEY_PAIR_NIST_P384 = 0x2D,
	EC_PRIV_KEY_NIST_P384 = 0x2E,
	EC_PUB_KEY_NIST_P384 = 0x2F,
	EC_KEY_PAIR_NIST_P521 = 0x31,
	EC_PRIV_KEY_NIST_P521 = 0x32,
	EC_PUB_KEY_NIST_P521 = 0x33,
	EC_KEY_PAIR_Brainpool160 = 0x35,
	EC_PRIV_KEY_Brainpool160 = 0x36,
	EC_PUB_KEY_Brainpool160 = 0x37,
	EC_KEY_PAIR_Brainpool192 = 0x39,
	EC_PRIV_KEY_Brainpool192 = 0x3A,
	EC_PUB_KEY_Brainpool192 = 0x3B,
	EC_KEY_PAIR_Brainpool224 = 0x3D,
	EC_PRIV_KEY_Brainpool224 = 0x3E,
	EC_PUB_KEY_Brainpool224 = 0x3F,
	EC_KEY_PAIR_Brainpool256 = 0x41,
	EC_PRIV_KEY_Brainpool256 = 0x42,
	EC_PUB_KEY_Brainpool256 = 0x43,
	EC_KEY_PAIR_Brainpool320 = 0x45,
	EC_PRIV_KEY_Brainpool320 = 0x46,
	EC_PUB_KEY_Brainpool320 = 0x47,
	EC_KEY_PAIR_Brainpool384 = 0x49,
	EC_PRIV_KEY_Brainpool384 = 0x4A,
	EC_PUB_KEY_Brainpool384 = 0x4B,
	EC_KEY_PAIR_Brainpool512 = 0x4D,
	EC_PRIV_KEY_Brainpool512 = 0x4E,
	EC_PUB_KEY_Brainpool512 = 0x4F,
	EC_KEY_PAIR_Secp160k1 = 0x51,
	EC_PRIV_KEY_Secp160k1 = 0x52,
	EC_PUB_KEY_Secp160k1 = 0x53,
	EC_KEY_PAIR_Secp192k1 = 0x55,
	EC_PRIV_KEY_Secp192k1 = 0x56,
	EC_PUB_KEY_Secp192k1 = 0x57,
	EC_KEY_PAIR_Secp224k1 = 0x59,
	EC_PRIV_KEY_Secp224k1 = 0x5A,
	EC_PUB_KEY_Secp224k1 = 0x5B,
	EC_KEY_PAIR_Secp256k1 = 0x5D,
	EC_PRIV_KEY_Secp256k1 = 0x5E,
	EC_PUB_KEY_Secp256k1 = 0x5F,
	EC_KEY_PAIR_BN_P256 = 0x61,
	EC_PRIV_KEY_BN_P256 = 0x62,
	EC_PUB_KEY_BN_P256 = 0x63,
	EC_KEY_PAIR_ED25519 = 0x65,
	EC_PRIV_KEY_ED25519 = 0x66,
	EC_PUB_KEY_ED25519 = 0x67,
	EC_KEY_PAIR_MONT_DH_25519 = 0x69,
	EC_PRIV_KEY_MONT_DH_25519 = 0x6A,
	EC_PUB_KEY_MONT_DH_25519 = 0x6B,
	EC_KEY_PAIR_MONT_DH_448 = 0x71,
	EC_PRIV_KEY_MONT_DH_448 = 0x72,
	EC_PUB_KEY_MONT_DH_448 = 0x73,
};

static inline char* get_name(enum se05x_oid_type type)
{
	#define OID_TYPE(__x) { .type = __x, .name = STR(__x) }
	struct {
		char *name;
		enum se05x_oid_type type;
	} list[] = {
		OID_TYPE(NA),
		OID_TYPE(EC_KEY_PAIR),
		OID_TYPE(EC_PRIV_KEY),
		OID_TYPE(EC_PUB_KEY),
		OID_TYPE(RSA_KEY_PAIR),
		OID_TYPE(RSA_KEY_PAIR_CRT),
		OID_TYPE(RSA_PRIV_KEY),
		OID_TYPE(RSA_PRIV_KEY_CRT),
		OID_TYPE(RSA_PUB_KEY),
		OID_TYPE(AES_KEY),
		OID_TYPE(DES_KEY),
		OID_TYPE(BINARY_FILE),
		OID_TYPE(UserID),
		OID_TYPE(COUNTER),
		OID_TYPE(PCR),
		OID_TYPE(CURVE),
		OID_TYPE(HMAC_KEY),
		OID_TYPE(EC_KEY_PAIR_NIST_P192),
		OID_TYPE(EC_PRIV_KEY_NIST_P192),
		OID_TYPE(EC_PUB_KEY_NIST_P192),
		OID_TYPE(EC_KEY_PAIR_NIST_P224),
		OID_TYPE(EC_PRIV_KEY_NIST_P224),
		OID_TYPE(EC_PUB_KEY_NIST_P224),
		OID_TYPE(EC_KEY_PAIR_NIST_P256),
		OID_TYPE(EC_PRIV_KEY_NIST_P256),
		OID_TYPE(EC_PUB_KEY_NIST_P256),
		OID_TYPE(EC_KEY_PAIR_NIST_P384),
		OID_TYPE(EC_PRIV_KEY_NIST_P384),
		OID_TYPE(EC_PUB_KEY_NIST_P384),
		OID_TYPE(EC_KEY_PAIR_NIST_P521),
		OID_TYPE(EC_PRIV_KEY_NIST_P521),
		OID_TYPE(EC_PUB_KEY_NIST_P521),
		OID_TYPE(EC_KEY_PAIR_Brainpool160),
		OID_TYPE(EC_PRIV_KEY_Brainpool160),
		OID_TYPE(EC_PUB_KEY_Brainpool160),
		OID_TYPE(EC_KEY_PAIR_Brainpool192),
		OID_TYPE(EC_PRIV_KEY_Brainpool192),
		OID_TYPE(EC_PUB_KEY_Brainpool192),
		OID_TYPE(EC_KEY_PAIR_Brainpool224),
		OID_TYPE(EC_PRIV_KEY_Brainpool224),
		OID_TYPE(EC_PUB_KEY_Brainpool224),
		OID_TYPE(EC_KEY_PAIR_Brainpool256),
		OID_TYPE(EC_PRIV_KEY_Brainpool256),
		OID_TYPE(EC_PUB_KEY_Brainpool256),
		OID_TYPE(EC_KEY_PAIR_Brainpool320),
		OID_TYPE(EC_PRIV_KEY_Brainpool320),
		OID_TYPE(EC_PUB_KEY_Brainpool320),
		OID_TYPE(EC_KEY_PAIR_Brainpool384),
		OID_TYPE(EC_PRIV_KEY_Brainpool384),
		OID_TYPE(EC_PUB_KEY_Brainpool384),
		OID_TYPE(EC_KEY_PAIR_Brainpool512),
		OID_TYPE(EC_PRIV_KEY_Brainpool512),
		OID_TYPE(EC_PUB_KEY_Brainpool512),
		OID_TYPE(EC_KEY_PAIR_Secp160k1),
		OID_TYPE(EC_PRIV_KEY_Secp160k1),
		OID_TYPE(EC_PUB_KEY_Secp160k1),
		OID_TYPE(EC_KEY_PAIR_Secp192k1),
		OID_TYPE(EC_PRIV_KEY_Secp192k1),
		OID_TYPE(EC_PUB_KEY_Secp192k1),
		OID_TYPE(EC_KEY_PAIR_Secp224k1),
		OID_TYPE(EC_PRIV_KEY_Secp224k1),
		OID_TYPE(EC_PUB_KEY_Secp224k1),
		OID_TYPE(EC_KEY_PAIR_Secp256k1),
		OID_TYPE(EC_PRIV_KEY_Secp256k1),
		OID_TYPE(EC_PUB_KEY_Secp256k1),
		OID_TYPE(EC_KEY_PAIR_BN_P256),
		OID_TYPE(EC_PRIV_KEY_BN_P256),
		OID_TYPE(EC_PUB_KEY_BN_P256),
		OID_TYPE(EC_KEY_PAIR_ED25519),
		OID_TYPE(EC_PRIV_KEY_ED25519),
		OID_TYPE(EC_PUB_KEY_ED25519),
		OID_TYPE(EC_KEY_PAIR_MONT_DH_25519),
		OID_TYPE(EC_PRIV_KEY_MONT_DH_25519),
		OID_TYPE(EC_PUB_KEY_MONT_DH_25519),
		OID_TYPE(EC_KEY_PAIR_MONT_DH_448),
		OID_TYPE(EC_PRIV_KEY_MONT_DH_448),
		OID_TYPE(EC_PUB_KEY_MONT_DH_448),
	};

	for (size_t i = 0; i < ARRAY_SIZE(list); i++) {
		if (list[i].type == type)
			return list[i].name;
	}

	return "Invalid";
}

/* The Plug and Trust stack does not allow these objects to be deleted */
static inline bool se05x_oid_reserved(uint32_t oid)
{
	if (SE05X_OBJID_SE05X_APPLET_RES_START ==
	    SE05X_OBJID_SE05X_APPLET_RES_MASK(oid)) {
		fprintf(stderr, "Not erasing 0x%08x (Reserved)\n", oid);
		return true;
	}

	if (EX_SSS_OBJID_DEMO_AUTH_START == EX_SSS_OBJID_DEMO_AUTH_MASK(oid)) {
		fprintf(stderr, "Not erasing 0x%08x (Demo Auth)\n", oid);
		return true;
	}

	if (EX_SSS_OBJID_IOT_HUB_A_START == EX_SSS_OBJID_IOT_HUB_A_MASK(oid)) {
		fprintf(stderr, "Not erasing 0x%08x (IoT Hub)\n", oid);
		return true;
	}

	if (!SE05X_OBJID_TP_MASK(oid) && oid) {
		fprintf(stderr, "Not erasing Trust Provisioned objects"
			"0x%08x\n", oid);
		return true;
	}

	return false;
}

enum se05x_tag {
	SE05x_TAG_NA = 0,
	SE05x_TAG_SESSION_ID = 0x10,
	SE05x_TAG_POLICY = 0x11,
	SE05x_TAG_MAX_ATTEMPTS = 0x12,
	SE05x_TAG_IMPORT_AUTH_DATA = 0x13,
	SE05x_TAG_IMPORT_AUTH_KEY_ID = 0x14,
	SE05x_TAG_POLICY_CHECK = 0x15,
	SE05x_TAG_1 = 0x41,
	SE05x_TAG_2 = 0x42,
	SE05x_TAG_3 = 0x43,
	SE05x_TAG_4 = 0x44,
	SE05x_TAG_5 = 0x45,
	SE05x_TAG_6 = 0x46,
	SE05x_TAG_7 = 0x47,
	SE05x_TAG_8 = 0x48,
	SE05x_TAG_9 = 0x49,
	SE05x_TAG_10 = 0x4A,
	SE05x_TAG_11 = 0x4B,
	SE05x_GP_TAG_CONTRL_REF_PARM = 0xA6,
	SE05x_GP_TAG_AID = 0x4F,
	SE05x_GP_TAG_KEY_TYPE = 0x80,
	SE05x_GP_TAG_KEY_LEN = 0x81,
	SE05x_GP_TAG_GET_DATA = 0x83,
	SE05x_GP_TAG_DR_SE = 0x85,
	SE05x_GP_TAG_RECEIPT = 0x86,
	SE05x_GP_TAG_SCP_PARMS = 0x90,
};

enum se05x_status {
	SE05x_NOT_OK = 0xFFFF,
	SE05x_OK = 0x9000,
};

enum se05x_result {
	kSE05x_Result_NA = 0,
	kSE05x_Result_SUCCESS = 0x01,
	kSE05x_Result_FAILURE = 0x02,
};

#define SE05X_OBJ_TYPE_HEADER  { 0x80, 0x02, 0x00, 0x26, }
#define SE05X_OBJ_GET_HEADER   { 0x80, 0x02, 0x00, 0x00, }
#define SE05X_OBJ_SIZE_HEADER  { 0x80, 0x02, 0x00, 0x07, }
#define SE05X_OBJ_EXIST_HEADER { 0x80, 0x04, 0x00, 0x27, }
#define SE05X_OBJ_GET_LIST     { 0x80, 0x02, 0x00, 0x25, }
#define SE05X_OBJ_DEL_HEADER   { 0x80, 0x04, 0x00, 0x28, }

#endif
