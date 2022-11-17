// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2022, Foundries.io Ltd.
 * Author: Jorge Ramirez-Ortiz <jorge@foundries.io>
 */
#include <pkcs11.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fio_pkcs11.h"
#include "fio_util.h"
#include "fio_ssl.h"

#define PKCS11_OPTEE_MANUFACTURER "Linaro"
#define OPTEE_STR "OP-TEE"

#define CKM_EC_EDWARDS_KEY_PAIR_GEN		(0x1055UL)
#define CKM_EC_MONTGOMERY_KEY_PAIR_GEN		(0x1056UL)
#define CKK_EC_EDWARDS				(0x40UL)
#define CKK_EC_MONTGOMERY			(0x41UL)

#define FILL_ATTR(attr, typ, val, len) \
	{ (attr).type = (typ); (attr).pValue = (val); (attr).ulValueLen = len; }

static const struct ec_curve_info {
	const char *name;
	const char *oid;
	const char *params;
	size_t size;
	CK_KEY_TYPE mechanism;
} ec_curve[] = {
	{ "secp192r1", "1.2.840.10045.3.1.1", "06082A8648CE3D030101", 192, 0 },
	{ "prime192v1", "1.2.840.10045.3.1.1", "06082A8648CE3D030101", 192, 0 },
	{ "prime192v2", "1.2.840.10045.3.1.2", "06082A8648CE3D030102", 192, 0 },
	{ "prime192v3", "1.2.840.10045.3.1.3", "06082A8648CE3D030103", 192, 0 },
	{ "nistp192", "1.2.840.10045.3.1.1", "06082A8648CE3D030101", 192, 0 },
	{ "ansiX9p192r1", "1.2.840.10045.3.1.1", "06082A8648CE3D030101", 192, 0 },

	{ "secp224r1", "1.3.132.0.33", "06052b81040021", 224, 0 },
	{ "nistp224",  "1.3.132.0.33", "06052b81040021", 224, 0 },

	{ "prime256v1", "1.2.840.10045.3.1.7", "06082A8648CE3D030107", 256, 0 },
	{ "secp256r1", "1.2.840.10045.3.1.7", "06082A8648CE3D030107", 256, 0 },
	{ "ansiX9p256r1", "1.2.840.10045.3.1.7", "06082A8648CE3D030107", 256, 0 },
	{ "frp256v1", "1.2.250.1.223.101.256.1", "060a2a817a01815f65820001", 256, 0 },

	{ "secp384r1", "1.3.132.0.34", "06052B81040022", 384, 0 },
	{ "prime384v1", "1.3.132.0.34", "06052B81040022", 384, 0 },
	{ "ansiX9p384r1", "1.3.132.0.34", "06052B81040022", 384, 0 },

	{ "prime521v1", "1.3.132.0.35", "06052B81040023", 521, 0 },
	{ "secp521r1", "1.3.132.0.35", "06052B81040023", 521, 0 },
	{ "nistp521", "1.3.132.0.35", "06052B81040023", 521, 0 },

	{ "brainpoolP192r1", "1.3.36.3.3.2.8.1.1.3", "06092B2403030208010103", 192, 0 },
	{ "brainpoolP224r1", "1.3.36.3.3.2.8.1.1.5", "06092B2403030208010105", 224, 0 },
	{ "brainpoolP256r1", "1.3.36.3.3.2.8.1.1.7", "06092B2403030208010107", 256, 0 },
	{ "brainpoolP320r1", "1.3.36.3.3.2.8.1.1.9", "06092B2403030208010109", 320, 0 },
	{ "brainpoolP384r1", "1.3.36.3.3.2.8.1.1.11", "06092B240303020801010B", 384, 0 },
	{ "brainpoolP512r1", "1.3.36.3.3.2.8.1.1.13", "06092B240303020801010D", 512, 0 },

	{ "secp192k1", "1.3.132.0.31", "06052B8104001F", 192, 0 },
	{ "secp256k1", "1.3.132.0.10", "06052B8104000A", 256, 0 },
	{ "secp521k1", "1.3.132.0.35", "06052B81040023", 521, 0 },

	{ "edwards25519", "1.3.6.1.4.1159.15.1", "130c656477617264733235353139", 255,
		CKM_EC_EDWARDS_KEY_PAIR_GEN },
	{ "curve25519", "1.3.6.1.4.3029.1.5.1", "130b63757276653235353139", 255,
		CKM_EC_MONTGOMERY_KEY_PAIR_GEN },

	{ NULL, NULL, NULL, 0, 0 },
};

static const char* p11_utf8_to_local(CK_UTF8CHAR *string, size_t len)
{
	static char buffer[512];
	size_t n, m;

	while (len && string[len - 1] == ' ')
		len--;

	for (n = m = 0; n < sizeof(buffer) - 1; n++) {
		if (m >= len)
			break;

		buffer[n] = string[m++];
	}

	buffer[n] = '\0';

	return buffer;
}

static int get_optee_slot(CK_SLOT_ID *slot, unsigned char *token_label)
{
	CK_TOKEN_INFO token_info = { };
	CK_SLOT_INFO slot_info = { };
	CK_SLOT_ID_PTR slots = NULL;
	CK_ULONG count = 0;
	size_t i = 0;
	const char *p = NULL;

	if (!slot)
		return CKR_GENERAL_ERROR;

	if (C_Initialize(0))
		return -1;

	if (C_GetSlotList(CK_TRUE, NULL, &count) || count < 1)
		goto error;

	slots = malloc(count * sizeof(CK_SLOT_ID));
	if (!slots)
		goto error;

	if (C_GetSlotList(CK_TRUE, slots, &count))
		goto error;

	for (i = 0; i < count; i++) {
		*slot = slots[i];

		if (C_GetSlotInfo(*slot, &slot_info))
			goto error;

		if (!strstr((const char *)slot_info.slotDescription,
			   PKCS11_OPTEE_MANUFACTURER))
			continue;

		if (C_GetTokenInfo(*slot, &token_info))
			goto error;

		p = p11_utf8_to_local(token_info.label,
				      sizeof(token_info.label));

		if (strncmp(p, (const char *)token_label, strlen(p)))
			continue;

		if (strstr((const char *)token_info.model, OPTEE_STR))
			break;
	}

	if (i < count) {
		free(slots);
		return 0;
	}
error:
	if (slots)
		free(slots);

	C_Finalize(0);

	return -1;
}

static int put_optee_slot(void)
{
	return C_Finalize(0) ? -1 : 0;
}

int fio_pkcs11_import_cert(unsigned char *token_label, unsigned char *id,
			   unsigned char *label, unsigned char *der,
			   size_t der_len)
{
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS cert_class = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE cert_type = CKC_X_509;
	CK_ATTRIBUTE cert_templ[10] = { };
	CK_OBJECT_HANDLE cert_obj = 0;
	CK_BBOOL false_val = 0;
	CK_BBOOL true_val = 1;
	CK_BYTE oid[20] = { };
	CK_SLOT_ID slot = 0;
	struct fio_cert_info cert = { };
	size_t oid_len = sizeof(oid);
	size_t nbr_attr = 0;
	int ret = 0;

	if (get_optee_slot(&slot, token_label))
		return -1;

	if (C_OpenSession(slot, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, 0,
			  &session)) {
		ret = -1;
		goto out;
	}

	if (fio_util_hex2bin((const unsigned char*)id, oid, &oid_len)) {
		ret = -1;
		goto out;
	}

	/* Prepare the certificate template */
	FILL_ATTR(cert_templ[nbr_attr], CKA_TOKEN,
		  &true_val, sizeof(true_val));
	nbr_attr++;
	FILL_ATTR(cert_templ[nbr_attr], CKA_VALUE,
		  der, der_len);
	nbr_attr++;
	FILL_ATTR(cert_templ[nbr_attr], CKA_CLASS,
		  &cert_class, sizeof(cert_class));
	nbr_attr++;
	FILL_ATTR(cert_templ[nbr_attr], CKA_CERTIFICATE_TYPE,
		  &cert_type, sizeof(cert_type));
	nbr_attr++;
	FILL_ATTR(cert_templ[nbr_attr], CKA_PRIVATE,
		  &false_val, sizeof(false_val));
	nbr_attr++;
	FILL_ATTR(cert_templ[nbr_attr], CKA_LABEL,
		  label, strlen((const char *)label));
	nbr_attr++;
	FILL_ATTR(cert_templ[nbr_attr], CKA_ID,
		  oid, oid_len);
	nbr_attr++;
	FILL_ATTR(cert_templ[nbr_attr], CKA_SUBJECT,
		  cert.subject.data, cert.subject.len);
	nbr_attr++;
	FILL_ATTR(cert_templ[nbr_attr], CKA_ISSUER,
		  cert.issuer.data, cert.issuer.len);
	nbr_attr++;
	FILL_ATTR(cert_templ[nbr_attr], CKA_SERIAL_NUMBER,
		  cert.serial.data, cert.serial.len);
	nbr_attr++;

	if (C_CreateObject(session, cert_templ, nbr_attr, &cert_obj)) {
		ret = -1;
		goto out;
	}

out:
	if (session && C_CloseSession(session))
		ret = -1;

	if (put_optee_slot())
		ret = -1;

	return ret;
}

int fio_pkcs11_import_key(unsigned char *token_label, unsigned char *nxp_id,
			  unsigned char *id, unsigned char *pin,
			  unsigned char *key_type)
{
	CK_MECHANISM rsa_mechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
	CK_MECHANISM ecc_mechanism = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS priv_class = CKO_PRIVATE_KEY;
	CK_OBJECT_CLASS pub_class = CKO_PUBLIC_KEY;
	CK_BYTE pub_exp[] = { 0x01, 0x00, 0x01 };
	CK_OBJECT_HANDLE pub_key, priv_key;
	CK_MECHANISM_PTR mechanism = NULL;
	CK_ULONG mod_bits = 1024;
	CK_BBOOL true_val = 1;
	CK_SLOT_ID slot = 0;
	CK_ATTRIBUTE pub_templ[20] = {
		{ CKA_CLASS, &pub_class, sizeof(pub_class) },
		{ CKA_TOKEN, &true_val, sizeof(true_val) },
	};
	int nbr_pub_attr = 2;
	CK_ATTRIBUTE priv_templ[20] = {
		{ CKA_CLASS, &priv_class, sizeof(priv_class) },
		{ CKA_TOKEN, &true_val, sizeof(true_val) },
		{ CKA_PRIVATE, &true_val, sizeof(true_val) },
		{ CKA_SENSITIVE, &true_val, sizeof(true_val) },
	};
	int nbr_priv_attr = 4;
	CK_ULONG type = CKK_RSA;
	CK_BYTE ec_params[100] = { };
	size_t ec_params_len = 100;
	CK_BYTE oid[20] = { };
	size_t oid_len = 20;
	char key_name[20] = { };
	char *str = "SE_%s";
	int ret = 0;

	/* skip the mandatory "0x" in the string */
	sprintf(key_name, str, nxp_id + 2);

	if (get_optee_slot(&slot, token_label))
		return -1;

	if (C_OpenSession(slot, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, 0,
			  &session)) {
		ret = -1;
		goto out;
	}

	if (!strncmp((const char *)key_type, "RSA:", strlen("RSA:")) ||
	    !strncmp((const char *)key_type, "rsa:", strlen("rsa:"))) {
		CK_ULONG len = atol((const char *)key_type + strlen("RSA:"));
		type = CKK_RSA;
		if (len != 0)
			mod_bits = len;

		mechanism = &rsa_mechanism;

		FILL_ATTR(pub_templ[nbr_pub_attr], CKA_MODULUS_BITS,
			  &mod_bits, sizeof(mod_bits));
		nbr_pub_attr++;
		FILL_ATTR(pub_templ[nbr_pub_attr], CKA_PUBLIC_EXPONENT,
			  pub_exp, sizeof(pub_exp));
		nbr_pub_attr++;
		FILL_ATTR(pub_templ[nbr_pub_attr], CKA_VERIFY,
			  &true_val, sizeof(true_val));
		nbr_pub_attr++;
		FILL_ATTR(priv_templ[nbr_priv_attr], CKA_SIGN,
			  &true_val, sizeof(true_val));
		nbr_priv_attr++;
		FILL_ATTR(pub_templ[nbr_pub_attr], CKA_ENCRYPT,
			  &true_val, sizeof(true_val));
		nbr_pub_attr++;
		FILL_ATTR(priv_templ[nbr_priv_attr], CKA_DECRYPT,
			  &true_val, sizeof(true_val));
		nbr_priv_attr++;
		FILL_ATTR(pub_templ[nbr_pub_attr], CKA_KEY_TYPE,
			  &type, sizeof(type));
		nbr_pub_attr++;
		FILL_ATTR(priv_templ[nbr_priv_attr], CKA_KEY_TYPE,
			  &type, sizeof(type));
		nbr_priv_attr++;

	} else if (!strncmp((const char *)key_type, "EC:", strlen("EC:")) ||
		   !strncmp((const char *)key_type, "ec:", strlen("ec:"))) {
		size_t i = 0;

		mechanism = &ecc_mechanism;

		for (i = 0; ec_curve[i].name; i++)   {
			if (!strcmp(ec_curve[i].name,
				    (const char *)key_type + 3))
				break;
			if (!strcmp(ec_curve[i].oid,
				    (const char *)key_type + 3))
				break;
		}

		if (!ec_curve[i].name) {
			ret = -1;
			goto out;
		}

		if (!strcmp((const char *)(key_type + 3), "edwards25519"))
			type = CKK_EC_EDWARDS;
		else if (!strcmp((const char *)key_type + 3, "curve25519"))
			type = CKK_EC_MONTGOMERY;
		else
			type = CKK_EC;

		ec_params_len = strlen((const char *)ec_curve[i].params) / 2;
		if (fio_util_hex2bin((const unsigned char *)ec_curve[i].params,
				     ec_params, &ec_params_len)) {
			ret = -1;
			goto out;
		}

		FILL_ATTR(pub_templ[nbr_pub_attr], CKA_VERIFY,
			  &true_val, sizeof(true_val));
		nbr_pub_attr++;
		FILL_ATTR(priv_templ[nbr_priv_attr], CKA_SIGN,
			  &true_val, sizeof(true_val));
		nbr_priv_attr++;
		FILL_ATTR(pub_templ[nbr_pub_attr], CKA_DERIVE,
			  &true_val, sizeof(true_val));
		nbr_pub_attr++;
		FILL_ATTR(priv_templ[nbr_priv_attr], CKA_DERIVE,
			  &true_val, sizeof(true_val));
		nbr_priv_attr++;
		FILL_ATTR(pub_templ[nbr_pub_attr], CKA_EC_PARAMS,
			  ec_params, ec_params_len);
		nbr_pub_attr++;
		FILL_ATTR(pub_templ[nbr_pub_attr], CKA_KEY_TYPE,
			  &type, sizeof(type));
		nbr_pub_attr++;
		FILL_ATTR(priv_templ[nbr_priv_attr], CKA_KEY_TYPE,
			  &type, sizeof(type));
		nbr_priv_attr++;

	} else {
		ret = -1;
		goto out;
	}

	FILL_ATTR(pub_templ[nbr_pub_attr], CKA_LABEL,
		  key_name, strlen((const char *)key_name));
	nbr_pub_attr++;
	FILL_ATTR(priv_templ[nbr_priv_attr], CKA_LABEL,
		  key_name, strlen((const char *)key_name));
	nbr_priv_attr++;

	if (fio_util_hex2bin(id, oid, &oid_len)) {
		ret = -1;
		goto out;
	}

	FILL_ATTR(pub_templ[nbr_pub_attr], CKA_ID,
		  oid, oid_len);
	nbr_pub_attr++;
	FILL_ATTR(priv_templ[nbr_priv_attr], CKA_ID,
		  oid, oid_len);
	nbr_priv_attr++;

	if (C_Login(session, CKU_USER, pin, strlen((const char *)pin))) {
		ret = -1;
		goto out;
	}

	if (C_GenerateKeyPair(session, mechanism,
			      pub_templ, nbr_pub_attr,
			      priv_templ, nbr_priv_attr,
			      &pub_key, &priv_key))
		ret = -1;
out:
	if (session && C_CloseSession(session))
		ret = -1;

	if (put_optee_slot())
		ret = -1;

	return ret;
}
