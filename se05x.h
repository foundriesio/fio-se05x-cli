// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2022, Foundries.io Ltd.
 * Author: Jorge Ramirez-Ortiz <jorge@foundries.io>
 */
#ifndef SE05X_H
#define SE05X_H

#define SE050_MAX_BUF_SIZE_CMD (892)
#define SE050_MAX_BUF_SIZE_RSP (892)
#define SE051_MAX_BUF_SIZE_CMD (1024)
#define SE051_MAX_BUF_SIZE_RSP (1024)

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

#endif
