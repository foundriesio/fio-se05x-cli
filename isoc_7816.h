// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2022, Foundries.io Ltd.
 * Author: Jorge Ramirez-Ortiz <jorge@foundries.io>
 */
#ifndef ISOC_7816_H
#define ISOC_7816_H

extern size_t TLV_SIZE_CMD;

int tlvGet_u8buf(uint32_t tag, size_t *index, uint8_t *buf, size_t len,
		 uint8_t *rsp, size_t *olen);
int tlvGet_u8(uint32_t tag, size_t *index, uint8_t *buf, size_t buf_len,
	      uint8_t *rsp);
int tlvSet_u8(uint32_t tag, uint8_t **buf, size_t *len, uint8_t value);
int tlvGet_u16(uint32_t tag, size_t *index, uint8_t *buf, size_t buf_len,
	       uint16_t *rsp);
int tlvSet_u16(uint32_t tag, uint8_t **buf, size_t *len, uint16_t value);
int tlvSet_u32(uint32_t tag, uint8_t **buf, size_t *len, uint32_t value);

#endif
