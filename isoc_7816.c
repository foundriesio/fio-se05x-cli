// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2022, Foundries.io Ltd.
 * Author: Jorge Ramirez-Ortiz <jorge@foundries.io>
 */
#include <err.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include "isoc_7816.h"

size_t TLV_SIZE_CMD;

int tlvGet_u8buf(uint32_t tag, size_t *index, uint8_t *buf, size_t len,
		 uint8_t *rsp, size_t *olen)
{
	size_t extended_len = 0;
	size_t rsp_len = 0;
	uint8_t *p = NULL;

	if (!rsp || !olen || !index || *index > len)
		return -EINVAL;

	p = buf + *index;

	if (*p++ != tag)
		return -EINVAL;

	rsp_len = *p++;

	switch (rsp_len) {
	case 0x00 ... 0x7F:
		extended_len = rsp_len;
		*index += 2;
		break;
	case 0x81:
		extended_len = *p++;
		*index += 3;
		break;
	case 0x82:
		extended_len = *p++;
		extended_len = (extended_len << 8) | *p++;
		*index += 4;
		break;
	default:
		return -EINVAL;
	}

	if (extended_len > *olen)
		return -EINVAL;

	if (extended_len > len)
		return -EINVAL;

	*olen = extended_len;
	*index += extended_len;

	while (extended_len-- > 0)
		*rsp++ = *p++;

	return 0;
}

int tlvGet_u8(uint32_t tag, size_t *index, uint8_t *buf, size_t buf_len,
	      uint8_t *rsp)
{
	uint8_t *p = buf + *index;
	size_t rsp_len = 0;

	if (*index > buf_len)
		return -EINVAL;

	if (*p++ != tag)
		return -EINVAL;

	rsp_len = *p++;
	if (rsp_len > 1)
		return -EINVAL;

	*rsp = *p;
	*index += 1 + 1 + rsp_len;

	return 0;
}

int tlvGet_u16(uint32_t tag, size_t *index, uint8_t *buf, size_t buf_len,
	       uint16_t *rsp)
{
	uint8_t *p = buf + *index;
	size_t rsp_len = 0;

	if (*index > buf_len)
		return -EINVAL;

	if (*p++ != tag)
		return -EINVAL;

	rsp_len = *p++;
	if (rsp_len > 2)
		return -EINVAL;

	*rsp = *p++ << 8;
	*rsp |= *p++;
	*index += 1 + 1 + rsp_len;

	return 0;
}


int tlvSet_u8(uint32_t tag, uint8_t **buf, size_t *len, uint8_t value)
{
	const size_t size_of_tlv = 1 + 1 + 1;
	uint8_t *p = *buf;

	if (size_of_tlv + *len > TLV_SIZE_CMD)
		return -EINVAL;

	*p++ = tag;
	*p++ = 1;
	*p++ = value;
	*buf = p;
	*len += size_of_tlv;

	return 0;
}

int tlvSet_u16(uint32_t tag, uint8_t **buf, size_t *len, uint16_t value)
{
	const size_t size_of_tlv = 1 + 1 + 2;
	uint8_t *p = *buf;

	if (size_of_tlv + *len > TLV_SIZE_CMD)
		return -EINVAL;

	*p++ = tag;
	*p++ = 2;
	*p++ = (value >> 1 * 8) & 0xFF;
	*p++ = (value >> 0 * 8) & 0xFF;
	*buf = p;
	*len += size_of_tlv;

	return 0;
}

int tlvSet_u32(uint32_t tag, uint8_t **buf, size_t *len, uint32_t value)
{
	const size_t tlv_len = 1 + 1 + 4;
	uint8_t *p = *buf;

	if (tlv_len + *len > TLV_SIZE_CMD)
		return -EINVAL;

	*p++ = tag;
	*p++ = 4;
	*p++ = (value >> 3 * 8) & 0xFF;
	*p++ = (value >> 2 * 8) & 0xFF;
	*p++ = (value >> 1 * 8) & 0xFF;
	*p++ = (value >> 0 * 8) & 0xFF;

	*buf = p;
	*len += tlv_len;

	return 0;
}
