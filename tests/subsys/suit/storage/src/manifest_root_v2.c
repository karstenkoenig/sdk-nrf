/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <stdint.h>
#include <stddef.h>

/** @brief SUIT envelope generated using the manifest/manifest_root_v2.yaml input file.
 *
 * @details This envelope contains 256-byte random numbers attached as an integrated
 *          payload and fetched directly into the memory-mapped region during install step.
 *          The envelope has been signed using the manifest/key_private.pem key.
 *
 * @note Please use the manifest_common/regenerate.sh script for regenerating payloads.
 */
uint8_t manifest_root_v2_buf[] = {
	0xD8, 0x6B, 0xA4, 0x02, 0x58, 0x7A, 0x82, 0x58, 0x24, 0x82, 0x2F, 0x58, 0x20, 0x61, 0x75,
	0xCC, 0x03, 0x5D, 0x95, 0xD4, 0x69, 0x8F, 0xC4, 0x86, 0xEC, 0x43, 0x9C, 0x02, 0x27, 0xF2,
	0x28, 0x6C, 0x6C, 0xA0, 0x32, 0x99, 0x5A, 0x9F, 0x53, 0xDD, 0x6A, 0x64, 0x21, 0xC6, 0xEA,
	0x58, 0x51, 0xD2, 0x84, 0x4A, 0xA2, 0x01, 0x26, 0x04, 0x45, 0x1A, 0x7F, 0xFF, 0xFF, 0xE0,
	0xA0, 0xF6, 0x58, 0x40, 0x99, 0x83, 0x33, 0x7F, 0x1D, 0x93, 0x63, 0x27, 0x68, 0xB9, 0x89,
	0x39, 0x50, 0xD3, 0x69, 0x14, 0xF3, 0x0E, 0xF4, 0x52, 0x66, 0x8F, 0x10, 0x20, 0x53, 0x64,
	0x8F, 0x6C, 0x54, 0xE4, 0xEB, 0xEE, 0xC3, 0x9A, 0xA0, 0xED, 0xB7, 0x47, 0x93, 0x36, 0x30,
	0x81, 0x65, 0x7F, 0x12, 0xA5, 0xFF, 0xE7, 0x45, 0xD8, 0x73, 0xB9, 0xBA, 0x94, 0x4A, 0xDC,
	0xD1, 0x3F, 0x0A, 0xB5, 0xA1, 0x46, 0x37, 0x0F, 0x03, 0x59, 0x01, 0x77, 0xA7, 0x01, 0x01,
	0x02, 0x02, 0x03, 0x58, 0xB3, 0xA3, 0x02, 0x83, 0x82, 0x4A, 0x69, 0x43, 0x41, 0x4E, 0x44,
	0x5F, 0x4D, 0x46, 0x53, 0x54, 0x41, 0x00, 0x82, 0x4C, 0x6B, 0x49, 0x4E, 0x53, 0x54, 0x4C,
	0x44, 0x5F, 0x4D, 0x46, 0x53, 0x54, 0x50, 0x81, 0x6A, 0xA0, 0xA0, 0xAF, 0x11, 0x5E, 0xF2,
	0x85, 0x8A, 0xFE, 0xB6, 0x68, 0xB2, 0xE9, 0xC9, 0x82, 0x4C, 0x6B, 0x49, 0x4E, 0x53, 0x54,
	0x4C, 0x44, 0x5F, 0x4D, 0x46, 0x53, 0x54, 0x50, 0x08, 0xC1, 0xB5, 0x99, 0x55, 0xE8, 0x5F,
	0xBC, 0x9E, 0x76, 0x7B, 0xC2, 0x9C, 0xE1, 0xB0, 0x4D, 0x04, 0x58, 0x59, 0x8E, 0x0C, 0x01,
	0x14, 0xA2, 0x01, 0x50, 0x76, 0x17, 0xDA, 0xA5, 0x71, 0xFD, 0x5A, 0x85, 0x8F, 0x94, 0xE2,
	0x8D, 0x73, 0x5C, 0xE9, 0xF4, 0x02, 0x50, 0x81, 0x6A, 0xA0, 0xA0, 0xAF, 0x11, 0x5E, 0xF2,
	0x85, 0x8A, 0xFE, 0xB6, 0x68, 0xB2, 0xE9, 0xC9, 0x0C, 0x02, 0x14, 0xA2, 0x01, 0x50, 0x76,
	0x17, 0xDA, 0xA5, 0x71, 0xFD, 0x5A, 0x85, 0x8F, 0x94, 0xE2, 0x8D, 0x73, 0x5C, 0xE9, 0xF4,
	0x02, 0x50, 0x08, 0xC1, 0xB5, 0x99, 0x55, 0xE8, 0x5F, 0xBC, 0x9E, 0x76, 0x7B, 0xC2, 0x9C,
	0xE1, 0xB0, 0x4D, 0x0C, 0x82, 0x01, 0x02, 0x01, 0x0F, 0x02, 0x0F, 0x01, 0xA3, 0x00, 0xA0,
	0x01, 0xA0, 0x02, 0xA0, 0x07, 0x49, 0x86, 0x0C, 0x82, 0x01, 0x02, 0x07, 0x0F, 0x0B, 0x0F,
	0x09, 0x49, 0x86, 0x0C, 0x82, 0x01, 0x02, 0x07, 0x0F, 0x0B, 0x0F, 0x11, 0x58, 0x83, 0x96,
	0x0C, 0x00, 0x14, 0xA3, 0x15, 0x69, 0x23, 0x72, 0x61, 0x64, 0x2E, 0x73, 0x75, 0x69, 0x74,
	0x03, 0x58, 0x24, 0x82, 0x2F, 0x58, 0x20, 0xE0, 0xBE, 0xFB, 0xAA, 0x5A, 0x90, 0x2F, 0x97,
	0x85, 0xB0, 0xC2, 0x10, 0xF7, 0x0B, 0x38, 0x8E, 0xB3, 0xA6, 0x5F, 0x1C, 0x14, 0x99, 0xA5,
	0x15, 0x88, 0x6B, 0x6F, 0x2E, 0xC2, 0xD4, 0x2F, 0x41, 0x0E, 0x19, 0x01, 0x39, 0x15, 0x02,
	0x03, 0x0F, 0x07, 0x0F, 0x0B, 0x0F, 0x14, 0xA3, 0x15, 0x69, 0x23, 0x61, 0x70, 0x70, 0x2E,
	0x73, 0x75, 0x69, 0x74, 0x03, 0x58, 0x24, 0x82, 0x2F, 0x58, 0x20, 0x4F, 0x0B, 0xEF, 0xA4,
	0xDF, 0x5D, 0xEC, 0xB8, 0x92, 0xBE, 0x9C, 0xB9, 0xF3, 0x0B, 0x5E, 0xF7, 0x05, 0x4A, 0xD0,
	0x95, 0x35, 0xDD, 0x4A, 0x97, 0x3B, 0x3C, 0x93, 0x3C, 0x5E, 0xF6, 0x44, 0xC5, 0x0E, 0x19,
	0x01, 0x39, 0x15, 0x02, 0x03, 0x0F, 0x07, 0x0F, 0x0B, 0x0F, 0x05, 0x82, 0x4C, 0x6B, 0x49,
	0x4E, 0x53, 0x54, 0x4C, 0x44, 0x5F, 0x4D, 0x46, 0x53, 0x54, 0x50, 0x3F, 0x6A, 0x3A, 0x4D,
	0xCD, 0xFA, 0x58, 0xC5, 0xAC, 0xCE, 0xF9, 0xF5, 0x84, 0xC4, 0x11, 0x24, 0x69, 0x23, 0x72,
	0x61, 0x64, 0x2E, 0x73, 0x75, 0x69, 0x74, 0x59, 0x01, 0x39, 0xD8, 0x6B, 0xA2, 0x02, 0x58,
	0x7A, 0x82, 0x58, 0x24, 0x82, 0x2F, 0x58, 0x20, 0x52, 0xDA, 0xDD, 0xDF, 0xDA, 0x18, 0xFF,
	0x08, 0x14, 0xAA, 0x45, 0x84, 0xC2, 0xE6, 0x71, 0x3B, 0x5F, 0xD5, 0x8E, 0x23, 0xF3, 0x7C,
	0xE8, 0xBB, 0x8A, 0xF6, 0x72, 0xEE, 0x4A, 0xE6, 0x3C, 0x89, 0x58, 0x51, 0xD2, 0x84, 0x4A,
	0xA2, 0x01, 0x26, 0x04, 0x45, 0x1A, 0x7F, 0xFF, 0xFF, 0xE0, 0xA0, 0xF6, 0x58, 0x40, 0x2D,
	0x41, 0x3F, 0x6F, 0x19, 0x9F, 0xFB, 0x17, 0xB9, 0x74, 0x30, 0x0F, 0x7C, 0xE5, 0xE5, 0xFA,
	0x31, 0xE7, 0x27, 0xA9, 0x53, 0xFA, 0x13, 0x81, 0x2C, 0xBE, 0x09, 0x2B, 0x10, 0xC3, 0x72,
	0x25, 0x82, 0x17, 0xE4, 0x74, 0x15, 0x82, 0x63, 0x13, 0xA5, 0x38, 0x9D, 0x74, 0x0F, 0xA1,
	0x02, 0x13, 0xEA, 0xB1, 0xED, 0xB0, 0xAC, 0x60, 0x3E, 0xC3, 0xC3, 0x7B, 0x33, 0xBB, 0x94,
	0xBB, 0x5A, 0xEF, 0x03, 0x58, 0xB6, 0xA7, 0x01, 0x01, 0x02, 0x02, 0x03, 0x58, 0x70, 0xA2,
	0x02, 0x81, 0x84, 0x44, 0x63, 0x4D, 0x45, 0x4D, 0x41, 0x03, 0x45, 0x1A, 0x0E, 0x05, 0x40,
	0x00, 0x45, 0x1A, 0x00, 0x05, 0x58, 0x00, 0x04, 0x58, 0x56, 0x86, 0x14, 0xA4, 0x01, 0x50,
	0x76, 0x17, 0xDA, 0xA5, 0x71, 0xFD, 0x5A, 0x85, 0x8F, 0x94, 0xE2, 0x8D, 0x73, 0x5C, 0xE9,
	0xF4, 0x02, 0x50, 0x81, 0x6A, 0xA0, 0xA0, 0xAF, 0x11, 0x5E, 0xF2, 0x85, 0x8A, 0xFE, 0xB6,
	0x68, 0xB2, 0xE9, 0xC9, 0x03, 0x58, 0x24, 0x82, 0x2F, 0x58, 0x20, 0x5F, 0xC3, 0x54, 0xBF,
	0x8E, 0x8C, 0x50, 0xFB, 0x4F, 0xBC, 0x2C, 0xFA, 0xEB, 0x04, 0x53, 0x41, 0xC9, 0x80, 0x6D,
	0xEA, 0xBD, 0xCB, 0x41, 0x54, 0xFB, 0x79, 0xCC, 0xA4, 0xF0, 0xC9, 0x8C, 0x12, 0x0E, 0x19,
	0x01, 0x00, 0x01, 0x0F, 0x02, 0x0F, 0x07, 0x43, 0x82, 0x03, 0x0F, 0x09, 0x43, 0x82, 0x17,
	0x02, 0x11, 0x52, 0x86, 0x14, 0xA1, 0x15, 0x69, 0x23, 0x66, 0x69, 0x6C, 0x65, 0x2E, 0x62,
	0x69, 0x6E, 0x15, 0x02, 0x03, 0x0F, 0x05, 0x82, 0x4C, 0x6B, 0x49, 0x4E, 0x53, 0x54, 0x4C,
	0x44, 0x5F, 0x4D, 0x46, 0x53, 0x54, 0x50, 0x81, 0x6A, 0xA0, 0xA0, 0xAF, 0x11, 0x5E, 0xF2,
	0x85, 0x8A, 0xFE, 0xB6, 0x68, 0xB2, 0xE9, 0xC9, 0x69, 0x23, 0x61, 0x70, 0x70, 0x2E, 0x73,
	0x75, 0x69, 0x74, 0x59, 0x01, 0x39, 0xD8, 0x6B, 0xA2, 0x02, 0x58, 0x7A, 0x82, 0x58, 0x24,
	0x82, 0x2F, 0x58, 0x20, 0x45, 0xCC, 0xC3, 0x8F, 0xB7, 0xEA, 0x5A, 0x86, 0xC9, 0xEA, 0xA1,
	0x73, 0x44, 0x25, 0xDB, 0x4A, 0x43, 0x90, 0x66, 0x14, 0x88, 0x16, 0x55, 0x08, 0xEA, 0xB5,
	0xEA, 0x94, 0x35, 0xD8, 0x49, 0x32, 0x58, 0x51, 0xD2, 0x84, 0x4A, 0xA2, 0x01, 0x26, 0x04,
	0x45, 0x1A, 0x7F, 0xFF, 0xFF, 0xE0, 0xA0, 0xF6, 0x58, 0x40, 0x25, 0x86, 0xDB, 0xA6, 0x20,
	0xFF, 0x98, 0xE9, 0x47, 0x6A, 0x20, 0xE0, 0x36, 0x99, 0xA4, 0x30, 0xD1, 0xB5, 0xAD, 0x69,
	0xE1, 0xF3, 0x5F, 0x0F, 0x21, 0xA0, 0xE5, 0x15, 0x46, 0xBD, 0x51, 0x1E, 0x0D, 0x50, 0x42,
	0x77, 0x59, 0x58, 0x42, 0x11, 0x10, 0x43, 0xAB, 0x47, 0x94, 0x66, 0x33, 0xF1, 0xC5, 0x1D,
	0x12, 0x37, 0xF6, 0x07, 0x76, 0xEF, 0x23, 0x30, 0xFE, 0xEF, 0x09, 0x61, 0x1B, 0x8D, 0x03,
	0x58, 0xB6, 0xA7, 0x01, 0x01, 0x02, 0x02, 0x03, 0x58, 0x70, 0xA2, 0x02, 0x81, 0x84, 0x44,
	0x63, 0x4D, 0x45, 0x4D, 0x41, 0x02, 0x45, 0x1A, 0x0E, 0x0A, 0xA0, 0x00, 0x45, 0x1A, 0x00,
	0x07, 0xF8, 0x00, 0x04, 0x58, 0x56, 0x86, 0x14, 0xA4, 0x01, 0x50, 0x76, 0x17, 0xDA, 0xA5,
	0x71, 0xFD, 0x5A, 0x85, 0x8F, 0x94, 0xE2, 0x8D, 0x73, 0x5C, 0xE9, 0xF4, 0x02, 0x50, 0x08,
	0xC1, 0xB5, 0x99, 0x55, 0xE8, 0x5F, 0xBC, 0x9E, 0x76, 0x7B, 0xC2, 0x9C, 0xE1, 0xB0, 0x4D,
	0x03, 0x58, 0x24, 0x82, 0x2F, 0x58, 0x20, 0x5F, 0xC3, 0x54, 0xBF, 0x8E, 0x8C, 0x50, 0xFB,
	0x4F, 0xBC, 0x2C, 0xFA, 0xEB, 0x04, 0x53, 0x41, 0xC9, 0x80, 0x6D, 0xEA, 0xBD, 0xCB, 0x41,
	0x54, 0xFB, 0x79, 0xCC, 0xA4, 0xF0, 0xC9, 0x8C, 0x12, 0x0E, 0x19, 0x01, 0x00, 0x01, 0x0F,
	0x02, 0x0F, 0x07, 0x43, 0x82, 0x03, 0x0F, 0x09, 0x43, 0x82, 0x17, 0x02, 0x11, 0x52, 0x86,
	0x14, 0xA1, 0x15, 0x69, 0x23, 0x66, 0x69, 0x6C, 0x65, 0x2E, 0x62, 0x69, 0x6E, 0x15, 0x02,
	0x03, 0x0F, 0x05, 0x82, 0x4C, 0x6B, 0x49, 0x4E, 0x53, 0x54, 0x4C, 0x44, 0x5F, 0x4D, 0x46,
	0x53, 0x54, 0x50, 0x08, 0xC1, 0xB5, 0x99, 0x55, 0xE8, 0x5F, 0xBC, 0x9E, 0x76, 0x7B, 0xC2,
	0x9C, 0xE1, 0xB0, 0x4D};

const size_t manifest_root_v2_len = sizeof(manifest_root_v2_buf);
