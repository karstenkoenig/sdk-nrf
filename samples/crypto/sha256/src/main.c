/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <psa/crypto.h>
#include <psa/crypto_extra.h>
#include <zephyr/logging/log.h>

#ifdef CONFIG_BUILD_WITH_TFM
#include <tfm_ns_interface.h>
#endif

#define DCACHE_HELL_THREAD_STACK_SIZE 500
#define DCACHE_HELL_THREAD_PRIORITY   CONFIG_MAIN_THREAD_PRIORITY

#define APP_SUCCESS	    (0)
#define APP_ERROR	    (-1)
#define APP_SUCCESS_MESSAGE "Example finished successfully!"
#define APP_ERROR_MESSAGE   "Example exited with error!"

#define PRINT_HEX(p_label, p_text, len)                                                            \
	({                                                                                         \
		LOG_INF("---- %s (len: %u): ----", p_label, len);                                  \
		LOG_HEXDUMP_INF(p_text, len, "Content:");                                          \
		LOG_INF("---- %s end  ----", p_label);                                             \
	})

LOG_MODULE_REGISTER(sha256, LOG_LEVEL_DBG);

K_THREAD_STACK_DEFINE(dcache_hell_thread_stack_area, DCACHE_HELL_THREAD_STACK_SIZE);
struct k_thread dcache_hell_thread_data;

/* Below text is used as plaintext for computing/verifing the hash. */
static uint8_t m_plain_text[] = {0x09, 0xfc, 0x1a, 0xcc, 0xc2, 0x30, 0xa2, 0x05, 0xe4, 0xa2, 0x08,
				 0xe6, 0x4a, 0x8f, 0x20, 0x42, 0x91, 0xf5, 0x81, 0xa1, 0x27, 0x56,
				 0x39, 0x2d, 0xa4, 0xb8, 0xc0, 0xcf, 0x5e, 0xf0, 0x2b, 0x95};

static uint8_t m_expected_digest[] = {0x4f, 0x44, 0xc1, 0xc7, 0xfb, 0xeb, 0xb6, 0xf9,
				      0x60, 0x18, 0x29, 0xf3, 0x89, 0x7b, 0xfd, 0x65,
				      0x0c, 0x56, 0xfa, 0x07, 0x84, 0x4b, 0xe7, 0x64,
				      0x89, 0x07, 0x63, 0x56, 0xac, 0x18, 0x86, 0xa4};

static struct {
	uint8_t always_dirty_member;
	uint8_t generated_digest[32];
} m_unaligned_members_struct;

static bool m_dcache_hell_thread_terminate = false;
/* ====================================================================== */

int crypto_init(void)
{
	psa_status_t status;

	/* Initialize PSA Crypto */
	status = psa_crypto_init();
	if (status != PSA_SUCCESS) {
		return APP_ERROR;
	}

	return APP_SUCCESS;
}

void dcache_hell_thread_exec(void *unused1, void *unused2, void *unused3)
{
	ARG_UNUSED(unused1);
	ARG_UNUSED(unused2);
	ARG_UNUSED(unused3);
	while (1) {
		m_unaligned_members_struct.always_dirty_member++;
		k_yield(); /* Switch back to main thread */
		if (m_dcache_hell_thread_terminate) {
			return;
		}
	}
}

int main(void)
{
	int status;
	LOG_INF("Starting SHA256 example...");

	LOG_INF("Starting DCache hell thread.");
	k_thread_create(&dcache_hell_thread_data, dcache_hell_thread_stack_area,
			K_THREAD_STACK_SIZEOF(dcache_hell_thread_stack_area),
			dcache_hell_thread_exec, NULL, NULL, NULL, DCACHE_HELL_THREAD_PRIORITY, 0,
			K_NO_WAIT);

	LOG_INF("Initializing crypto library");

	status = crypto_init();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}

	size_t olen;

	LOG_INF("Hashing using SHA256...");

	/* Calculate the SHA256 hash */
	status = psa_hash_compute(PSA_ALG_SHA_256, m_plain_text, sizeof(m_plain_text),
				  m_unaligned_members_struct.generated_digest,
				  sizeof(m_unaligned_members_struct.generated_digest), &olen);

	if (status != PSA_SUCCESS) {
		LOG_INF("psa_hash_compute failed! (Error: %d)", status);
		return APP_ERROR;
	}

	LOG_INF("Hashing successful!");
	PRINT_HEX("SHA256 hash", m_unaligned_members_struct.generated_digest,
		  sizeof(m_unaligned_members_struct.generated_digest));

	status = memcmp(m_unaligned_members_struct.generated_digest, m_expected_digest,
			sizeof(m_expected_digest));

	m_dcache_hell_thread_terminate = true;

	if (status != 0) {
		LOG_INF("Error: Digests don't match!");
		return APP_ERROR;
	}

	LOG_INF(APP_SUCCESS_MESSAGE);

	return APP_SUCCESS;
}
