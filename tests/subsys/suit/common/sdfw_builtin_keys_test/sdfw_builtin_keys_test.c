/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <psa/crypto.h>
#include <errno.h>

/**
 * Currently the implementation only allows to build the tests, it
 * might be expanded if additional testing is needed.
 */

bool sdfw_builtin_keys_is_builtin(mbedtls_svc_key_id_t key_id)
{
	return false;
}

int sdfw_builtin_keys_verify_message(mbedtls_svc_key_id_t key_id,
				     psa_algorithm_t alg,
				     const uint8_t * input,
				     size_t input_length,
				     const uint8_t * signature,
				     size_t signature_length)
{
	return -ENOENT;
}
