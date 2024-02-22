/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <suit_platform.h>
#include <suit_platform_internal.h>
#include <suit_plat_decode_util.h>
#include <suit_plat_error_convert.h>
#include <suit_service.h>

#ifdef CONFIG_SUIT_STREAM_SINK_DIGEST
#include <suit_memptr_storage.h>
#include <generic_address_streamer.h>
#include <digest_sink.h>

#include <psa/crypto.h>
#endif /* CONFIG_SUIT_STREAM_SINK_DIGEST */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(suit_plat_check_image_match, CONFIG_SUIT_LOG_LEVEL);

static int suit_plat_check_image_match_ssf(struct zcbor_string *component_id,
					   enum suit_cose_alg alg_id, struct zcbor_string *digest)
{
	suit_plat_mreg_t component_id_mreg = {
		.mem = component_id->value,
		.size = component_id->len,
	};

	suit_plat_mreg_t digest_mreg = {
		.mem = digest->value,
		.size = digest->len,
	};

	suit_ssf_err_t ret = suit_check_installed_component_digest(&component_id_mreg, (int)alg_id,
								   &digest_mreg);

	switch (ret) {
	case SUIT_PLAT_SUCCESS:
		return SUIT_SUCCESS;
	case SUIT_SSF_FAIL_CONDITION:
		return SUIT_FAIL_CONDITION;
	case SUIT_SSF_MISSING_COMPONENT:
		return SUIT_FAIL_CONDITION;
	case SUIT_PLAT_ERR_UNSUPPORTED:
		return SUIT_ERR_UNSUPPORTED_PARAMETER;
	default:
		break;
	}

	return SUIT_ERR_CRASH;
}

#ifdef CONFIG_SUIT_STREAM_SINK_DIGEST
static int suit_plat_check_image_match_mem_mapped(suit_component_t component,
						  enum suit_cose_alg alg_id,
						  struct zcbor_string *digest)
{
	void *impl_data = NULL;
	int err = suit_plat_component_impl_data_get(component, &impl_data);
	if (err != SUIT_SUCCESS) {
		LOG_ERR("Failed to get implementation data: %d", err);
		return SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
	}

	uint8_t *data = NULL;
	size_t size = 0;
	err = suit_memptr_storage_ptr_get((memptr_storage_handle_t)impl_data, &data, &size);
	if (err != SUIT_PLAT_SUCCESS) {
		LOG_ERR("Failed to get memptr ptr: %d", err);
		return SUIT_ERR_CRASH;
	}

	psa_algorithm_t psa_alg;

	if (suit_cose_sha512 == alg_id) {
		psa_alg = PSA_ALG_SHA_512;
	} else if (suit_cose_sha256 == alg_id) {
		psa_alg = PSA_ALG_SHA_256;
	} else {
		LOG_ERR("Unsupported hash algorithm: %d", alg_id);
		return SUIT_ERR_UNSUPPORTED_PARAMETER;
	}

	struct stream_sink digest_sink;

	err = suit_digest_sink_get(&digest_sink, psa_alg, digest->value);
	if (err != SUIT_PLAT_SUCCESS) {
		LOG_ERR("Failed to get digest sink: %d", err);
		return suit_plat_err_to_processor_err_convert(err);
	}

	err = suit_generic_address_streamer_stream(data, size, &digest_sink);
	if (err != SUIT_PLAT_SUCCESS) {
		LOG_ERR("Failed to stream to digest sink: %d", err);
		err = suit_plat_err_to_processor_err_convert(err);
	} else {
		err = suit_digest_sink_digest_match(digest_sink.ctx);
		if (err != SUIT_PLAT_SUCCESS) {
			LOG_ERR("Failed to check digest: %d", err);
			/* Translate error code to allow entering another branches in try-each
			 * sequence */
			err = SUIT_FAIL_CONDITION;
		}
		else
		{
			err = SUIT_SUCCESS;
		}
	}

	suit_plat_err_t release_err = digest_sink.release(digest_sink.ctx);
	if (release_err != SUIT_PLAT_SUCCESS) {
		LOG_ERR("Failed to release digest sink: %d", release_err);
		if (err != SUIT_SUCCESS) {
			err = suit_plat_err_to_processor_err_convert(release_err);
		}
	}

	return err;
}
#endif /* CONFIG_SUIT_STREAM_SINK_DIGEST */

int suit_plat_check_image_match(suit_component_t component, enum suit_cose_alg alg_id,
				struct zcbor_string *digest)
{
	struct zcbor_string *component_id = NULL;
	suit_component_type_t component_type = SUIT_COMPONENT_TYPE_UNSUPPORTED;

	int err = suit_plat_component_id_get(component, &component_id);
	if (err != SUIT_SUCCESS) {
		LOG_ERR("Failed to get component id: %d", err);
		return err;
	}

	if (suit_plat_decode_component_type(component_id, &component_type) != SUIT_PLAT_SUCCESS) {
		LOG_ERR("Failed to decode component type");
		return SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
	}

	LOG_DBG("Component type: %d", component_type);

	switch (component_type) {
	case SUIT_COMPONENT_TYPE_UNSUPPORTED: {
		LOG_ERR("Unsupported component type");
		err = SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
		break;
	}
	case SUIT_COMPONENT_TYPE_INSTLD_MFST:
	case SUIT_COMPONENT_TYPE_MEM:
	case SUIT_COMPONENT_TYPE_SOC_SPEC: {
		err = suit_plat_check_image_match_ssf(component_id, alg_id, digest);
		break;
	}
	case SUIT_COMPONENT_TYPE_CAND_IMG:
#ifdef CONFIG_SUIT_STREAM_SINK_DIGEST
		err = suit_plat_check_image_match_mem_mapped(component, alg_id, digest);
		break;
#endif /* CONFIG_SUIT_STREAM_SINK_DIGEST */
	case SUIT_COMPONENT_TYPE_CAND_MFST:
	case SUIT_COMPONENT_TYPE_CACHE_POOL:
	default: {
		LOG_ERR("Unhandled component type: %d", component_type);
		err = SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
		break;
	}
	}

	return err;
}
