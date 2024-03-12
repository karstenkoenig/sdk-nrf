/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <suit_plat_check_image_match_domain_specific.h>
#include <zephyr/logging/log.h>

#include <sdfw/sdfw_services/suit_service.h>

LOG_MODULE_REGISTER(suit_plat_check_image_match_app, CONFIG_SUIT_LOG_LEVEL);

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

bool suit_plat_check_image_match_domain_specific_is_type_mem_mapped(
	suit_component_type_t component_type)
{
#ifdef CONFIG_SUIT_STREAM_SINK_DIGEST
	return (component_type == SUIT_COMPONENT_TYPE_CAND_IMG)
	       || (component_type == SUIT_COMPONENT_TYPE_CAND_MFST);
#else
	return false;
#endif
}

int suit_plat_check_image_match_domain_specific(suit_component_t component,
						enum suit_cose_alg alg_id,
						struct zcbor_string *digest,
						struct zcbor_string *component_id,
						suit_component_type_t component_type)
{
	int err = SUIT_SUCCESS;

	switch (component_type) {
	case SUIT_COMPONENT_TYPE_CAND_IMG:
	case SUIT_COMPONENT_TYPE_CAND_MFST:
		/* Types already handled by suit_plat_check_image_match */
		break;
	case SUIT_COMPONENT_TYPE_INSTLD_MFST:
	case SUIT_COMPONENT_TYPE_MEM:
	case SUIT_COMPONENT_TYPE_SOC_SPEC: {
		err = suit_plat_check_image_match_ssf(component_id, alg_id, digest);
		break;
	}
	case SUIT_COMPONENT_TYPE_CACHE_POOL:
	default: {
		LOG_ERR("Unhandled component type: %d", component_type);
		err = SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
		break;
	}
	}

	return err;
}
