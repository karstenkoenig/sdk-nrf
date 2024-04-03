/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <suit_plat_check_image_match_domain_specific.h>
#include <suit_platform.h>

#include <suit_plat_digest_cache.h>
#include <suit_plat_decode_util.h>
#include <suit.h>
#include <psa/crypto.h>

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(suit_plat_check_image_match_sdfw, CONFIG_SUIT_LOG_LEVEL);

static int suit_plat_check_image_match_soc_spec_sdfw(struct zcbor_string *component_id,
						     enum suit_cose_alg alg_id,
						     struct zcbor_string *digest)
{
#ifdef CONFIG_SOC_NRF54H20
	if (suit_cose_sha512 != alg_id) {
		LOG_ERR("Unsupported digest algorithm: %d", alg_id);
		return SUIT_ERR_UNSUPPORTED_PARAMETER;
	}

	uint8_t *current_sdfw_digest = (uint8_t *)(NRF_SICR->UROT.SM.TBS.FW.DIGEST);

	if (PSA_HASH_LENGTH(PSA_ALG_SHA_512) != digest->len) {
		LOG_ERR("Digest length mismatch: %d instead of %d", digest->len,
			PSA_HASH_LENGTH(PSA_ALG_SHA_512));
		return SUIT_FAIL_CONDITION;
	}

	if (memcmp((void *)current_sdfw_digest, (void *)digest->value,
		   PSA_HASH_LENGTH(PSA_ALG_SHA_512))) {
		LOG_INF("Digest mismatch");
		return SUIT_FAIL_CONDITION;
	}

	return SUIT_SUCCESS;
#else  /* CONFIG_SOC_NRF54H20 */
	return SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
#endif /* CONFIG_SOC_NRF54H20 */
}

static int suit_plat_check_image_match_soc_spec(struct zcbor_string *component_id,
						enum suit_cose_alg alg_id,
						struct zcbor_string *digest)
{
	uint32_t number = 0;

	if (suit_plat_decode_component_number(component_id, &number) != SUIT_PLAT_SUCCESS) {
		LOG_ERR("Missing component id number");
		return SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
	}

	LOG_DBG("Component id number: %d", number);

	int err = SUIT_ERR_UNSUPPORTED_COMPONENT_ID;

	if (number == 1) {
		/* SDFW */
		err = suit_plat_check_image_match_soc_spec_sdfw(component_id, alg_id, digest);
	} else if (number == 2) {
		/* SDFW recovery */
		err = SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
	} else {
		/* Unsupported */
		err = SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
	}

	return err;
}

static int suit_plat_check_image_match_mfst(suit_component_t component, enum suit_cose_alg alg_id,
					    struct zcbor_string *digest)
{
	int ret = SUIT_ERR_UNSUPPORTED_COMPONENT_ID;

	const uint8_t *envelope_str;
	size_t envelope_len;
	struct zcbor_string manifest_digest;
	enum suit_cose_alg alg;

	ret = suit_plat_retrieve_manifest(component, &envelope_str, &envelope_len);
	if (ret != SUIT_SUCCESS) {
		LOG_ERR("Failed to check image digest: unable to retrieve manifest contents "
			"(handle: %p)\r\n",
			(void *)component);
		return ret;
	}

	ret = suit_processor_get_manifest_metadata(envelope_str, envelope_len, false, NULL,
						   &manifest_digest, &alg, NULL);
	if (ret != SUIT_SUCCESS) {
		LOG_ERR("Failed to check image digest: unable to read manifest digest (handle: "
			"%p)\r\n",
			(void *)component);
		return ret;
	}

	if (alg_id != alg) {
		LOG_ERR("Manifest digest check failed: digest algorithm does not match (handle: "
			"%p)\r\n",
			(void *)component);
		ret = SUIT_FAIL_CONDITION;
	} else if (!suit_compare_zcbor_strings(digest, &manifest_digest)) {
		LOG_ERR("Manifest digest check failed: digest values does not match (handle: "
			"%p)\r\n",
			(void *)component);
		ret = SUIT_FAIL_CONDITION;
	}

	return ret;
}

bool suit_plat_check_image_match_domain_specific_is_type_mem_mapped(
	suit_component_type_t component_type)
{
	return (component_type == SUIT_COMPONENT_TYPE_CAND_IMG) ||
	       (component_type == SUIT_COMPONENT_TYPE_MEM);
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
	case SUIT_COMPONENT_TYPE_MEM:
		/* Types already handled by suit_plat_check_image_match */
		break;
	case SUIT_COMPONENT_TYPE_SOC_SPEC: {
		err = suit_plat_check_image_match_soc_spec(component_id, alg_id, digest);
		break;
	}
	case SUIT_COMPONENT_TYPE_CAND_MFST:
	case SUIT_COMPONENT_TYPE_INSTLD_MFST:
		err = suit_plat_check_image_match_mfst(component, alg_id, digest);
		break;

	case SUIT_COMPONENT_TYPE_CACHE_POOL:
	default: {
		LOG_ERR("Unhandled component type: %d", component_type);
		err = SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
		break;
	}
	}

#if CONFIG_SUIT_DIGEST_CACHE
	if (err == SUIT_SUCCESS) {
		int ret;

		switch (component_type) {
		case SUIT_COMPONENT_TYPE_MEM:
		case SUIT_COMPONENT_TYPE_SOC_SPEC: {
			ret = suit_plat_digest_cache_add(component_id, alg_id, digest);

			if (ret != SUIT_SUCCESS) {
				LOG_WRN("Failed to cache digest for component type %d, err %d",
					component_type, ret);
			}
		}
		default: {
			break;
		}
		}
	}
#endif /* CONFIG_SUIT_DIGEST_CACHE */

	return err;
}
