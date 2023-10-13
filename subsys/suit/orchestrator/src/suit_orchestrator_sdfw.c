/*
 * Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/logging/log.h>
#include <zephyr/logging/log_ctrl.h>
#include <zephyr/sys/reboot.h>
#include <suit_orchestrator.h>

#include <psa/crypto.h>
#include <stdbool.h>
#include <suit.h>
#include <suit_platform.h>
#include <suit_storage.h>
#include <suit_plat_mem_util.h>

LOG_MODULE_REGISTER(suit, CONFIG_SUIT_LOG_LEVEL);

static int load_keys(void)
{
	const uint8_t public_key[] = {
		0x04, /* POINT_CONVERSION_UNCOMPRESSED */
		0xed, 0xd0, 0x9e, 0xa5, 0xec, 0xe4, 0xed, 0xbe, 0x6c, 0x08, 0xe7, 0x47, 0x09,
		0x55, 0x9a, 0x38, 0x29, 0xc5, 0x31, 0x33, 0x22, 0x7b, 0xf4, 0xf0, 0x11, 0x6e,
		0x8c, 0x05, 0x2d, 0x02, 0x0e, 0x0e, 0xc3, 0xe0, 0xd8, 0x37, 0xf4, 0xc2, 0x6f,
		0xc1, 0x28, 0x80, 0x2f, 0x45, 0x38, 0x1a, 0x23, 0x2b, 0x6d, 0xd5, 0xda, 0x28,
		0x60, 0x00, 0x5d, 0xab, 0xe2, 0xa0, 0x83, 0xdb, 0xef, 0x38, 0x55, 0x13};
	psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
	psa_key_id_t public_key_id;

	/* Initialize PSA Crypto */
	psa_status = psa_crypto_init();
	if (psa_status != PSA_SUCCESS) {
		LOG_ERR("Failed to initialize PSA Crypto: %d", psa_status);
		return psa_status;
	}

	/* Add keys */
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_VERIFY_HASH);
	psa_set_key_algorithm(&key_attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));

	psa_status =
		psa_import_key(&key_attributes, public_key, sizeof(public_key), &public_key_id);
	if (psa_status != PSA_SUCCESS) {
		LOG_ERR("Failed to add public key: %d", psa_status);
		return psa_status;
	}
	LOG_DBG("Loaded key ID: 0x%x", public_key_id);

	return 0;
}

static int enter_emergency_recovery(void)
{
	LOG_WRN("TODO: Implement entering emergency recovery");
	return 0;
}

static int validate_update_candidate_address_and_size(const uint8_t *addr, size_t size)
{
	if (addr == NULL || addr == (void *)EMPTY_STORAGE_VALUE) {
		LOG_DBG("Invalid update candidate address: %p", addr);
		return EFAULT;
	}

	if (size == 0 || size == EMPTY_STORAGE_VALUE) {
		LOG_DBG("Invalid update candidate size: %d", size);
		return EFAULT;
	}

	return 0;
}

static bool update_candidate_applicable(void)
{
	LOG_WRN("TODO: Implement update candidate applicability check");
	return true;
}

static int validate_update_candidate_manifest(uint8_t *manifest_address, size_t manifest_size)
{
	int err = suit_process_sequence(manifest_address, manifest_size, SUIT_SEQ_PARSE);

	if (err) {
		LOG_ERR("Failed to validate update candidate manifest: %d", err);
		return err;
	}

	if (update_candidate_applicable()) {
		LOG_INF("Update candidate applicable");
	} else {
		LOG_INF("Update candidate not applicable");
		return ENOTSUP;
	}

	return 0;
}

static int update_path(void)
{
	const suit_plat_mreg_t *update_regions = NULL;
	size_t update_regions_len = 0;

	int err = suit_storage_update_cand_get(&update_regions, &update_regions_len);
	if ((err) || (update_regions_len < 1)) {
		LOG_ERR("Failed to get update candidate data: %d", err);
		return err;
	}

	LOG_DBG("Update candidate address: %p", update_regions[0].mem);
	LOG_DBG("Update candidate size: %d", update_regions[0].size);

	err = validate_update_candidate_address_and_size(update_regions[0].mem,
							 update_regions[0].size);
	if (err) {
		LOG_INF("Invalid update candidate: %d", err);

		err = suit_storage_update_cand_set(NULL, 0);
		if (err) {
			LOG_ERR("Failed to clear update candidate");
			return err;
		}

		LOG_DBG("Update candidate cleared");

		/* Do not return error if candidate is invalid - this can happen */
		return 0;
	}

	err = validate_update_candidate_manifest((uint8_t *)update_regions[0].mem,
						 update_regions[0].size);
	if (err) {
		LOG_ERR("Failed to validate update candidate manifest: %d", err);
		err = suit_storage_update_cand_set(NULL, 0);
		if (err) {
			LOG_ERR("Failed to clear update candidate");
			return err;
		}

		LOG_DBG("Update candidate cleared");
		/* Do not return error if candidate is invalid - this can happen */
		return 0;
	}
	LOG_DBG("Manifest validated");

	err = suit_process_sequence((uint8_t *)update_regions[0].mem, update_regions[0].size,
				    SUIT_SEQ_INSTALL);
	if (err) {
		LOG_ERR("Failed to execute suit-install: %d", err);
		return err;
	}

	LOG_DBG("suit-install successful");

	err = suit_storage_update_cand_set(NULL, 0);
	if (err) {
		LOG_ERR("Failed to clear update candidate");
		return err;
	}

	LOG_DBG("Update candidate cleared");

	if (IS_ENABLED(CONFIG_SUIT_UPDATE_REBOOT_ENABLED)) {
		LOG_INF("Reboot the system after update");

		if (IS_ENABLED(CONFIG_LOG)) {
			/* Flush all logs */
			log_panic();
		}

		sys_reboot(SYS_REBOOT_COLD);
	}

	return 0;
}

static int boot_envelope(const suit_manifest_class_id_t *class_id)
{
	uint8_t *installed_envelope_address = NULL;
	size_t installed_envelope_size = 0;

	int err = suit_storage_installed_envelope_get(class_id, &installed_envelope_address,
						      &installed_envelope_size);
	if (err) {
		LOG_ERR("Failed to get installed envelope data: %d", err);
		return enter_emergency_recovery();
	}
	if (installed_envelope_address == NULL) {
		LOG_ERR("Invalid envelope address");
		return enter_emergency_recovery();
	}
	if (installed_envelope_size == 0) {
		LOG_ERR("Invalid envelope size");
		return enter_emergency_recovery();
	}
	LOG_DBG("Found installed envelope");

	err = suit_process_sequence(installed_envelope_address, installed_envelope_size,
				    SUIT_SEQ_PARSE);
	if (err) {
		LOG_ERR("Failed to validate installed root manifest: %d", err);
		return enter_emergency_recovery();
	}
	LOG_DBG("Validated installed root manifest");

	unsigned int seq_num;
	err = suit_processor_get_manifest_metadata(
		installed_envelope_address, installed_envelope_size, true, NULL, NULL, &seq_num);
	if (err) {
		LOG_ERR("Failed to read manifest version and digest: %d", err);
		return enter_emergency_recovery();
	}
	LOG_INF("Booting from manifest version: 0x%x", seq_num);

	err = suit_process_sequence(installed_envelope_address, installed_envelope_size,
				    SUIT_SEQ_VALIDATE);
	if (err) {
		LOG_ERR("Failed to execute suit-validate: %d", err);
		return enter_emergency_recovery();
	}
	LOG_DBG("Processed suit-validate");

	err = suit_process_sequence(installed_envelope_address, installed_envelope_size,
				    SUIT_SEQ_LOAD);
	if (err) {
		if (err == SUIT_ERR_UNAVAILABLE_COMMAND_SEQ) {
			LOG_DBG("Command sequence suit-load not available - skip it");
			err = 0;
		} else {
			LOG_ERR("Failed to execute suit-load: %d", err);
			return enter_emergency_recovery();
		}
	}
	LOG_DBG("Processed suit-load");

	err = suit_process_sequence(installed_envelope_address, installed_envelope_size,
				    SUIT_SEQ_INVOKE);
	if (err) {
		LOG_ERR("Failed to execute suit-invoke: %d", err);
		return enter_emergency_recovery();
	}
	LOG_DBG("Processed suit-invoke");

	return 0;
}

static int boot_path(void)
{
#if CONFIG_SUIT_LEGACY_PLATFORM
#ifdef CONFIG_SOC_NRF54H20
	/* RFC4122 uuid5(nordic_vid, 'nRF54H20_sample_app') */
	const suit_manifest_class_id_t nordic_app_manifest_class_id = {
		{0x08, 0xc1, 0xb5, 0x99, 0x55, 0xe8, 0x5f, 0xbc, 0x9e, 0x76, 0x7b, 0xc2, 0x9c, 0xe1,
		 0xb0, 0x4d}};
#else  /* CONFIG_SOC_NRF54H20 */
	/* RFC4122 uuid5(nordic_vid, 'posix_sample_app') */
	const suit_manifest_class_id_t nordic_app_manifest_class_id = {
		{0x56, 0xdc, 0x9a, 0x14, 0x28, 0xd8, 0x52, 0xd3, 0xbd, 0x62, 0xe7, 0x7a, 0x08, 0xbc,
		 0x8b, 0x91}};
#endif /* CONFIG_SOC_NRF54H20 */

	return boot_envelope(&nordic_app_manifest_class_id);
#else  /* CONFIG_SUIT_LEGACY_PLATFORM */
	const suit_manifest_class_id_t *class_ids_to_boot[CONFIG_SUIT_STORAGE_N_ENVELOPES];
	size_t class_ids_to_boot_len = ARRAY_SIZE(class_ids_to_boot);

	int ret = mci_get_invoke_order((const suit_manifest_class_id_t **)&class_ids_to_boot,
				       &class_ids_to_boot_len);
	if (ret != 0) {
		LOG_ERR("Unable to get invoke order (%d)", ret);
		return ret;
	}

	for (size_t i = 0; i < class_ids_to_boot_len; i++) {
		ret = boot_envelope((const suit_manifest_class_id_t *)class_ids_to_boot[i]);
		if (ret != 0) {
			LOG_ERR("Booting %d manifest failed (%d)", i, ret);
		} else {
			LOG_DBG("Manifest %d booted", i);
		}
	}

	return ret;
#endif /* CONFIG_SUIT_LEGACY_PLATFORM */
}

int suit_orchestrator_init(void)
{
	const suit_manifest_class_id_t *supported_class_ids[CONFIG_SUIT_STORAGE_N_ENVELOPES];
	size_t supported_class_ids_len = ARRAY_SIZE(supported_class_ids);

	int err = suit_processor_init();
	if (err) {
		LOG_ERR("Failed to initialize suit processor: %d", err);
		return err;
	}

	err = load_keys();
	if (err) {
		LOG_ERR("Failed to load keys: %d", err);
		return err;
	}

	err = mci_get_supported_manifest_class_ids(
		(const suit_manifest_class_id_t **)&supported_class_ids, &supported_class_ids_len);
	if (err) {
		LOG_ERR("Failed to get list of supported manifest class IDs: %d", err);
		return err;
	}

	err = suit_storage_init(supported_class_ids, supported_class_ids_len);
	if (err) {
		LOG_ERR("Failed to init suit storage: %d", err);
		return err;
	}

	LOG_DBG("SUIT orchestrator init ok");
	return 0;
}

int suit_orchestrator_entry(void)
{
	const suit_plat_mreg_t *update_regions = NULL;
	size_t update_regions_len = 0;

	int err = suit_storage_update_cand_get(&update_regions, &update_regions_len);

	if ((err == 0) && (update_regions_len > 0)) {
		LOG_INF("Update path");
		return update_path();
	} else {
		LOG_INF("Boot path");
		return boot_path();
	}
}
