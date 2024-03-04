/*
 * Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/logging/log.h>
#include <zephyr/logging/log_ctrl.h>
#include <zephyr/sys/reboot.h>
#include <suit_orchestrator.h>

#include <stdbool.h>
#include <suit.h>
#include <suit_platform.h>
#include <suit_storage.h>
#include <suit_plat_mem_util.h>
#include <suit_plat_decode_util.h>
#include <suit_mci.h>
#include <suit_plat_digest_cache.h>
#include "suit_plat_err.h"
#include <suit_execution_mode.h>
#include <dfu_cache.h>

LOG_MODULE_REGISTER(suit_orchestrator, CONFIG_SUIT_LOG_LEVEL);

#define SUIT_PROCESSOR_ERR_TO_ZEPHYR_ERR(err) ((err) == SUIT_SUCCESS ? 0 : -EACCES)

#define SUIT_PLAT_ERR_TO_ZEPHYR_ERR(err) ((err) == SUIT_PLAT_SUCCESS ? 0 : -EACCES)

static int enter_emergency_recovery(void)
{
	LOG_WRN("TODO: Implement entering emergency recovery");
	return 0;
}

static int validate_update_candidate_address_and_size(const uint8_t *addr, size_t size)
{
	if (addr == NULL || addr == (void *)EMPTY_STORAGE_VALUE) {
		LOG_DBG("Invalid update candidate address: %p", (void *)addr);
		return -EFAULT;
	}

	if (size == 0 || size == EMPTY_STORAGE_VALUE) {
		LOG_DBG("Invalid update candidate size: %d", size);
		return -EFAULT;
	}

	return 0;
}

static bool update_candidate_applicable(void)
{
	LOG_WRN("TODO: Implement update candidate applicability check");
	return true;
}

static int initialize_dfu_cache(const suit_plat_mreg_t *update_regions, size_t update_regions_len)
{
	if (update_regions == NULL || update_regions_len < 1) {
		return -EINVAL;
	}

	struct dfu_cache cache = {0};

	cache.pools_count = update_regions_len - 1;

	for (size_t i = 1; i < update_regions_len; i++) {
		cache.pools[i - 1].address = (uint8_t *)update_regions[i].mem;
		cache.pools[i - 1].size = update_regions[i].size;
	}

	return SUIT_PROCESSOR_ERR_TO_ZEPHYR_ERR(suit_dfu_cache_initialize(&cache));
}

static int validate_update_candidate_manifest(uint8_t *manifest_address, size_t manifest_size)
{
	struct zcbor_string manifest_component_id = {
		.value = NULL,
		.len = 0,
	};
	suit_manifest_class_id_t *manifest_class_id = NULL;
	suit_independent_updateability_policy_t policy;

	int err = suit_processor_get_manifest_metadata(manifest_address, manifest_size, true,
						       &manifest_component_id, NULL, NULL, NULL);
	if (err != SUIT_SUCCESS) {
		LOG_ERR("Unable to read update candidate manifest metadata: %d", err);
		return SUIT_PROCESSOR_ERR_TO_ZEPHYR_ERR(err);
	}

	err = suit_plat_decode_manifest_class_id(&manifest_component_id, &manifest_class_id);
	if (err != SUIT_PLAT_SUCCESS) {
		LOG_ERR("Failed to parse update candidate manifest class ID: %d", err);
		return SUIT_PROCESSOR_ERR_TO_ZEPHYR_ERR(SUIT_ERR_MANIFEST_VALIDATION);
	}

	err = suit_mci_independent_update_policy_get(manifest_class_id, &policy);
	if (err != SUIT_PLAT_SUCCESS) {
		LOG_ERR("Failed to read independent updateability policy: %d", err);
		return SUIT_PROCESSOR_ERR_TO_ZEPHYR_ERR(SUIT_ERR_UNSUPPORTED_COMPONENT_ID);
	}

	if (policy != SUIT_INDEPENDENT_UPDATE_ALLOWED) {
		LOG_ERR("Independent updates of the provided update candidate denied.");
		return SUIT_PROCESSOR_ERR_TO_ZEPHYR_ERR(SUIT_ERR_AUTHENTICATION);
	}

	err = suit_process_sequence(manifest_address, manifest_size, SUIT_SEQ_PARSE);

	if (err != SUIT_SUCCESS) {
		LOG_ERR("Failed to validate update candidate manifest: %d", err);
		return SUIT_PROCESSOR_ERR_TO_ZEPHYR_ERR(err);
	}

	if (update_candidate_applicable()) {
		LOG_INF("Update candidate applicable");
	} else {
		LOG_INF("Update candidate not applicable");
		return -ENOTSUP;
	}

	return 0;
}

static int clear_update_candidate(void)
{
	int err = 0;

	err = suit_storage_update_cand_set(NULL, 0);
	if (err != SUIT_PLAT_SUCCESS) {
		LOG_ERR("Failed to clear update candidate: %d", err);
		return SUIT_PLAT_ERR_TO_ZEPHYR_ERR(err);
	}

	LOG_DBG("Update candidate cleared");

	return 0;
}

static int update_path(void)
{
	const suit_plat_mreg_t *update_regions = NULL;
	size_t update_regions_len = 0;

	int err = suit_storage_update_cand_get(&update_regions, &update_regions_len);
	if ((err != SUIT_PLAT_SUCCESS) || (update_regions_len < 1)) {
		LOG_ERR("Failed to get update candidate data: %d", err);
		return SUIT_PLAT_ERR_TO_ZEPHYR_ERR(err);
	}

	LOG_DBG("Update candidate address: %p", (void *)update_regions[0].mem);
	LOG_DBG("Update candidate size: %d", update_regions[0].size);

	err = validate_update_candidate_address_and_size(update_regions[0].mem,
							 update_regions[0].size);
	if (err != 0) {
		LOG_INF("Invalid update candidate: %d", err);
		return clear_update_candidate();
	}

	err = initialize_dfu_cache(update_regions, update_regions_len);

	if (err != 0) {
		LOG_ERR("Failed to initialize DFU cache pools: %d", err);
		return clear_update_candidate();
	}

	err = validate_update_candidate_manifest((uint8_t *)update_regions[0].mem,
						 update_regions[0].size);
	if (err != 0) {
		LOG_ERR("Failed to validate update candidate manifest: %d", err);
		return clear_update_candidate();
	}
	LOG_DBG("Manifest validated");

	err = suit_process_sequence((uint8_t *)update_regions[0].mem, update_regions[0].size,
				    SUIT_SEQ_INSTALL);
	if (err != SUIT_SUCCESS) {
		LOG_ERR("Failed to execute suit-install: %d", err);
		return SUIT_PLAT_ERR_TO_ZEPHYR_ERR(err);
	}

	LOG_DBG("suit-install successful");

	err = clear_update_candidate();
	if (err != 0) {
		return err;
	}

	if (IS_ENABLED(CONFIG_SUIT_UPDATE_REBOOT_ENABLED)) {
		LOG_INF("Reboot the system after update");

		LOG_PANIC();

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
	if (err != SUIT_PLAT_SUCCESS) {
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
	if (err != SUIT_SUCCESS) {
		LOG_ERR("Failed to validate installed root manifest: %d", err);
		return enter_emergency_recovery();
	}
	LOG_DBG("Validated installed root manifest");

	unsigned int seq_num;
	err = suit_processor_get_manifest_metadata(installed_envelope_address,
						   installed_envelope_size, true, NULL, NULL, NULL,
						   &seq_num);
	if (err != SUIT_SUCCESS) {
		LOG_ERR("Failed to read manifest version and digest: %d", err);
		return enter_emergency_recovery();
	}
	LOG_INF("Booting from manifest version: 0x%x", seq_num);

	err = suit_process_sequence(installed_envelope_address, installed_envelope_size,
				    SUIT_SEQ_VALIDATE);
	if (err != SUIT_SUCCESS) {
		LOG_ERR("Failed to execute suit-validate: %d", err);
		return enter_emergency_recovery();
	}

	LOG_DBG("Processed suit-validate");

	err = suit_process_sequence(installed_envelope_address, installed_envelope_size,
				    SUIT_SEQ_LOAD);
	if (err != SUIT_SUCCESS) {
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
	if (err != SUIT_SUCCESS) {
		LOG_ERR("Failed to execute suit-invoke: %d", err);
		return enter_emergency_recovery();
	}
	LOG_DBG("Processed suit-invoke");

	return 0;
}

static int boot_path(void)
{
	const suit_manifest_class_id_t *class_ids_to_boot[CONFIG_SUIT_STORAGE_N_ENVELOPES] = {NULL};
	size_t class_ids_to_boot_len = ARRAY_SIZE(class_ids_to_boot);
	int ret = 0;
	mci_err_t mci_ret = suit_mci_invoke_order_get(
		(const suit_manifest_class_id_t **)&class_ids_to_boot, &class_ids_to_boot_len);
	if (mci_ret != SUIT_PLAT_SUCCESS) {
		LOG_ERR("Unable to get invoke order (MCI err: %d)", mci_ret);
		return SUIT_PLAT_ERR_TO_ZEPHYR_ERR(mci_ret);
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
}

int suit_orchestrator_init(void)
{
	int err = suit_processor_init();
	if (err != SUIT_SUCCESS) {
		LOG_ERR("Failed to initialize suit processor: %d", err);
		return SUIT_PROCESSOR_ERR_TO_ZEPHYR_ERR(err);
	}

	suit_plat_err_t plat_err = suit_storage_init();
	if (plat_err != SUIT_PLAT_SUCCESS) {
		LOG_ERR("Failed to init suit storage: %d", plat_err);
		return SUIT_PLAT_ERR_TO_ZEPHYR_ERR(plat_err);
	}

	mci_err_t mci_err = suit_mci_init();
	if (mci_err != SUIT_PLAT_SUCCESS) {
		LOG_ERR("Failed to init MCI: %d", mci_err);
		return SUIT_PLAT_ERR_TO_ZEPHYR_ERR(mci_err);
	}

	LOG_DBG("SUIT orchestrator init ok");
	return 0;
}

int suit_orchestrator_entry(void)
{
	const suit_plat_mreg_t *update_regions = NULL;
	size_t update_regions_len = 0;

	suit_plat_err_t err = suit_storage_update_cand_get(&update_regions, &update_regions_len);

#if CONFIG_SUIT_DIGEST_CACHE
	if (suit_plat_digest_cache_remove_all() != SUIT_SUCCESS) {
		return SUIT_PROCESSOR_ERR_TO_ZEPHYR_ERR(SUIT_ERR_CRASH);
	}
#endif

	if ((err == SUIT_PLAT_SUCCESS) && (update_regions_len > 0)) {
		LOG_INF("Update path");

		err = suit_execution_mode_set(EXECUTION_MODE_INSTALL);
		if (err != SUIT_PLAT_SUCCESS) {
			LOG_ERR("Setting execution mode failed: %i", err);
			return SUIT_PLAT_ERR_TO_ZEPHYR_ERR(err);
		}

		return update_path();
	}

	LOG_INF("Boot path");
	err = suit_execution_mode_set(EXECUTION_MODE_INVOKE);
	if (err != SUIT_PLAT_SUCCESS) {
		LOG_ERR("Setting execution mode failed: %i", err);
		return SUIT_PLAT_ERR_TO_ZEPHYR_ERR(err);
	}

	suit_plat_err_t ret = boot_path();

	err = suit_execution_mode_set(EXECUTION_MODE_POST_INVOKE);
	if (err != SUIT_PLAT_SUCCESS) {
		LOG_ERR("Setting execution mode failed: %i", err);
		return SUIT_PLAT_ERR_TO_ZEPHYR_ERR(err);
	}

#ifdef CONFIG_SUIT_LOG_SECDOM_VERSION
	LOG_INF("Secdom version: %s", CONFIG_SUIT_SECDOM_VERSION);
#endif /* CONFIG_SUIT_LOG_SECDOM_VERSION */
	return ret;
}
