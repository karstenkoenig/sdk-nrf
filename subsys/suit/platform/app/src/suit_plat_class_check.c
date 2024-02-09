/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <suit_platform.h>

#include <suit_platform.h>
#include <suit_platform_internal.h>
#include <suit_plat_component_compatibility.h>
#include <suit_metadata.h>
#include <suit_service.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(suit_plat_class_check, CONFIG_SUIT_LOG_LEVEL);

static const suit_uuid_t *validate_and_get_uuid(struct zcbor_string *in_uuid)
{
	if ((in_uuid == NULL) || (in_uuid->value == NULL) ||
	    (in_uuid->len != sizeof(suit_uuid_t))) {
		return NULL;
	}

	return (const suit_uuid_t *)in_uuid->value;
}

static int supported_manifest_class_ids_get(const suit_manifest_class_id_t **class_id, size_t *out_size)
{
	static suit_ssf_manifest_class_info_t
		manifest_class_infos_list[CONFIG_MAX_NUMBER_OF_MANIFEST_CLASS_IDS];
	static size_t size = CONFIG_MAX_NUMBER_OF_MANIFEST_CLASS_IDS;
	static bool initialized = false;

	if (!initialized) {
		suit_ssf_err_t ret = suit_get_supported_manifest_class_info(manifest_class_infos_list, &size);
		if (ret != SUIT_PLAT_SUCCESS) {
			return ret;
		}
	}

	if (NULL == class_id || NULL == out_size) {
		return SUIT_PLAT_ERR_INVAL;
	}

	if (*out_size < size) {
		return SUIT_PLAT_ERR_NOMEM;
	}

	for (size_t i = 0; i < size; i++) {
		class_id[i] = &manifest_class_infos_list[i].class_id;
	}

	*out_size = size;

	return SUIT_PLAT_SUCCESS;
}

int suit_plat_check_cid(suit_component_t component_handle, struct zcbor_string *cid_uuid)
{
	const suit_manifest_class_id_t
		*manifest_class_ids_list[CONFIG_MAX_NUMBER_OF_MANIFEST_CLASS_IDS] = {NULL};
	size_t size = CONFIG_MAX_NUMBER_OF_MANIFEST_CLASS_IDS;
	struct zcbor_string *component_id;
	const suit_uuid_t *cid = validate_and_get_uuid(cid_uuid);

	if (cid == NULL) {
		LOG_ERR("Invalid argument");
		return SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
	}

	int ret = supported_manifest_class_ids_get(manifest_class_ids_list, &size);

	if (ret != SUIT_PLAT_SUCCESS) {
		return SUIT_ERR_CRASH;
	}

	/* Get component ID from component_handle */
	if (suit_plat_component_id_get(component_handle, &component_id) != SUIT_SUCCESS) {
		return SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
	}

	for (size_t i = 0; i < size; i++) {
		if ((suit_plat_component_compatibility_check(manifest_class_ids_list[i],
							     component_id) == SUIT_SUCCESS) &&
		    (suit_metadata_uuid_compare(cid, manifest_class_ids_list[i]) ==
		     SUIT_PLAT_SUCCESS)) {
			return SUIT_SUCCESS;
		}
	}

	return SUIT_FAIL_CONDITION;
}

int suit_plat_check_vid(suit_component_t component_handle, struct zcbor_string *vid_uuid)
{
    	const suit_manifest_class_id_t
		*manifest_class_ids_list[CONFIG_MAX_NUMBER_OF_MANIFEST_CLASS_IDS] = {NULL};
	size_t size = CONFIG_MAX_NUMBER_OF_MANIFEST_CLASS_IDS;
	struct zcbor_string *component_id;
	suit_uuid_t vendor_id;
	const suit_uuid_t *vid = validate_and_get_uuid(vid_uuid);

	if (vid == NULL) {
		LOG_ERR("Invalid argument");
		return SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
	}

	int ret = supported_manifest_class_ids_get(manifest_class_ids_list, &size);

	if (ret != SUIT_PLAT_SUCCESS) {
		return SUIT_ERR_CRASH;
	}

	/* Get component ID from component_handle */
	if (suit_plat_component_id_get(component_handle, &component_id) != SUIT_SUCCESS) {
		return SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
	}

	for (size_t i = 0; i < size; i++) {
		if ((suit_plat_component_compatibility_check(manifest_class_ids_list[i],
							     component_id) == SUIT_SUCCESS) &&
		    (suit_get_vendor_id_for_manifest_class_id(manifest_class_ids_list[i], &vendor_id) ==
		     SUIT_PLAT_SUCCESS) &&
		    (suit_metadata_uuid_compare(vid, &vendor_id) == SUIT_PLAT_SUCCESS)) {
			return SUIT_SUCCESS;
		}
	}

	return SUIT_FAIL_CONDITION;
}

int suit_plat_check_did(suit_component_t component_handle, struct zcbor_string *did_uuid)
{
	return SUIT_ERR_UNSUPPORTED_COMMAND;
}
