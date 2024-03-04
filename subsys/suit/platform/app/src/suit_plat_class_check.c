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

static int supported_manifest_class_infos_get(const suit_ssf_manifest_class_info_t **class_info,
					      size_t *out_size)
{
	static suit_ssf_manifest_class_info_t
		manifest_class_infos_list[CONFIG_MAX_NUMBER_OF_MANIFEST_CLASS_IDS];
	static size_t size = CONFIG_MAX_NUMBER_OF_MANIFEST_CLASS_IDS;
	static bool initialized = false;

	suit_manifest_role_t manifest_roles_list[CONFIG_MAX_NUMBER_OF_MANIFEST_CLASS_IDS];

	if (!initialized) {
		suit_ssf_err_t ret = suit_get_supported_manifest_roles(manifest_roles_list, &size);
		if (ret != SUIT_PLAT_SUCCESS) {
			return ret;
		}

		for (size_t i = 0; i < size; i++) {
			ret = suit_get_supported_manifest_info(manifest_roles_list[i],
							       &manifest_class_infos_list[i]);

			if (ret != SUIT_PLAT_SUCCESS) {
				return ret;
			}
		}

		initialized = true;
	}

	if (NULL == class_info || NULL == out_size) {
		return SUIT_PLAT_ERR_INVAL;
	}

	if (*out_size < size) {
		return SUIT_PLAT_ERR_NOMEM;
	}

	for (size_t i = 0; i < size; i++) {
		class_info[i] = &manifest_class_infos_list[i];
	}

	*out_size = size;

	return SUIT_PLAT_SUCCESS;
}

/**
 * @brief Find a role for a manifest with given class ID.
 *
 * @param[in]   class_id  Manifest class ID.
 * @param[out]  role      Pointer to the role variable.
 *
 * @retval SUIT_PLAT_SUCCESS        on success
 * @retval SUIT_PLAT_ERR_INVAL      invalid parameter, i.e. null pointer
 * @retval SUIT_PLAT_ERR_CRASH      unable to fetch manifest provisioning information
 * @retval SUIT_PLAT_ERR_NOT_FOUND  manifest with given manifest class ID not configured.
 */
static int manifest_role_get(const suit_manifest_class_id_t *class_id, suit_manifest_role_t *role)
{
	const suit_ssf_manifest_class_info_t
		*manifest_class_infos_list[CONFIG_MAX_NUMBER_OF_MANIFEST_CLASS_IDS] = {NULL};
	size_t size = CONFIG_MAX_NUMBER_OF_MANIFEST_CLASS_IDS;

	if (role == NULL) {
		return SUIT_PLAT_ERR_INVAL;
	}

	int ret = supported_manifest_class_infos_get(manifest_class_infos_list, &size);

	if (ret != SUIT_PLAT_SUCCESS) {
		return SUIT_ERR_CRASH;
	}

	for (size_t i = 0; i < size; i++) {
		if (suit_metadata_uuid_compare(class_id, &manifest_class_infos_list[i]->class_id) ==
		    SUIT_PLAT_SUCCESS) {
			*role = manifest_class_infos_list[i]->role;
			return SUIT_SUCCESS;
		}
	}

	*role = SUIT_MANIFEST_UNKNOWN;

	return SUIT_PLAT_ERR_NOT_FOUND;
}

int suit_plat_check_cid(suit_component_t component_handle, struct zcbor_string *cid_uuid)
{
	const suit_ssf_manifest_class_info_t
		*manifest_class_infos_list[CONFIG_MAX_NUMBER_OF_MANIFEST_CLASS_IDS] = {NULL};
	size_t size = CONFIG_MAX_NUMBER_OF_MANIFEST_CLASS_IDS;
	struct zcbor_string *component_id;
	const suit_uuid_t *cid = validate_and_get_uuid(cid_uuid);

	if (cid == NULL) {
		LOG_ERR("Invalid argument");
		return SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
	}

	int ret = supported_manifest_class_infos_get(manifest_class_infos_list, &size);

	if (ret != SUIT_PLAT_SUCCESS) {
		return SUIT_ERR_CRASH;
	}

	/* Get component ID from component_handle */
	if (suit_plat_component_id_get(component_handle, &component_id) != SUIT_SUCCESS) {
		return SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
	}

	for (size_t i = 0; i < size; i++) {
		if ((suit_plat_component_compatibility_check(
			     &manifest_class_infos_list[i]->class_id, component_id) ==
		     SUIT_SUCCESS) &&
		    (suit_metadata_uuid_compare(cid, &manifest_class_infos_list[i]->class_id) ==
		     SUIT_PLAT_SUCCESS)) {
			return SUIT_SUCCESS;
		}
	}

	return SUIT_FAIL_CONDITION;
}

int suit_plat_check_vid(suit_component_t component_handle, struct zcbor_string *vid_uuid)
{
	const suit_ssf_manifest_class_info_t
		*manifest_class_infos_list[CONFIG_MAX_NUMBER_OF_MANIFEST_CLASS_IDS] = {NULL};
	size_t size = CONFIG_MAX_NUMBER_OF_MANIFEST_CLASS_IDS;
	struct zcbor_string *component_id;
	const suit_uuid_t *vid = validate_and_get_uuid(vid_uuid);

	if (vid == NULL) {
		LOG_ERR("Invalid argument");
		return SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
	}

	int ret = supported_manifest_class_infos_get(manifest_class_infos_list, &size);

	if (ret != SUIT_PLAT_SUCCESS) {
		return SUIT_ERR_CRASH;
	}

	/* Get component ID from component_handle */
	if (suit_plat_component_id_get(component_handle, &component_id) != SUIT_SUCCESS) {
		return SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
	}

	for (size_t i = 0; i < size; i++) {
		if ((suit_plat_component_compatibility_check(
			     &manifest_class_infos_list[i]->class_id, component_id) ==
		     SUIT_SUCCESS) &&
		    (suit_metadata_uuid_compare(vid, &manifest_class_infos_list[i]->vendor_id) ==
		     SUIT_PLAT_SUCCESS)) {
			return SUIT_SUCCESS;
		}
	}

	return SUIT_FAIL_CONDITION;
}

int suit_plat_check_did(suit_component_t component_handle, struct zcbor_string *did_uuid)
{
	return SUIT_ERR_UNSUPPORTED_COMMAND;
}

int suit_plat_authorize_process_dependency(struct zcbor_string *parent_component_id,
					   struct zcbor_string *child_component_id,
					   enum suit_command_sequence seq_name)
{
	suit_manifest_class_id_t *parent_class_id = NULL;
	suit_manifest_class_id_t *child_class_id = NULL;
	suit_manifest_role_t parent_role = SUIT_MANIFEST_UNKNOWN;
	suit_manifest_role_t child_role = SUIT_MANIFEST_UNKNOWN;

	suit_plat_err_t err =
		suit_plat_decode_manifest_class_id(parent_component_id, &parent_class_id);
	if (err != SUIT_PLAT_SUCCESS) {
		LOG_ERR("Unable to parse parent manifest class ID (err: %i)", err);
		return SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
	}

	err = suit_plat_decode_manifest_class_id(child_component_id, &child_class_id);
	if (err != SUIT_PLAT_SUCCESS) {
		LOG_ERR("Unable to parse child manifest class ID (err: %i)", err);
		return SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
	}

	int ret = manifest_role_get(parent_class_id, &parent_role);
	if (ret != SUIT_SUCCESS) {
		LOG_ERR("Unable to find parent manifest role (err: %i)", err);
		return ret;
	}

	ret = manifest_role_get(child_class_id, &child_role);
	if (ret != SUIT_SUCCESS) {
		LOG_ERR("Unable to find child manifest role (err: %i)", err);
		return ret;
	}

	/* Nordic top is allowed to fetch SCFW and SDFW manifests. */
	if ((parent_role == SUIT_MANIFEST_SEC_TOP) &&
	    ((child_role == SUIT_MANIFEST_SEC_SYSCTRL) || (child_role == SUIT_MANIFEST_SEC_SDFW))) {
		return SUIT_SUCCESS;
	}

	/* Application root is allowed to fetch any local as well as Nordic top manifest. */
	if ((parent_role == SUIT_MANIFEST_APP_ROOT) &&
	    (((child_role >= SUIT_MANIFEST_APP_LOCAL_1) &&
	      (child_role <= SUIT_MANIFEST_APP_LOCAL_3)) ||
	     ((child_role >= SUIT_MANIFEST_RAD_LOCAL_1) &&
	      (child_role <= SUIT_MANIFEST_RAD_LOCAL_2)) ||
	     (child_role == SUIT_MANIFEST_SEC_TOP))) {
		return SUIT_SUCCESS;
	}

	/* Application recovery may fetch only the radio recovery manifest. */
	if ((parent_role == SUIT_MANIFEST_APP_RECOVERY) &&
	    (child_role == SUIT_MANIFEST_RAD_RECOVERY)) {
		return SUIT_SUCCESS;
	}

	LOG_INF("Manifest dependency link unauthorized for sequence %d (err: %i)", seq_name, ret);

	return SUIT_ERR_AUTHENTICATION;
}
