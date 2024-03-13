/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <suit_platform.h>
#include <suit_plat_decode_util.h>
#include <suit_plat_component_compatibility.h>

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(suit_plat_authenticate, CONFIG_SUIT_LOG_LEVEL);

int suit_plat_authorize_component_id(struct zcbor_string *manifest_component_id,
				     struct zcbor_string *component_id)
{
	suit_manifest_class_id_t *class_id;

	if ((manifest_component_id == NULL) || (component_id == NULL) ||
	    (manifest_component_id->value == NULL) || (manifest_component_id->len == 0) ||
	    (component_id->value == NULL) || (component_id->len == 0)) {
		return SUIT_ERR_DECODING;
	}

	/* Check if component ID is a manifest class */
	if (suit_plat_decode_manifest_class_id(manifest_component_id, &class_id)
	    != SUIT_PLAT_SUCCESS) {
		LOG_ERR("Component ID is not a manifest class");
		return SUIT_ERR_UNAUTHORIZED_COMPONENT;
	}

	return suit_plat_component_compatibility_check(class_id, component_id);
}
