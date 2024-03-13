/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef SUIT_PLAT_MANIFEST_INFO_INTERNAL_H__
#define SUIT_PLAT_MANIFEST_INFO_INTERNAL_H__

#include <suit_metadata.h>
#include <zcbor_common.h>

#ifdef __cplusplus
extern "C" {
#endif

int suit_plat_supported_manifest_class_infos_get(suit_manifest_class_info_t *class_info,
						 size_t *size);

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
int suit_plat_manifest_role_get(const suit_manifest_class_id_t *class_id,
				suit_manifest_role_t *role);

#ifdef __cplusplus
}
#endif

#endif /* SUIT_PLAT_MANIFEST_INFO_INTERNAL_H__ */
