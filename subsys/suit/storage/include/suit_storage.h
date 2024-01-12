/*
 * Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/** @file
 * @brief SUIT storage module.
 *
 * @details This module is responsible for providing access to installed manifests,
 *          allows to install them as well as read Manifest Provisioning Information
 *          and manipulate Non-volatile variables accessible by the OEM manifests.
 */

#ifndef SUIT_STORAGE_H__
#define SUIT_STORAGE_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <suit_metadata.h>
#include <suit_mreg.h>
#include <suit_plat_err.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize the SUIT storage.
 *
 * @retval SUIT_PLAT_SUCCESS           if module is successfully initialized.
 * @retval SUIT_PLAT_ERR_HW_NOT_READY  if NVM controller is unavailable.
 */
suit_plat_err_t suit_storage_init(void);

/**
 * @brief Get the memory regions, containing update candidate.
 *
 * @param[out]  regions  List of update candidate memory regions (envelope, caches).
 *                       By convention, the first region holds the SUIT envelope.
 * @param[out]  len      Length of the memory regions list.
 *
 * @retval SUIT_PLAT_SUCCESS        if pointer to the update candidate info successfully returned.
 * @retval SUIT_PLAT_ERR_INVAL      if one of the input arguments is invalid (i.e. NULL).
 * @retval SUIT_PLAT_ERR_SIZE       if update candidate area has incorrect size.
 * @retval SUIT_PLAT_ERR_NOT_FOUND  if update candidate is not set.
 */
suit_plat_err_t suit_storage_update_cand_get(const suit_plat_mreg_t **regions, size_t *len);

/**
 * @brief Save the information about update candidate.
 *
 * @param[in]  regions  List of update candidate memory regions (envelope, caches).
 *                      By convention, the first region holds the SUIT envelope.
 * @param[in]  len      Length of the memory regions list.
 *
 * @retval SUIT_PLAT_SUCCESS           if update candidate info successfully saved.
 * @retval SUIT_PLAT_ERR_INVAL         if one of the input arguments is invalid (i.e. NULL).
 * @retval SUIT_PLAT_ERR_SIZE          if update candidate area has incorrect size or the number
 *                                     of update regions is too big.
 * @retval SUIT_PLAT_ERR_HW_NOT_READY  if NVM controller is unavailable.
 * @retval SUIT_PLAT_ERR_IO            if unable to change NVM contents.
 */
suit_plat_err_t suit_storage_update_cand_set(suit_plat_mreg_t *regions, size_t len);

/**
 * @brief Get the address and size of the envelope, stored inside the SUIT partition.
 *
 * @param[in]   id     Class ID of the manifest inside the envelope.
 * @param[out]  addr   SUIT envelope address.
 * @param[out]  size   SUIT envelope size.
 *
 * @retval SUIT_PLAT_SUCCESS            if the envelope was successfully returned.
 * @retval SUIT_PLAT_ERR_CBOR_DECODING  if failed to decode envelope.
 */
suit_plat_err_t suit_storage_installed_envelope_get(const suit_manifest_class_id_t *id,
						    uint8_t **addr, size_t *size);

/**
 * @brief Install the authentication block and manifest of the envelope inside the SUIT storage.
 *
 * @note This API removes all severable elements of the SUIT envelope, such as integrated
 *       payloads, text fields, etc.
 *
 * @param[in]  id     Class ID of the manifest inside the envelope.
 * @param[in]  addr   SUIT envelope address.
 * @param[in]  size   SUIT envelope size.
 *
 * @retval SUIT_PLAT_SUCCESS              if the envelope was successfully insatlled.
 * @retval SUIT_PLAT_ERR_CBOR_DECODING    if failed to decode input or encode severed envelope.
 * @retval SUIT_PLAT_ERR_INVAL            if one of the input arguments is invalid
 *                                        (i.e. NULL, buffer length, incorrect class ID).
 * @retval SUIT_PLAT_ERR_IO               if unable to change NVM contents.
 * @retval SUIT_PLAT_ERR_HW_NOT_READY     if NVM controller is unavailable.
 * @retval SUIT_PLAT_ERR_INCORRECT_STATE  if the previous installation was unexpectedly aborted.
 */
suit_plat_err_t suit_storage_install_envelope(const suit_manifest_class_id_t *id, uint8_t *addr,
					      size_t size);

#ifdef __cplusplus
}
#endif

#endif /* SUIT_STORAGE_H__ */
