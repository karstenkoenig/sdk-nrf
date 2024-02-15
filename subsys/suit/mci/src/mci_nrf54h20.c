/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */
#include <suit_mci.h>
#include <drivers/nrfx_common.h>
#include <suit_storage_mpi.h>
#include <suit_execution_mode.h>
#include <lcs.h>

#define MANIFEST_PUBKEY_NRF_TOP_GEN0		0x4000BB00
#define MANIFEST_PUBKEY_SYSCTRL_GEN0		0x40082100
#define MANIFEST_PUBKEY_OEM_ROOT_GEN0		0x4000AA00
#define MANIFEST_PUBKEY_APPLICATION_GEN0	0x40022100
#define MANIFEST_PUBKEY_RADIO_GEN0			0x40032100
#define MANIFEST_PUBKEY_GEN_RANGE 			2

mci_err_t suit_mci_supported_manifest_class_ids_get(suit_manifest_class_info_t *class_info,
						    size_t *size)
{
	if (NULL == class_info || NULL == size) {
		return SUIT_PLAT_ERR_INVAL;
	}

	return suit_storage_mpi_class_ids_get(class_info, size);
}

mci_err_t suit_mci_invoke_order_get(const suit_manifest_class_id_t **class_id, size_t *size)
{
	if (NULL == class_id || NULL == size) {
		return SUIT_PLAT_ERR_INVAL;
	}
	size_t output_max_size = *size;
	size_t output_size = 2; /* Current number of elements on invocation order list */

	if (output_size > output_max_size) {
		return SUIT_PLAT_ERR_SIZE;
	}

	suit_execution_mode_t execution_mode = suit_execution_mode_get();

	switch (execution_mode) {
	case EXECUTION_MODE_INVOKE:
		if(SUIT_PLAT_SUCCESS != suit_storage_mpi_class_get(SUIT_MANIFEST_SEC_TOP, &class_id[0])) {
			return SUIT_PLAT_ERR_NOT_FOUND;
		}
 
		if(SUIT_PLAT_SUCCESS != suit_storage_mpi_class_get(SUIT_MANIFEST_APP_ROOT, &class_id[1])) {
			return SUIT_PLAT_ERR_NOT_FOUND;
		}
		break;

	case EXECUTION_MODE_INVOKE_RECOVERY:
		if(SUIT_PLAT_SUCCESS != suit_storage_mpi_class_get(SUIT_MANIFEST_SEC_TOP, &class_id[0])) {
			return SUIT_PLAT_ERR_NOT_FOUND;
		}

		if(SUIT_PLAT_SUCCESS != suit_storage_mpi_class_get(SUIT_MANIFEST_APP_RECOVERY, &class_id[1])) {
			return SUIT_PLAT_ERR_NOT_FOUND;
		}
		break;

	default:
		return SUIT_PLAT_ERR_INCORRECT_STATE;
	}

	*size = output_size;
	return SUIT_PLAT_SUCCESS;
}

mci_err_t suit_mci_downgrade_prevention_policy_get(const suit_manifest_class_id_t *class_id,
						   downgrade_prevention_policy_t *policy)
{
	if (NULL == class_id || NULL == policy) {
		return SUIT_PLAT_ERR_INVAL;
	}

	suit_storage_mpi_t *mpi;

	if (SUIT_PLAT_SUCCESS != suit_storage_mpi_get(class_id, &mpi)) {
		return MCI_ERR_MANIFESTCLASSID;
	}

	if (SUIT_MPI_DOWNGRADE_PREVENTION_DISABLED == mpi->downgrade_prevention_policy) {
		*policy = DOWNGRADE_PREVENTION_DISABLED;
	} else if (SUIT_MPI_DOWNGRADE_PREVENTION_ENABLED == mpi->downgrade_prevention_policy) {
		*policy = DOWNGRADE_PREVENTION_ENABLED;
	} else {
		return SUIT_PLAT_ERR_OUT_OF_BOUNDS;
	}

	return SUIT_PLAT_SUCCESS;
}

mci_err_t suit_mci_manifest_class_id_validate(const suit_manifest_class_id_t *class_id)
{
	if (NULL == class_id) {
		return SUIT_PLAT_ERR_INVAL;
	}

	suit_manifest_role_t role = SUIT_MANIFEST_UNKNOWN;
	suit_plat_err_t ret = suit_storage_mpi_role_get(class_id, &role);

	if (SUIT_PLAT_SUCCESS != ret) {
		return MCI_ERR_MANIFESTCLASSID;
	}

	return SUIT_PLAT_SUCCESS;
}

mci_err_t suit_mci_signing_key_id_validate(const suit_manifest_class_id_t *class_id,
					   uint32_t key_id)
{
	if (NULL == class_id) {
		return SUIT_PLAT_ERR_INVAL;
	}

	suit_manifest_role_t role = SUIT_MANIFEST_UNKNOWN;
	if (SUIT_PLAT_SUCCESS != suit_storage_mpi_role_get(class_id, &role)) {
		return MCI_ERR_MANIFESTCLASSID;
	}

#ifdef CONFIG_SDFW_LCS
	/* Read the domain-specific LCS value. */
	enum lcs current_lcs = LCS_DISCARDED;
	switch (role) {
	case SUIT_MANIFEST_SEC_TOP:
	case SUIT_MANIFEST_SEC_SDFW:
	case SUIT_MANIFEST_SEC_SYSCTRL:
		current_lcs = lcs_get(LCS_DOMAIN_ID_SECURE);
		break;

	case SUIT_MANIFEST_APP_ROOT:
	case SUIT_MANIFEST_APP_RECOVERY:
	case SUIT_MANIFEST_APP_LOCAL_1:
	case SUIT_MANIFEST_APP_LOCAL_2:
	case SUIT_MANIFEST_APP_LOCAL_3:
		current_lcs = lcs_get(LCS_DOMAIN_ID_APPLICATION);
		break;

	case SUIT_MANIFEST_RAD_RECOVERY:
	case SUIT_MANIFEST_RAD_LOCAL_1:
	case SUIT_MANIFEST_RAD_LOCAL_2:
		current_lcs = lcs_get(LCS_DOMAIN_ID_RADIOCORE);
		break;

	default:
		break;
	}
#endif /* CONFIG_SDFW_LCS */

	if (key_id == 0) {
#ifdef CONFIG_SDFW_LCS
		/* Check if LCS requires to skip signature check.
		 * Temporarily skip signature verification in LCS_ROT and LCS_ROT_DEBUG.
		 * Condition to be described and implemented in NCSDK-25998.
		 */
		if ((current_lcs == LCS_ROT) || (current_lcs == LCS_ROT_DEBUG)) {
			return SUIT_PLAT_SUCCESS;
		}
#endif /* CONFIG_SDFW_LCS */

		suit_storage_mpi_t *mpi;
		if (SUIT_PLAT_SUCCESS != suit_storage_mpi_get(class_id, &mpi)) {
			return MCI_ERR_MANIFESTCLASSID;
		}

		if (mpi->signature_verification_policy == SUIT_MPI_SIGNATURE_CHECK_DISABLED) {
			return SUIT_PLAT_SUCCESS;
		} else if (mpi->signature_verification_policy ==
			SUIT_MPI_SIGNATURE_CHECK_ENABLED_ON_UPDATE &&
			EXECUTION_MODE_INVOKE == suit_execution_mode_get()) {
				return SUIT_PLAT_SUCCESS;
		}

		return MCI_ERR_WRONGKEYID;
	}

	switch (role) {
	case SUIT_MANIFEST_SEC_TOP:
	case SUIT_MANIFEST_SEC_SDFW:
		if (key_id >= MANIFEST_PUBKEY_NRF_TOP_GEN0 &&
			key_id <= MANIFEST_PUBKEY_NRF_TOP_GEN0 + MANIFEST_PUBKEY_GEN_RANGE) {
			return SUIT_PLAT_SUCCESS;
		}
		break;

	case SUIT_MANIFEST_SEC_SYSCTRL:
		if (key_id >= MANIFEST_PUBKEY_SYSCTRL_GEN0 &&
			key_id <= MANIFEST_PUBKEY_SYSCTRL_GEN0 + MANIFEST_PUBKEY_GEN_RANGE) {
			return SUIT_PLAT_SUCCESS;
		}
		break;

	case SUIT_MANIFEST_APP_ROOT:
		if (key_id >= MANIFEST_PUBKEY_OEM_ROOT_GEN0 &&
			key_id <= MANIFEST_PUBKEY_OEM_ROOT_GEN0 + MANIFEST_PUBKEY_GEN_RANGE) {
			return SUIT_PLAT_SUCCESS;
		}
		break;

	case SUIT_MANIFEST_APP_RECOVERY:
	case SUIT_MANIFEST_APP_LOCAL_1:
	case SUIT_MANIFEST_APP_LOCAL_2:
	case SUIT_MANIFEST_APP_LOCAL_3:
		if (key_id >= MANIFEST_PUBKEY_APPLICATION_GEN0 &&
			key_id <= MANIFEST_PUBKEY_APPLICATION_GEN0 + MANIFEST_PUBKEY_GEN_RANGE) {
			return SUIT_PLAT_SUCCESS;
		}
		break;

	case SUIT_MANIFEST_RAD_RECOVERY:
	case SUIT_MANIFEST_RAD_LOCAL_1:
	case SUIT_MANIFEST_RAD_LOCAL_2:
		if (key_id >= MANIFEST_PUBKEY_RADIO_GEN0 &&
			key_id <= MANIFEST_PUBKEY_RADIO_GEN0 + MANIFEST_PUBKEY_GEN_RANGE) {
			return SUIT_PLAT_SUCCESS;
		}
		break;

	default:
		break;
	}

	return MCI_ERR_WRONGKEYID;
}

mci_err_t suit_mci_processor_start_rights_validate(const suit_manifest_class_id_t *class_id,
						   int processor_id)
{
	if (NULL == class_id) {
		return SUIT_PLAT_ERR_INVAL;
	}

	suit_manifest_role_t role = SUIT_MANIFEST_UNKNOWN;

	if (SUIT_PLAT_SUCCESS != suit_storage_mpi_role_get(class_id, &role)) {
		return MCI_ERR_MANIFESTCLASSID;
	}

	switch (role) {
	case SUIT_MANIFEST_UNKNOWN:
		return MCI_ERR_MANIFESTCLASSID;

	case SUIT_MANIFEST_SEC_TOP:
	case SUIT_MANIFEST_APP_ROOT:
	case SUIT_MANIFEST_SEC_SDFW:
		break;

	case SUIT_MANIFEST_SEC_SYSCTRL:
		/* Sys manifest */
		if (NRF_PROCESSOR_SYSCTRL == processor_id) {
			/* SysCtrl */
			return SUIT_PLAT_SUCCESS;
		}
		break;

	case SUIT_MANIFEST_APP_RECOVERY:
	case SUIT_MANIFEST_APP_LOCAL_1:
	case SUIT_MANIFEST_APP_LOCAL_2:
	case SUIT_MANIFEST_APP_LOCAL_3:
		/* App manifest.
		* TODO - implement verification for NRF_PROCESSOR_ID_PPR(13) and
		* NRF_PROCESSOR_ID_FLPR(14) support(based on UICR) NCSDK-26006
		*/
		if (NRF_PROCESSOR_APPLICATION == processor_id) {
			/* Appcore */
			return SUIT_PLAT_SUCCESS;
		}
		break;

	case SUIT_MANIFEST_RAD_RECOVERY:
	case SUIT_MANIFEST_RAD_LOCAL_1:
	case SUIT_MANIFEST_RAD_LOCAL_2:
		/* Rad manifest
		* TODO - implement verification for NRF_PROCESSOR_ID_PPR(13) and
		* NRF_PROCESSOR_ID_FLPR(14) support(based on UICR) NCSDK-26006
		*/
		if (NRF_PROCESSOR_RADIOCORE == processor_id) {
			/* Radiocore */
			return SUIT_PLAT_SUCCESS;
		}
		break;

	default:
		break;
	}

	return MCI_ERR_NOACCESS;
}

mci_err_t suit_mci_memory_access_rights_validate(const suit_manifest_class_id_t *class_id,
						 void *address, size_t mem_size)
{
	if (NULL == class_id || NULL == address || 0 == mem_size) {
		return SUIT_PLAT_ERR_INVAL;
	}

	suit_manifest_role_t role = SUIT_MANIFEST_UNKNOWN;

	if (SUIT_PLAT_SUCCESS != suit_storage_mpi_role_get(class_id, &role)) {
		return MCI_ERR_MANIFESTCLASSID;
	}

	switch (role) {
	case SUIT_MANIFEST_UNKNOWN:
		return MCI_ERR_MANIFESTCLASSID;

	case SUIT_MANIFEST_SEC_TOP:
		/* Nordic top manifest - ability to operate on memory ranges intentionally blocked
		*/
		return MCI_ERR_NOACCESS;

	case SUIT_MANIFEST_SEC_SDFW:
		/* Sec manifest - TODO - implement checks based on UICR/SICR
		*/
		return SUIT_PLAT_SUCCESS;

	case SUIT_MANIFEST_SEC_SYSCTRL:
		/* Sysctrl manifest - TODO - implement checks based on UICR/SICR
		*/
		return SUIT_PLAT_SUCCESS;

	case SUIT_MANIFEST_APP_ROOT:
		/* Root manifest - ability to operate on memory ranges intentionally blocked
		*/
		return MCI_ERR_NOACCESS;

	case SUIT_MANIFEST_APP_RECOVERY:
	case SUIT_MANIFEST_APP_LOCAL_1:
	case SUIT_MANIFEST_APP_LOCAL_2:
	case SUIT_MANIFEST_APP_LOCAL_3:
		/* App manifest - TODO - implement checks based on UICR
		*/
		return SUIT_PLAT_SUCCESS;

	case SUIT_MANIFEST_RAD_RECOVERY:
	case SUIT_MANIFEST_RAD_LOCAL_1:
	case SUIT_MANIFEST_RAD_LOCAL_2:
		/* Rad manifest - TODO - implement checks based on UICR
		*/
		return SUIT_PLAT_SUCCESS;

	default:
		break;
	}

	return MCI_ERR_NOACCESS;
}

mci_err_t
suit_mci_platform_specific_component_rights_validate(const suit_manifest_class_id_t *class_id,
						     int platform_specific_component_number)
{
	if (NULL == class_id) {
		return SUIT_PLAT_ERR_INVAL;
	}

	suit_manifest_role_t role = SUIT_MANIFEST_UNKNOWN;

	if (SUIT_PLAT_SUCCESS != suit_storage_mpi_role_get(class_id, &role)) {
		return MCI_ERR_MANIFESTCLASSID;
	}

	if (SUIT_MANIFEST_SEC_SDFW == role) {
		/* The only manifest with ability to control platform specific components is secdom.
		 * 0 - SDFW Firmware
		 * 1 - SDFW Recovery Firmware
		 */
		if (0 == platform_specific_component_number ||
		    1 == platform_specific_component_number) {
			return SUIT_PLAT_SUCCESS;
		}
	}

	return MCI_ERR_NOACCESS;
}

mci_err_t suit_mci_vendor_id_for_manifest_class_id_get(const suit_manifest_class_id_t *class_id,
						       const suit_uuid_t **vendor_id)
{
	if (NULL == class_id || NULL == vendor_id) {
		return SUIT_PLAT_ERR_INVAL;
	}
 
	suit_storage_mpi_t *mpi;
	if (SUIT_PLAT_SUCCESS != suit_storage_mpi_get(class_id, &mpi)) {
		return MCI_ERR_MANIFESTCLASSID;
	}

	/* Casting is done as a temporary solution until mpi refactoring */
	*vendor_id = (const suit_uuid_t *)mpi->vendor_id;
	return SUIT_PLAT_SUCCESS;
}

mci_err_t suit_mci_manifest_parent_child_declaration_validate(const suit_manifest_class_id_t *parent_class_id,
						  const suit_manifest_class_id_t *child_class_id)
{
	if ((parent_class_id == NULL) || (child_class_id == NULL)) {
		return SUIT_PLAT_ERR_INVAL;
	}

	suit_manifest_role_t parent_role = SUIT_MANIFEST_UNKNOWN;
	if (SUIT_PLAT_SUCCESS != suit_storage_mpi_role_get(parent_class_id, &parent_role)) {
		return MCI_ERR_MANIFESTCLASSID;
	}

	suit_manifest_role_t child_role = SUIT_MANIFEST_UNKNOWN;
	if (SUIT_PLAT_SUCCESS != suit_storage_mpi_role_get(child_class_id, &child_role)) {
		return MCI_ERR_MANIFESTCLASSID;
	}

	if ((parent_role == SUIT_MANIFEST_APP_ROOT) &&
		(((child_role >= SUIT_MANIFEST_APP_LOCAL_1) && (child_role <= SUIT_MANIFEST_APP_LOCAL_3)) ||
		 ((child_role >= SUIT_MANIFEST_RAD_LOCAL_1) && (child_role >= SUIT_MANIFEST_RAD_LOCAL_2)) ||
		 (child_role == SUIT_MANIFEST_SEC_TOP))) {
		return SUIT_PLAT_SUCCESS;
	}

	if ((parent_role == SUIT_MANIFEST_SEC_TOP) &&
		((child_role == SUIT_MANIFEST_SEC_SYSCTRL) ||
		 (child_role == SUIT_MANIFEST_SEC_SDFW))) {
		return SUIT_PLAT_SUCCESS;
	}

	if ((parent_role == SUIT_MANIFEST_APP_RECOVERY) &&
		((child_role == SUIT_MANIFEST_RAD_RECOVERY) ||
		((child_role >= SUIT_MANIFEST_APP_LOCAL_1) && (child_role <= SUIT_MANIFEST_APP_LOCAL_3)) ||
		((child_role >= SUIT_MANIFEST_RAD_LOCAL_1) && (child_role >= SUIT_MANIFEST_RAD_LOCAL_2)))) {
			return SUIT_PLAT_SUCCESS;
		}

	return MCI_ERR_NOACCESS;
}

mci_err_t suit_mci_manifest_process_dependency_validate(
						const suit_manifest_class_id_t *parent_class_id,
						const suit_manifest_class_id_t *child_class_id)
{
	if ((parent_class_id == NULL) || (child_class_id == NULL)) {
		return SUIT_PLAT_ERR_INVAL;
	}

	suit_execution_mode_t execution_mode = suit_execution_mode_get();

	suit_manifest_role_t parent_role = SUIT_MANIFEST_UNKNOWN;
	if (SUIT_PLAT_SUCCESS != suit_storage_mpi_role_get(parent_class_id, &parent_role)) {
		return MCI_ERR_MANIFESTCLASSID;
	}

	suit_manifest_role_t child_role = SUIT_MANIFEST_UNKNOWN;
	if (SUIT_PLAT_SUCCESS != suit_storage_mpi_role_get(child_class_id, &child_role)) {
		return MCI_ERR_MANIFESTCLASSID;
	}

	switch(execution_mode) {
	case EXECUTION_MODE_INVOKE:
		if ((parent_role == SUIT_MANIFEST_SEC_TOP) &&
			((child_role == SUIT_MANIFEST_SEC_SYSCTRL) ||
			 (child_role == SUIT_MANIFEST_SEC_SDFW))) {
			return SUIT_PLAT_SUCCESS;
		}

		if ((parent_role == SUIT_MANIFEST_APP_ROOT) &&
			(((child_role >= SUIT_MANIFEST_APP_LOCAL_1) && (child_role <= SUIT_MANIFEST_APP_LOCAL_3)) ||
			 ((child_role >= SUIT_MANIFEST_RAD_LOCAL_1) && (child_role >= SUIT_MANIFEST_RAD_LOCAL_2)))) {
			return SUIT_PLAT_SUCCESS;
		}
		break;

	case EXECUTION_MODE_INSTALL:
		if ((parent_role == SUIT_MANIFEST_SEC_TOP) &&
			((child_role == SUIT_MANIFEST_SEC_SYSCTRL) ||
			 (child_role == SUIT_MANIFEST_SEC_SDFW))) {
			return SUIT_PLAT_SUCCESS;
		}

		if ((parent_role == SUIT_MANIFEST_APP_ROOT) &&
		(((child_role >= SUIT_MANIFEST_APP_LOCAL_1) && (child_role <= SUIT_MANIFEST_APP_LOCAL_3)) ||
		 ((child_role >= SUIT_MANIFEST_RAD_LOCAL_1) && (child_role >= SUIT_MANIFEST_RAD_LOCAL_2)) ||
		 (child_role == SUIT_MANIFEST_SEC_TOP))) {
			return SUIT_PLAT_SUCCESS;
		}

		if ((parent_role == SUIT_MANIFEST_APP_RECOVERY) &&
			 (child_role == SUIT_MANIFEST_RAD_RECOVERY)) {
			return SUIT_PLAT_SUCCESS;
		}
		break;

	case EXECUTION_MODE_INVOKE_RECOVERY:
		if ((parent_role == SUIT_MANIFEST_SEC_TOP) &&
			((child_role == SUIT_MANIFEST_SEC_SYSCTRL) ||
			(child_role == SUIT_MANIFEST_SEC_SDFW))) {
			return SUIT_PLAT_SUCCESS;
		}

		if ((parent_role == SUIT_MANIFEST_APP_RECOVERY) &&
			((child_role == SUIT_MANIFEST_RAD_RECOVERY) ||
			((child_role >= SUIT_MANIFEST_APP_LOCAL_1) && (child_role <= SUIT_MANIFEST_APP_LOCAL_3)) ||
			((child_role >= SUIT_MANIFEST_RAD_LOCAL_1) && (child_role >= SUIT_MANIFEST_RAD_LOCAL_2)))) {
			return SUIT_PLAT_SUCCESS;
		}
		break;

	default:
		break;
	}

	return MCI_ERR_NOACCESS;
}

mci_err_t suit_mci_init(void)
{
	return SUIT_PLAT_SUCCESS;
}
