/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/ztest.h>
#include <suit_storage.h>
#include <suit_storage_mpi.h>
#include <suit_storage_nvv.h>
#include "test_common.h"

ZTEST_SUITE(suit_storage_nrf54h20_init_tests, NULL, NULL, NULL, NULL, NULL);

ZTEST(suit_storage_nrf54h20_init_tests, test_empty_storage)
{
	uint8_t nvv_erased[SUIT_STORAGE_APP_NVV_SIZE];
	memset(nvv_erased, 0xff, sizeof(nvv_erased));

	/* GIVEN the whole SUIT storage area is erased (unprovisioned device) */
	erase_area_nordic();
	erase_area_rad();
	erase_area_app();

	/* WHEN storage module is initialized */
	int err = suit_storage_init();

	/* THEN digest of the application MPI and it's backup does not match... */
	int exp_err = SUIT_PLAT_ERR_CRASH;
	/* ... and an error code is returned */
	zassert_equal(err, exp_err, "Unexpected error code returned (%d).", err);
	/* ... and NVV area is not initialized */
	zassert_mem_equal(SUIT_STORAGE_APP_NVV_ADDRESS, nvv_erased, SUIT_STORAGE_APP_NVV_SIZE);
	/* ... and Nordic class IDs are supported */
	assert_nordic_classes();
}

ZTEST(suit_storage_nrf54h20_init_tests, test_empty_app_with_digest)
{
	uint8_t nvv_erased[SUIT_STORAGE_APP_NVV_SIZE];
	memset(nvv_erased, 0xff, sizeof(nvv_erased));

	/* GIVEN the device is provisioned with empty application MPI */
	erase_area_nordic();
	erase_area_rad();
	erase_area_app();
	write_empty_area_app();

	/* WHEN storage module is initialized */
	int err = suit_storage_init();

	/* THEN digest of the application MPI matches... */
	/* ... and the application MPI is copied into application backup area */
	assert_empty_mpi_area_app(SUIT_STORAGE_APP_ADDRESS,
				  SUIT_STORAGE_APP_MPI_SIZE + SUIT_STORAGE_DIGEST_SIZE);
	assert_empty_mpi_area_app(SUIT_STORAGE_NORDIC_ADDRESS + SUIT_STORAGE_RAD_MPI_SIZE,
				  SUIT_STORAGE_APP_MPI_SIZE + SUIT_STORAGE_DIGEST_SIZE);
	/* ... and parsing of the root MPI entry fails */
	int exp_err = SUIT_PLAT_ERR_NOT_FOUND;
	/* ... and an error code is returned */
	zassert_equal(err, exp_err, "Unexpected error code returned (%d).", err);
	/* ... and NVV area is not initialized */
	zassert_mem_equal(SUIT_STORAGE_APP_NVV_ADDRESS, nvv_erased, SUIT_STORAGE_APP_NVV_SIZE);
	/* ... and Nordic class IDs are supported */
	assert_nordic_classes();
}

ZTEST(suit_storage_nrf54h20_init_tests, test_app_with_root)
{
	/* GIVEN the device is provisioned with application MPI with root config */
	erase_area_nordic();
	erase_area_rad();
	erase_area_app();
	write_area_app_root();

	/* WHEN storage module is initialized */
	int err = suit_storage_init();

	/* THEN digest of the application MPI matches... */
	/* ... and the application MPI is copied into application backup area */
	assert_valid_mpi_area_app(SUIT_STORAGE_APP_ADDRESS,
				  SUIT_STORAGE_APP_MPI_SIZE + SUIT_STORAGE_DIGEST_SIZE);
	assert_valid_mpi_area_app(SUIT_STORAGE_NORDIC_ADDRESS + SUIT_STORAGE_RAD_MPI_SIZE,
				  SUIT_STORAGE_APP_MPI_SIZE + SUIT_STORAGE_DIGEST_SIZE);
	/* ... and parsing of the root MPI succeeds */
	int exp_err = SUIT_PLAT_SUCCESS;
	/* ... and NVV area digest does not match */
	/* ... and NVV area is initialized with default values (0xFF) and digest */
	zassert_mem_equal(SUIT_STORAGE_APP_NVV_ADDRESS, nvv_empty, SUIT_STORAGE_APP_NVV_SIZE / 2);
	/* ... and NVV area is copied into NVV backup area */
	zassert_mem_equal(SUIT_STORAGE_APP_NVV_ADDRESS + SUIT_STORAGE_APP_NVV_SIZE / 2, nvv_empty,
			  SUIT_STORAGE_APP_NVV_SIZE / 2);
	/* ... and initialization succeeds */
	zassert_equal(err, exp_err, "Failed to initialize SUIT storage (%d).", err);
	/* ... and Nordic class IDs are supported */
	assert_nordic_classes();
	/* ... and sample root class is supported */
	assert_sample_root_class();
}

ZTEST(suit_storage_nrf54h20_init_tests, test_app_with_root_backup)
{
	/* GIVEN the device was provisioned with application MPI with root config */
	erase_area_nordic();
	write_area_nordic_root();
	/* .. and the application area was erased after the backup was created */
	erase_area_rad();
	erase_area_app();

	/* WHEN storage module is initialized */
	int err = suit_storage_init();

	/* THEN digest of the application MPI does not match... */
	/* ... and the application MPI is copied from backup area */
	assert_valid_mpi_area_app(SUIT_STORAGE_APP_ADDRESS,
				  SUIT_STORAGE_APP_MPI_SIZE + SUIT_STORAGE_DIGEST_SIZE);
	assert_valid_mpi_area_app(SUIT_STORAGE_NORDIC_ADDRESS + SUIT_STORAGE_RAD_MPI_SIZE,
				  SUIT_STORAGE_APP_MPI_SIZE + SUIT_STORAGE_DIGEST_SIZE);
	/* ... and parsing of the root MPI succeeds */
	int exp_err = SUIT_PLAT_SUCCESS;
	/* ... and NVV area digest does not match */
	/* ... and NVV area is initialized with default values (0xFF) and digest */
	zassert_mem_equal(SUIT_STORAGE_APP_NVV_ADDRESS, nvv_empty, SUIT_STORAGE_APP_NVV_SIZE / 2);
	/* ... and NVV area is copied into NVV backup area */
	zassert_mem_equal(SUIT_STORAGE_APP_NVV_ADDRESS + SUIT_STORAGE_APP_NVV_SIZE / 2, nvv_empty,
			  SUIT_STORAGE_APP_NVV_SIZE / 2);
	/* ... and initialization succeeds */
	zassert_equal(err, exp_err, "Failed to initialize SUIT storage (%d).", err);
	/* ... and Nordic class IDs are supported */
	assert_nordic_classes();
	/* ... and sample root class is supported */
	assert_sample_root_class();
}

ZTEST(suit_storage_nrf54h20_init_tests, test_app_with_old_root_nvv_backup)
{
	/* GIVEN the device was provisioned with application MPI with old root config */
	erase_area_nordic();
	write_area_nordic_old_root();
	/* .. and the device is provisioned with new application MPI with root config */
	erase_area_rad();
	erase_area_app();
	write_area_app_empty_nvv_backup();
	write_area_app_nvv();
	write_area_app_root();

	/* WHEN storage module is initialized */
	int err = suit_storage_init();

	/* THEN digest of the application MPI matches... */
	/* ... and the application MPI is copied into application backup area */
	assert_valid_mpi_area_app(SUIT_STORAGE_APP_ADDRESS,
				  SUIT_STORAGE_APP_MPI_SIZE + SUIT_STORAGE_DIGEST_SIZE);
	assert_valid_mpi_area_app(SUIT_STORAGE_NORDIC_ADDRESS + SUIT_STORAGE_RAD_MPI_SIZE,
				  SUIT_STORAGE_APP_MPI_SIZE + SUIT_STORAGE_DIGEST_SIZE);
	/* ... and parsing of the root MPI succeeds */
	int exp_err = SUIT_PLAT_SUCCESS;
	/* ... and NVV area digest does matches */
	/* ... and NVV area is not modified */
	zassert_mem_equal(SUIT_STORAGE_APP_NVV_ADDRESS, nvv_sample, SUIT_STORAGE_APP_NVV_SIZE / 2);
	/* ... and NVV area backup is updated */
	zassert_mem_equal(SUIT_STORAGE_APP_NVV_ADDRESS + SUIT_STORAGE_APP_NVV_SIZE / 2, nvv_sample,
			  SUIT_STORAGE_APP_NVV_SIZE / 2);
	/* ... and initialization succeeds */
	zassert_equal(err, exp_err, "Failed to initialize SUIT storage (%d).", err);
	/* ... and Nordic class IDs are supported */
	assert_nordic_classes();
	/* ... and sample root class is supported */
	assert_sample_root_class();
}

ZTEST(suit_storage_nrf54h20_init_tests, test_app_corrupted_nvv)
{
	/* GIVEN the device is provisioned with application MPI with root config */
	erase_area_nordic();
	write_area_nordic_root();
	/* .. and NVV area is erased */
	erase_area_rad();
	erase_area_app();
	write_area_app_root();
	/* .. and NVV backup is present */
	write_area_app_nvv_backup();

	/* WHEN storage module is initialized */
	int err = suit_storage_init();

	/* THEN digest of the application MPI matches... */
	/* ... and the application MPI is the same as application backup area */
	assert_valid_mpi_area_app(SUIT_STORAGE_APP_ADDRESS,
				  SUIT_STORAGE_APP_MPI_SIZE + SUIT_STORAGE_DIGEST_SIZE);
	assert_valid_mpi_area_app(SUIT_STORAGE_NORDIC_ADDRESS + SUIT_STORAGE_RAD_MPI_SIZE,
				  SUIT_STORAGE_APP_MPI_SIZE + SUIT_STORAGE_DIGEST_SIZE);
	/* ... and parsing of the root MPI succeeds */
	int exp_err = SUIT_PLAT_SUCCESS;
	/* ... and NVV area digest does not match */
	/* ... and NVV area is recovered from backup */
	zassert_mem_equal(SUIT_STORAGE_APP_NVV_ADDRESS, nvv_sample, SUIT_STORAGE_APP_NVV_SIZE / 2);
	/* ... and NVV area backup is not modified */
	zassert_mem_equal(SUIT_STORAGE_APP_NVV_ADDRESS + SUIT_STORAGE_APP_NVV_SIZE / 2, nvv_sample,
			  SUIT_STORAGE_APP_NVV_SIZE / 2);
	/* ... and initialization succeeds */
	zassert_equal(err, exp_err, "Failed to initialize SUIT storage (%d).", err);
	/* ... and Nordic class IDs are supported */
	assert_nordic_classes();
	/* ... and sample root class is supported */
	assert_sample_root_class();
}

ZTEST(suit_storage_nrf54h20_init_tests, test_app_corrupted_nvv_backup)
{
	/* GIVEN the device is provisioned with application MPI with root config */
	erase_area_nordic();
	write_area_nordic_root();
	/* .. and NVV backup is erased */
	erase_area_rad();
	erase_area_app();
	write_area_app_root();
	/* .. and NVV is present */
	write_area_app_nvv();

	/* WHEN storage module is initialized */
	int err = suit_storage_init();

	/* THEN digest of the application MPI matches... */
	/* ... and the application MPI is the same as application backup area */
	assert_valid_mpi_area_app(SUIT_STORAGE_APP_ADDRESS,
				  SUIT_STORAGE_APP_MPI_SIZE + SUIT_STORAGE_DIGEST_SIZE);
	assert_valid_mpi_area_app(SUIT_STORAGE_NORDIC_ADDRESS + SUIT_STORAGE_RAD_MPI_SIZE,
				  SUIT_STORAGE_APP_MPI_SIZE + SUIT_STORAGE_DIGEST_SIZE);
	/* ... and parsing of the root MPI succeeds */
	int exp_err = SUIT_PLAT_SUCCESS;
	/* ... and NVV area digest matches */
	/* ... and NVV area is not modified */
	zassert_mem_equal(SUIT_STORAGE_APP_NVV_ADDRESS, nvv_sample, SUIT_STORAGE_APP_NVV_SIZE / 2);
	/* ... and NVV area backup is updated */
	zassert_mem_equal(SUIT_STORAGE_APP_NVV_ADDRESS + SUIT_STORAGE_APP_NVV_SIZE / 2, nvv_sample,
			  SUIT_STORAGE_APP_NVV_SIZE / 2);
	/* ... and initialization succeeds */
	zassert_equal(err, exp_err, "Failed to initialize SUIT storage (%d).", err);
	/* ... and Nordic class IDs are supported */
	assert_nordic_classes();
	/* ... and sample root class is supported */
	assert_sample_root_class();
}
