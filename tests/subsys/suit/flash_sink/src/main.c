/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/ztest.h>
#include <stdint.h>
#include <flash_sink.h>
#include <sink.h>
#include <suit_plat_mem_util.h>
#include <zephyr/drivers/flash.h>
#include <suit_memptr_storage.h>

#define TEST_DATA_SIZE 64
#define TEST_REQUESTED_AREA 0x1000
#define WRITE_ADDR     suit_plat_mem_nvm_ptr_get(SUIT_DFU_PARTITION_OFFSET)

#define SUIT_DFU_PARTITION_OFFSET  FIXED_PARTITION_OFFSET(dfu_partition)
#define SUIT_DFU_PARTITION_SIZE    FIXED_PARTITION_SIZE(dfu_partition)

static uint8_t test_data[] = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
			      16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
			      32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
			      48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63};

static void test_setup_flash(void *arg)
{
	/* Erase the area, to met the preconditions in the next test. */
	const struct device *fdev = DEVICE_DT_GET(DT_CHOSEN(zephyr_flash_controller));
	zassert_not_null(fdev, "Unable to find a driver to erase area");

	int rc = flash_erase(fdev, SUIT_DFU_PARTITION_OFFSET, SUIT_DFU_PARTITION_SIZE);
	zassert_equal(rc, 0, "Unable to erase memory before test execution");
}

ZTEST_SUITE(flash_sink_tests, NULL, NULL, test_setup_flash, NULL, NULL);

ZTEST(flash_sink_tests, test_flash_sink_get_OK)
{
	struct stream_sink flash_sink;
	memptr_storage_handle_t handle = NULL;

	int err = suit_memptr_storage_get(&handle);
	zassert_equal(err, 0, "suit_memptr_storage_get failed - error %i", err);

	err = flash_sink_get(&flash_sink, WRITE_ADDR, TEST_REQUESTED_AREA, handle);
	zassert_equal(err, 0, "flash_sink_get failed - error %i", err);
	zassert_not_equal(flash_sink.ctx, NULL, "flash_sink_get failed - ctx is NULL");

	err = flash_sink.release(flash_sink.ctx);
	zassert_equal(err, 0, "flash_sink.release failed - error %i", err);

	err = suit_memptr_storage_release(handle);
	zassert_equal(err, 0, "memptr_storage.release failed - error %i", err);
}

ZTEST(flash_sink_tests, test_flash_sink_get_NOK)
{
	struct stream_sink flash_sink;
	memptr_storage_handle_t handle = NULL;

	int err = suit_memptr_storage_get(&handle);
	zassert_equal(err, 0, "suit_memptr_storage_get failed - error %i", err);

	err = flash_sink_get(&flash_sink, NULL, TEST_REQUESTED_AREA, handle);
	zassert_not_equal(err, 0, "flash_sink_get should have failed - dst == NULL");

	err = flash_sink_get(&flash_sink, WRITE_ADDR, 0, handle);
	zassert_not_equal(err, 0, "flash_sink_get should have failed - offset_limit == 0");

	err = flash_sink_get(&flash_sink, WRITE_ADDR, TEST_REQUESTED_AREA, NULL);
	zassert_not_equal(err, 0, "flash_sink_get should have failed - handle == NULL");

	err = suit_memptr_storage_release(handle);
	zassert_equal(err, 0, "memptr_storage.release failed - error %i", err);
}

ZTEST(flash_sink_tests, test_flash_sink_release_NOK)
{
	struct stream_sink flash_sink;
	memptr_storage_handle_t handle = NULL;

	int err = suit_memptr_storage_get(&handle);
	zassert_equal(err, 0, "suit_memptr_storage_get failed - error %i", err);

	err = flash_sink_get(&flash_sink, WRITE_ADDR, TEST_REQUESTED_AREA, handle);
	zassert_equal(err, 0, "flash_sink_get failed - error %i", err);

	err = flash_sink.release(NULL);
	zassert_not_equal(err, 0, "flash_sink.release should have failed - ctx == NULL");

	err = flash_sink.release(flash_sink.ctx);
	zassert_equal(err, 0, "flash_sink.release failed - error %i", err);

	err = suit_memptr_storage_release(handle);
	zassert_equal(err, 0, "memptr_storage.release failed - error %i", err);
}

ZTEST(flash_sink_tests, test_flash_sink_seek_OK)
{
	struct stream_sink flash_sink;
	memptr_storage_handle_t handle = NULL;

	int err = suit_memptr_storage_get(&handle);
	zassert_equal(err, 0, "suit_memptr_storage_get failed - error %i", err);

	err = flash_sink_get(&flash_sink, WRITE_ADDR, TEST_REQUESTED_AREA, handle);
	zassert_equal(err, 0, "flash_sink_get failed - error %i", err);

	err = flash_sink.seek(flash_sink.ctx, 0);
	zassert_equal(err, 0, "flash_sink.seek failed - error %i", err);

	err = flash_sink.seek(flash_sink.ctx, 9);
	zassert_equal(err, 0, "flash_sink.seek failed - error %i", err);

	err = flash_sink.seek(flash_sink.ctx, 63);
	zassert_equal(err, 0, "flash_sink.seek failed - error %i", err);

	err = flash_sink.release(flash_sink.ctx);
	zassert_equal(err, 0, "flash_sink.release failed - error %i", err);

	err = suit_memptr_storage_release(handle);
	zassert_equal(err, 0, "memptr_storage.release failed - error %i", err);
}

ZTEST(flash_sink_tests, test_flash_sink_seek_NOK)
{
	struct stream_sink flash_sink;
	memptr_storage_handle_t handle = NULL;

	int err = suit_memptr_storage_get(&handle);
	zassert_equal(err, 0, "suit_memptr_storage_get failed - error %i", err);

	err = flash_sink_get(&flash_sink, WRITE_ADDR, TEST_REQUESTED_AREA, handle);
	zassert_equal(err, 0, "flash_sink_get failed - error %i", err);

	err = flash_sink.seek(flash_sink.ctx, TEST_REQUESTED_AREA);
	zassert_not_equal(err, 0, "flash_sink.seek should have failed - passed arg == offset_limit");

	err = flash_sink.seek(flash_sink.ctx, TEST_REQUESTED_AREA + 1);
	zassert_not_equal(err, 0, "flash_sink.seek should have failed - passed arg > offset_limit");

	err = flash_sink.release(flash_sink.ctx);
	zassert_equal(err, 0, "flash_sink.release failed - error %i", err);

	err = suit_memptr_storage_release(handle);
	zassert_equal(err, 0, "memptr_storage.release failed - error %i", err);
}

ZTEST(flash_sink_tests, test_flash_sink_used_storage_OK)
{
	struct stream_sink flash_sink;
	size_t used_storage = 0;
	memptr_storage_handle_t handle = NULL;

	int err = suit_memptr_storage_get(&handle);
	zassert_equal(err, 0, "suit_memptr_storage_get failed - error %i", err);

	err = flash_sink_get(&flash_sink, WRITE_ADDR, TEST_REQUESTED_AREA, handle);
	zassert_equal(err, 0, "flash_sink_get failed - error %i", err);

	err = flash_sink.used_storage(flash_sink.ctx, &used_storage);
	zassert_equal(err, 0, "flash_sink.use_storage failed - error %i", err);
	zassert_equal(used_storage, 0, "flash_sink.use_storage failed - not initialized to 0");

	err = flash_sink.release(flash_sink.ctx);
	zassert_equal(err, 0, "flash_sink.release failed - error %i", err);

	err = suit_memptr_storage_release(handle);
	zassert_equal(err, 0, "memptr_storage.release failed - error %i", err);
}

ZTEST(flash_sink_tests, test_flash_sink_used_storage_NOK)
{
	struct stream_sink flash_sink;
	memptr_storage_handle_t handle = NULL;

	int err = suit_memptr_storage_get(&handle);
	zassert_equal(err, 0, "suit_memptr_storage_get failed - error %i", err);

	err = flash_sink_get(&flash_sink, WRITE_ADDR, TEST_REQUESTED_AREA, handle);
	zassert_equal(err, 0, "flash_sink_get failed - error %i", err);

	err = flash_sink.used_storage(flash_sink.ctx, NULL);
	zassert_not_equal(err, 0, "flash_sink.use_storage should have failed - arg size == NULL");

	err = flash_sink.release(flash_sink.ctx);
	zassert_equal(err, 0, "flash_sink.release failed - error %i", err);

	err = suit_memptr_storage_release(handle);
	zassert_equal(err, 0, "memptr_storage.release failed - error %i", err);
}

ZTEST(flash_sink_tests, test_flash_sink_write_OK)
{
	struct stream_sink flash_sink;
	size_t used_storage = 0;
	size_t input_size = 21; /* Arbitrary value, chosen to be unaligned */
	memptr_storage_handle_t handle = NULL;

	int err = suit_memptr_storage_get(&handle);
	zassert_equal(err, 0, "suit_memptr_storage_get failed - error %i", err);

	err = flash_sink_get(&flash_sink, WRITE_ADDR, TEST_REQUESTED_AREA, handle);
	zassert_equal(err, 0, "flash_sink_get failed - error %i", err);

	err = flash_sink.write(flash_sink.ctx, test_data, &input_size);
	zassert_equal(err, 0, "flash_sink.write failed - error %i", err);

	err = flash_sink.used_storage(flash_sink.ctx, &used_storage);
	zassert_equal(err, 0, "flash_sink.use_storage failed - error %i", err);
	zassert_equal(used_storage, input_size, "flash_sink.use_storage failed - value %d",
		      used_storage);

	err = flash_sink.seek(flash_sink.ctx, input_size + 7);
	zassert_equal(err, 0, "flash_sink.seek failed - error %i", err);

	err = flash_sink.used_storage(flash_sink.ctx, &used_storage);
	zassert_equal(err, 0, "flash_sink.use_storage failed - error %i", err);

	err = flash_sink.write(flash_sink.ctx, &test_data[input_size], &input_size);
	zassert_equal(err, 0, "flash_sink.write failed - error %i", err);

	err = flash_sink.release(flash_sink.ctx);
	zassert_equal(err, 0, "flash_sink.release failed - error %i", err);

	err = suit_memptr_storage_release(handle);
	zassert_equal(err, 0, "memptr_storage.release failed - error %i", err);
}

ZTEST(flash_sink_tests, test_flash_sink_write_NOK)
{
	struct stream_sink flash_sink;
	size_t input_size = 0;
	memptr_storage_handle_t handle = NULL;

	int err = suit_memptr_storage_get(&handle);
	zassert_equal(err, 0, "suit_memptr_storage_get failed - error %i", err);

	err = flash_sink_get(&flash_sink, WRITE_ADDR, TEST_REQUESTED_AREA, handle);
	zassert_equal(err, 0, "flash_sink_get failed - error %i", err);

	err = flash_sink.write(flash_sink.ctx, test_data, &input_size);
	zassert_not_equal(err, 0, "flash_sink.write should have failed - size == 0");

	input_size = 8;
	err = flash_sink.write(NULL, test_data, &input_size);
	zassert_not_equal(err, 0, "flash_sink.write should have failed - ctx == NULL");

	err = flash_sink.write(flash_sink.ctx, NULL, &input_size);
	zassert_not_equal(err, 0, "flash_sink.write should have failed - buf == NULL");

	err = flash_sink.release(flash_sink.ctx);
	zassert_equal(err, 0, "flash_sink.release failed - error %i", err);

	err = suit_memptr_storage_release(handle);
	zassert_equal(err, 0, "memptr_storage.release failed - error %i", err);
}
