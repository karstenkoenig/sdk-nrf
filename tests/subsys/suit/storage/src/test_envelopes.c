/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/ztest.h>
#include <suit_storage.h>
#include <platform_mem_util.h>
#ifdef CONFIG_FLASH_SIMULATOR
#include <zephyr/drivers/flash/flash_simulator.h>
#endif /* CONFIG_FLASH_SIMULATOR */

#ifdef CONFIG_FLASH_SIMULATOR
static uint8_t *f_base_address = NULL;
#endif /* CONFIG_FLASH_SIMULATOR */

#define SUIT_STORAGE_ADDRESS FLASH_ADDRESS(SUIT_STORAGE_OFFSET)
#define SUIT_STORAGE_OFFSET  FIXED_PARTITION_OFFSET(suit_storage)
#define SUIT_STORAGE_SIZE    FIXED_PARTITION_SIZE(suit_storage)

/* The SUIT envelopes are defined inside the respective manfest_*.c files. */
extern uint8_t manifest_root_buf[];
extern const size_t manifest_root_len;
extern uint8_t manifest_app_buf[];
extern const size_t manifest_app_len;
extern uint8_t manifest_rad_buf[];
extern const size_t manifest_rad_len;
extern uint8_t manifest_sys_buf[];
extern const size_t manifest_sys_len;

extern uint8_t manifest_root_v2_buf[];
extern const size_t manifest_root_v2_len;
extern uint8_t manifest_app_v2_buf[];
extern const size_t manifest_app_v2_len;
extern uint8_t manifest_rad_v2_buf[];
extern const size_t manifest_rad_v2_len;

extern uint8_t manifest_app_posix_buf[];
extern const size_t manifest_app_posix_len;
extern uint8_t manifest_root_posix_buf[];
extern const size_t manifest_root_posix_len;

static const suit_manifest_class_id_t classes[] = {
	/* RFC4122 uuid5(nordic_vid, 'nRF54H20_sample_root') */
	{{0x3f, 0x6a, 0x3a, 0x4d, 0xcd, 0xfa, 0x58, 0xc5, 0xac, 0xce, 0xf9, 0xf5, 0x84, 0xc4, 0x11,
	  0x24}},
	/* RFC4122 uuid5(nordic_vid, 'nRF54H20_sample_app') */
	{{0x08, 0xc1, 0xb5, 0x99, 0x55, 0xe8, 0x5f, 0xbc, 0x9e, 0x76, 0x7b, 0xc2, 0x9c, 0xe1, 0xb0,
	  0x4d}},
	/* RFC4122 uuid5(nordic_vid, 'nRF54H20_sample_rad') */
	{{0x81, 0x6a, 0xa0, 0xa0, 0xaf, 0x11, 0x5e, 0xf2, 0x85, 0x8a, 0xfe, 0xb6, 0x68, 0xb2, 0xe9,
	  0xc9}},
	/* RFC4122 uuid5(nordic_vid, 'nRF54H20_sec_sys') */
	{{0x75, 0x81, 0x1f, 0x10, 0x09, 0x94, 0x57, 0x72, 0xad, 0xf7, 0x71, 0x88, 0xbc, 0x8c, 0x5b,
	  0x73}},
	/* RFC4122 uuid5(nordic_vid, 'posix_sample_root') */
	{{0xc8, 0x36, 0x30, 0xf5, 0x9e, 0x0f, 0x5f, 0xe4, 0x8e, 0xff, 0x34, 0x27, 0xd3, 0x64, 0x7d,
	  0x97}},
	/* RFC4122 uuid5(nordic_vid, 'posix_sample_app') */
	{{0x56, 0xdc, 0x9a, 0x14, 0x28, 0xd8, 0x52, 0xd3, 0xbd, 0x62, 0xe7, 0x7a, 0x08, 0xbc, 0x8b,
	  0x91}},
};

static const suit_manifest_class_id_t *supported_classes[] = {
	&classes[0],
	&classes[1],
	&classes[2],
	&classes[3],
};

static const suit_manifest_class_id_t *unsupported_classes[] = {
	&classes[4],
	&classes[5],
};

static void *test_suite_setup(void)
{
#ifdef CONFIG_FLASH_SIMULATOR
	static const struct device *fdev = DEVICE_DT_GET(DT_CHOSEN(zephyr_flash_controller));
	size_t f_size = 0;
	f_base_address = flash_simulator_get_memory(fdev, &f_size);
#endif /* CONFIG_FLASH_SIMULATOR */

	return NULL;
}

static void test_suite_before(void *f)
{
	/* Erase the area, to met the preconditions in the next test. */
	const struct device *fdev = DEVICE_DT_GET(DT_CHOSEN(zephyr_flash_controller));
	zassert_not_null(fdev, "Unable to find a driver to erase area");

	int rc = flash_erase(fdev, SUIT_STORAGE_OFFSET, SUIT_STORAGE_SIZE);
	zassert_equal(rc, 0, "Unable to erase memory before test execution");

	rc = suit_storage_init(supported_classes, ARRAY_SIZE(supported_classes));
	zassert_equal(rc, 0, "Failed to initialize SUIT storage module (%d).", rc);
}

ZTEST_SUITE(suit_storage_envelopes_tests, NULL, test_suite_setup, test_suite_before, NULL, NULL);

ZTEST(suit_storage_envelopes_tests, test_empty_envelope_get)
{
	uint8_t *addr;
	size_t size;
	int rc = 0;

	for (size_t i = 0; i < ARRAY_SIZE(classes); i++) {
		rc = suit_storage_installed_envelope_get(NULL, NULL, NULL);
		zassert_not_equal(rc, 0, "Arguments are incorrect, but %d envelope was received",
				  i);

		rc = suit_storage_installed_envelope_get(NULL, NULL, &size);
		zassert_not_equal(rc, 0,
				  "Arguments are incorrect, but %d envelope was received (%d)", i,
				  size);

		rc = suit_storage_installed_envelope_get(NULL, &addr, NULL);
		zassert_not_equal(rc, 0,
				  "Arguments are incorrect, but %d envelope was received (0x%x)", i,
				  addr);

		rc = suit_storage_installed_envelope_get(&classes[i], NULL, NULL);
		zassert_not_equal(rc, 0, "Arguments are incorrect, but %d envelope was received",
				  i);

		rc = suit_storage_installed_envelope_get(&classes[i], NULL, &size);
		zassert_not_equal(rc, 0,
				  "Arguments are incorrect, but %d envelope was received (%d)", i,
				  size);

		rc = suit_storage_installed_envelope_get(&classes[i], &addr, NULL);
		zassert_not_equal(rc, 0,
				  "Arguments are incorrect, but %d envelope was received (0x%x)", i,
				  addr);

		rc = suit_storage_installed_envelope_get(&classes[i], &addr, &size);
		zassert_not_equal(rc, 0,
				  "Suit storage is empty, but %d envelope was received (0x%x, %d)",
				  i, addr, size);
	}
}

ZTEST(suit_storage_envelopes_tests, test_empty_envelope_set)
{
	uint8_t *addr;
	size_t size;
	int rc = 0;

	suit_plat_mreg_t envelopes[] = {
		{
			.mem = manifest_root_buf,
			.size = manifest_root_len,
		},
		{
			.mem = manifest_app_buf,
			.size = manifest_app_len,
		},
		{
			.mem = manifest_rad_buf,
			.size = manifest_rad_len,
		},
		{
			.mem = manifest_sys_buf,
			.size = manifest_sys_len,
		},
	};

	for (size_t i = 0; i < ARRAY_SIZE(envelopes); i++) {
		rc = suit_storage_installed_envelope_get(supported_classes[i], &addr, &size);
		zassert_not_equal(rc, 0,
				  "Envelope %d was not installed, but was returned (0x%x, %d)", i,
				  addr, size);

		rc = suit_storage_install_envelope(supported_classes[i],
						   (uint8_t *)envelopes[i].mem, envelopes[i].size);
		zassert_equal(rc, 0, "Unable to install envelope %d", i);

		rc = suit_storage_installed_envelope_get(supported_classes[i], &addr, &size);
		zassert_equal(rc, 0, "Envelope %d was installed, but was not returned (0x%x, %d)",
			      i, addr, size);
		zassert_true(size < (envelopes[i].size - 256),
			     "Envelope %d was installed, but the size was not reduced (%d >= %d)",
			     i, size, envelopes[i].size);
	}
}

ZTEST(suit_storage_envelopes_tests, test_empty_envelope_override)
{
	uint8_t *addr;
	size_t size;
	int rc = 0;

	suit_plat_mreg_t envelopes[] = {
		{
			.mem = manifest_root_buf,
			.size = manifest_root_len,
		},
		{
			.mem = manifest_app_buf,
			.size = manifest_app_len,
		},
		{
			.mem = manifest_rad_buf,
			.size = manifest_rad_len,
		},
		{
			.mem = manifest_sys_buf,
			.size = manifest_sys_len,
		},
	};

	/* Verify that envelopes are not installed. */
	for (size_t i = 0; i < ARRAY_SIZE(envelopes); i++) {
		rc = suit_storage_installed_envelope_get(supported_classes[i], &addr, &size);
		zassert_not_equal(rc, 0,
				  "Envelope %d was not installed, but was returned (0x%x, %d)", i,
				  addr, size);
	}

	/* Install envelopes for the first time. */
	for (size_t i = 0; i < ARRAY_SIZE(envelopes); i++) {
		rc = suit_storage_install_envelope(supported_classes[i],
						   (uint8_t *)envelopes[i].mem, envelopes[i].size);
		zassert_equal(rc, 0, "Unable to install envelope %d", i);

		rc = suit_storage_installed_envelope_get(supported_classes[i], &addr, &size);
		zassert_equal(rc, 0, "Envelope %d was installed, but was not returned (0x%x, %d)",
			      i, addr, size);
	}

	/* Install new version of the envelopes. */
	suit_plat_mreg_t envelopes_v2[] = {
		{
			.mem = manifest_root_v2_buf,
			.size = manifest_root_v2_len,
		},
		{
			.mem = manifest_app_v2_buf,
			.size = manifest_app_v2_len,
		},
		{
			.mem = manifest_rad_v2_buf,
			.size = manifest_rad_v2_len,
		},
		{
			.mem = manifest_sys_buf,
			.size = manifest_sys_len,
		},
	};

	for (size_t i = 0; i < ARRAY_SIZE(envelopes_v2); i++) {
		rc = suit_storage_install_envelope(
			supported_classes[i], (uint8_t *)envelopes_v2[i].mem, envelopes_v2[i].size);
		zassert_equal(rc, 0, "Unable to install envelope %d", i);

		rc = suit_storage_installed_envelope_get(supported_classes[i], &addr, &size);
		zassert_equal(rc, 0, "Envelope %d was installed, but was not returned (0x%x, %d)",
			      i, addr, size);
	}
}

ZTEST(suit_storage_envelopes_tests, test_empty_envelope_set_unsupported_classes)
{
	uint8_t *addr;
	size_t size;
	int rc = 0;

	suit_plat_mreg_t envelopes[] = {
		{
			.mem = manifest_root_posix_buf,
			.size = manifest_root_posix_len,
		},
		{
			.mem = manifest_app_posix_buf,
			.size = manifest_app_posix_len,
		},
	};

	for (size_t i = 0; i < ARRAY_SIZE(envelopes); i++) {
		rc = suit_storage_install_envelope(unsupported_classes[i],
						   (uint8_t *)envelopes[i].mem, envelopes[i].size);
		zassert_not_equal(rc, 0, "Envelope with unsupported class ID shall fail %d", i);

		rc = suit_storage_installed_envelope_get(unsupported_classes[i], &addr, &size);
		zassert_not_equal(rc, 0,
				  "Envelope %d was not installed, but was returned (0x%x, %d)", i,
				  addr, size);
	}
}

ZTEST(suit_storage_envelopes_tests, test_empty_envelope_set_class_mismatch)
{
	uint8_t *addr;
	size_t size;
	int rc = 0;

	suit_plat_mreg_t envelopes[] = {
		{
			.mem = manifest_root_posix_buf,
			.size = manifest_root_posix_len,
		},
		{
			.mem = manifest_app_posix_buf,
			.size = manifest_app_posix_len,
		},
	};

	for (size_t i = 0; i < ARRAY_SIZE(envelopes); i++) {
		rc = suit_storage_install_envelope(supported_classes[i],
						   (uint8_t *)envelopes[i].mem, envelopes[i].size);
		zassert_not_equal(rc, 0, "Envelope with unmatched class ID shall fail %d", i);

		rc = suit_storage_installed_envelope_get(supported_classes[i], &addr, &size);
		zassert_not_equal(rc, 0,
				  "Envelope %d was not installed, but was returned (0x%x, %d)", i,
				  addr, size);
	}
}
