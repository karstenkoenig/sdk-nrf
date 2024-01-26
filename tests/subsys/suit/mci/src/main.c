/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */
#include <zephyr/ztest.h>
#include <suit_mci.h>
#ifdef CONFIG_SUIT_STORAGE
#include <suit_storage.h>
#endif /* CONFIG_SUIT_STORAGE */

void test_generic_ids(void);
void test_sanity(void);
void test_api_positive_scenarios(void);
void test_topology(void);

void test_main(void)
{
#ifdef CONFIG_SUIT_STORAGE
	int ret = suit_storage_init();
	if (ret != SUIT_PLAT_SUCCESS) {
		printk("Storage init failed\n");
		return;
	}
#endif /* CONFIG_SUIT_STORAGE */

	suit_mci_init();
	test_generic_ids();
	test_sanity();
	test_api_positive_scenarios();
	test_topology();
}
