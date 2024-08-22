/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(idle);

int main(void)
{
	unsigned int cnt = 0;

	LOG_INF("Multicore idle test on %s", CONFIG_BOARD_TARGET);
	while (1) {
		LOG_INF("Multicore idle test iteration %u", cnt++);
#if defined(CONFIG_WAKEUP_NEVER)
		k_sleep(K_FOREVER);
#elif defined(CONFIG_WAKEUP_1S)
		k_msleep(1000);
#endif
	}

	return 0;
}
