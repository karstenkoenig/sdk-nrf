/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/sys/printk.h>
#include <zephyr/drivers/clock_control.h>
#if !defined(CONFIG_SOC_SERIES_NRF54HX)
#include <zephyr/drivers/clock_control/nrf_clock_control.h>
#endif /* !defined(CONFIG_SOC_SERIES_NRF54HX) */

#if !defined(CONFIG_SOC_SERIES_NRF54HX)
static void clock_init(void)
{
	int err;
	int res;
	struct onoff_manager *clk_mgr;
	struct onoff_client clk_cli;

	clk_mgr = z_nrf_clock_control_get_onoff(CLOCK_CONTROL_NRF_SUBSYS_HF);
	if (!clk_mgr) {
		printk("Unable to get the Clock manager\n");
		return;
	}

	sys_notify_init_spinwait(&clk_cli.notify);

	err = onoff_request(clk_mgr, &clk_cli);
	if (err < 0) {
		printk("Clock request failed: %d\n", err);
		return;
	}

	do {
		err = sys_notify_fetch_result(&clk_cli.notify, &res);
		if (!err && res) {
			printk("Clock could not be started: %d\n", res);
			return;
		}
	} while (err);

	printk("Clock has started\n");
}
#else
static void clock_init(void)
{
}
#endif /* !defined(CONFIG_SOC_SERIES_NRF54HX) */

int main(void)
{
	printk("Starting Radio Test example\n");
	
	clock_init();

	return 0;
}
