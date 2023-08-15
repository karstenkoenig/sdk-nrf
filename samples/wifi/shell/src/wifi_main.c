/*
 * Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/** @file
 * @brief WiFi shell sample main function
 */

#include <zephyr/sys/printk.h>
#if NRFX_CLOCK_ENABLED && defined(CLOCK_FEATURE_HFCLK_DIVIDE_PRESENT) && NRF_CLOCK_HAS_HFCLK192M
#include <nrfx_clock.h>
#endif /* NRFX_CLOCK_ENABLED && CLOCK_FEATURE_HFCLK_DIVIDE_PRESENT */
#include <zephyr/device.h>
#include <zephyr/net/net_config.h>

int main(void)
{
#if NRFX_CLOCK_ENABLED && defined(CLOCK_FEATURE_HFCLK_DIVIDE_PRESENT) && NRF_CLOCK_HAS_HFCLK192M
	/* For now hardcode to 128MHz */
	nrfx_clock_divider_set(NRF_CLOCK_DOMAIN_HFCLK,
			       NRF_CLOCK_HFCLK_DIV_1);
#endif /* NRFX_CLOCK_ENABLED && CLOCK_FEATURE_HFCLK_DIVIDE_PRESENT */
	printk("Starting %s with CPU frequency: %d MHz\n", CONFIG_BOARD, SystemCoreClock/MHZ(1));

#ifdef CONFIG_NET_CONFIG_SETTINGS
	/* Without this, DHCPv4 starts on first interface and if that is not Wi-Fi or
	 * only supports IPv6, then its an issue. (E.g., OpenThread)
	 *
	 * So, we start DHCPv4 on Wi-Fi interface always, independent of the ordering.
	 */
	/* TODO: Replace device name with DTS settings later */
	const struct device *dev = device_get_binding("wlan0");

	net_config_init_app(dev, "Initializing network");
#endif

	return 0;
}
