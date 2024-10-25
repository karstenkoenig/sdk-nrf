/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/logging/log.h>

#include <nrfs_gdpwr.h>
#include <nrfs_backend_ipc_service.h>

LOG_MODULE_REGISTER(idle);


static void gdpwr_handler(nrfs_gdpwr_evt_t const *p_evt, void *context)
{
	switch (p_evt->type) {
	case NRFS_GDPWR_REQ_APPLIED:
		LOG_INF("GDPWR handler: response received");
		break;
	case NRFS_GDPWR_REQ_REJECTED:
		LOG_ERR("GDPWR handler - request rejected!");
		break;
	default:
		LOG_ERR("GDPWR handler - unexpected event: 0x%x", p_evt->type);
		break;
	}
}

static int clear_gdpwr_requests(void)
{
	nrfs_err_t status = NRFS_SUCCESS;

	status = nrfs_gdpwr_init(gdpwr_handler);
	if (status != NRFS_SUCCESS) {
		LOG_ERR("GDPWR service init failed: %d", status);
		return -1;
	}

	status = nrfs_gdpwr_power_request(GDPWR_POWER_DOMAIN_ACTIVE_FAST, GDPWR_POWER_REQUEST_CLEAR,
					  NULL);
	if (status != NRFS_SUCCESS) {
		LOG_ERR("Failed to clear power request for GDFAST_ACTIVE, %d", status);
		return -1;
	}
	status = nrfs_gdpwr_power_request(GDPWR_POWER_DOMAIN_ACTIVE_SLOW, GDPWR_POWER_REQUEST_CLEAR,
					  NULL);
	if (status != NRFS_SUCCESS) {
		LOG_ERR("Failed to clear power request for GDSLOW_ACTIVE, %d", status);
		return -1;
	}
	status = nrfs_gdpwr_power_request(GDPWR_POWER_DOMAIN_MAIN_SLOW, GDPWR_POWER_REQUEST_CLEAR,
					  NULL);
	if (status != NRFS_SUCCESS) {
		LOG_ERR("Failed to clear power request for GDSLOW_MAIN, %d", status);
		return -1;
	}

	return 0;
}

int main(void)
{
	unsigned int cnt = 0;

#if defined CONFIG_FIRST_SLEEP_OFFSET
	k_msleep(1000);
#else
	k_msleep(3000);
#endif

	clear_gdpwr_requests();

	LOG_INF("Multicore idle test on %s", CONFIG_BOARD_TARGET);
	while (1) {
		LOG_INF("Multicore idle test iteration %u", cnt++);
		k_msleep(2000);
	}

	return 0;
}
