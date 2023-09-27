/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#define DT_DRV_COMPAT interdomain_timer

#include <zephyr/kernel.h>
#include <zephyr/devicetree.h>
#include <zephyr/device.h>
#include <zephyr/drivers/counter.h>

#include <helpers/nrfx_gppi.h>
#include <hal/nrf_timer.h>
#include <hal/nrf_ipct.h>
#include <idtimer.h>

#define LOG_LEVEL CONFIG_INTERDOMAIN_TIMER_LOG_LEVEL
#define LOG_MODULE_NAME idtimer
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(LOG_MODULE_NAME, LOG_LEVEL);

struct idtimer_ipct_spec {
	/** @brief IPCT register */
	NRF_IPCT_Type *reg;
	/** @brief channel index */
	uint8_t chidx;
};

struct idtimer_config {
	struct idtimer_ipct_spec ipct_stop;
	struct idtimer_ipct_spec ipct_start;
	const struct device *timer;
	NRF_TIMER_Type *const timer_reg;
};


int idtimer_start(const struct device *dev)
{
	const struct idtimer_config *config = dev->config;

	nrf_timer_task_trigger(config->timer_reg, NRF_TIMER_TASK_START);

	return 0;
}

int idtimer_stop(const struct device *dev)
{
	const struct idtimer_config *config = dev->config;

	nrf_timer_task_trigger(config->timer_reg, NRF_TIMER_TASK_STOP);

	return 0;
}

int idtimer_clear(const struct device *dev)
{
	const struct idtimer_config *config = dev->config;

	nrf_timer_task_trigger(config->timer_reg, NRF_TIMER_TASK_CLEAR);

	return 0;
}

uint32_t idtimer_get_value(const struct device *dev)
{
	uint32_t val = 0;
	const struct idtimer_config *config = dev->config;

	(void)counter_get_value(config->timer, &val);

	return val;
}

const struct device *idtimer_get_counter(const struct device *dev)
{
	const struct idtimer_config *config = dev->config;

	return config->timer;
}

static int idtimer_connect_ipct_task(const struct idtimer_ipct_spec *ipct_spec, uint32_t task)
{
	nrfx_err_t err;
	uint8_t chan;
	err = nrfx_gppi_channel_alloc(&chan);

	if (err != NRFX_SUCCESS) {
		LOG_ERR("gppi_channel_alloc failed with: %d\n", err);
		return -ENOMEM;
	}
	LOG_DBG("Allocated channel %u\n", (uint32_t)chan);

	nrf_ipct_shorts_enable(ipct_spec->reg, BIT(ipct_spec->chidx));
	nrfx_gppi_channel_endpoints_setup(
		chan,
		(uint32_t) nrf_ipct_event_address_get(
				ipct_spec->reg,
				nrf_ipct_receive_event_get(ipct_spec->chidx)),
		task);
	nrfx_gppi_channels_enable(BIT(chan));

	return 0;
}

static int idtimer_init(const struct device *dev)
{
	const struct idtimer_config *config = dev->config;

	if (config->ipct_stop.reg) {
		int ret = idtimer_connect_ipct_task(
			&config->ipct_stop,
			(uint32_t) nrf_timer_task_address_get(
					config->timer_reg,
					NRF_TIMER_TASK_STOP));

		if (ret) {
			return ret;
		}
	} else if (config->ipct_start.reg) {
		int ret = idtimer_connect_ipct_task(
			&config->ipct_start,
			(uint32_t) nrf_timer_task_address_get(
					config->timer_reg,
					NRF_TIMER_TASK_START));

		if (ret) {
			return ret;
		}
	}

	return 0;
}

#define _IDTIMER_IPCT_SPEC_GET(node_id, ipct_prop, ipct_ch_prop) {                   \
		.reg = (NRF_IPCT_Type *)DT_REG_ADDR(DT_PHANDLE(node_id, ipct_prop)), \
		.chidx = DT_PROP(node_id, ipct_ch_prop)                              \
	}

#define _IDTIMER_IPCT_SPEC_GET_OR(node_id, ipct_prop, ipct_ch_prop, default_value) \
	COND_CODE_1(DT_NODE_HAS_PROP(node_id, ipct_prop),                          \
		(_IDTIMER_IPCT_SPEC_GET(node_id, ipct_prop, ipct_ch_prop)),        \
		(default_value)                                                    \
	)

#define _IDTIMER_DEVICE(idx)                                                                    \
	static const struct idtimer_config idtimer_##idx##_config = {                           \
		.ipct_stop  = _IDTIMER_IPCT_SPEC_GET_OR(                                        \
			DT_DRV_INST(idx), ipct_stop, ipct_ch_stop, {.reg = NULL}),              \
		.ipct_start = _IDTIMER_IPCT_SPEC_GET_OR(                                        \
			DT_DRV_INST(idx), ipct_start, ipct_ch_start, {.reg = NULL}),            \
		.timer = DEVICE_DT_GET(DT_INST_PHANDLE(idx, timer)),                            \
		.timer_reg = (NRF_TIMER_Type *)DT_REG_ADDR(DT_INST_PHANDLE(idx, timer)),        \
	};                                                                                      \
	DEVICE_DT_INST_DEFINE(idx,                                                              \
			      idtimer_init,                                                     \
			      NULL,                                                             \
			      NULL,                                                             \
			      &idtimer_##idx##_config,                                          \
			      PRE_KERNEL_1, CONFIG_IDTIMER_INIT_PRIORITY,                       \
			      NULL);

DT_INST_FOREACH_STATUS_OKAY(_IDTIMER_DEVICE)
