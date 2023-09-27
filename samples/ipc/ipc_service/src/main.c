/*
 * Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <string.h>
#include <zephyr/drivers/counter.h>
#include <idtimer.h>

#include <zephyr/logging/log.h>

#include <zephyr/ipc/ipc_service.h>

#ifdef CONFIG_TEST_EXTRA_STACK_SIZE
#define STACKSIZE	(1024 + CONFIG_TEST_EXTRA_STACK_SIZE)
#else
#define STACKSIZE	(1024)
#endif

#ifdef CONFIG_COVERAGE
#define MAX_CALCULATIONS	(6)
#else
#define MAX_CALCULATIONS	(65535)
#endif

#define LATENCY_REMOTE_START_NODE DT_NODELABEL(remote_latency_start)
#define USE_LATENCY_REMOTE_START DT_NODE_EXISTS(LATENCY_REMOTE_START_NODE)

/* The interdomain timer used to measure latency */
static const struct device *latency_timer = DEVICE_DT_GET_OR_NULL(DT_NODELABEL(latency_timer));

#if USE_LATENCY_REMOTE_START
#include <hal/nrf_ipct.h>
/* IPCT channel used to generate remote latency timer stop event */
static NRF_IPCT_Type *ipct_start_reg =
	(NRF_IPCT_Type *)DT_REG_ADDR(DT_PHANDLE(LATENCY_REMOTE_START_NODE, ipct));
static uint8_t ipct_start_ch = DT_PROP(LATENCY_REMOTE_START_NODE, ch);
#endif

static const struct gpio_dt_spec pin_send =
	GPIO_DT_SPEC_GET_OR(DT_NODELABEL(ipc_send_pin), gpios, {0});
static const struct gpio_dt_spec pin_recv =
	GPIO_DT_SPEC_GET_OR(DT_NODELABEL(ipc_recv_pin), gpios, {0});

LOG_MODULE_REGISTER(host, LOG_LEVEL_INF);

struct payload {
	unsigned long cnt;
	unsigned long size;
	uint8_t data[];
};

static K_SEM_DEFINE(bound_sem, 0, 1);
K_THREAD_STACK_DEFINE(check_task_stack, STACKSIZE);
struct k_thread check_task_data;

static uint32_t payload_data[(CONFIG_APP_IPC_SERVICE_MESSAGE_LEN + 3)/4];
static struct payload *p_payload = (struct payload *) payload_data;

static uint32_t run_counter = 0;

static void ep_bound(void *priv)
{
	k_sem_give(&bound_sem);
}

static void ep_recv(const void *data, size_t len, void *priv)
{
	uint8_t received_val = *((uint8_t *)data);
	static uint8_t expected_val;

	if (pin_recv.port) {
		gpio_pin_set_dt(&pin_recv, 1);
	}

	if (latency_timer) {
		uint32_t t_val = idtimer_get_value(latency_timer);
		uint64_t t_us = counter_ticks_to_us(idtimer_get_counter(latency_timer), t_val);

		idtimer_stop(latency_timer);
		idtimer_clear(latency_timer);

		printk("Message received after: %"PRIu64"us\n", t_us);
	}

	if ((received_val != expected_val) || (len != CONFIG_APP_IPC_SERVICE_MESSAGE_LEN)) {
		printk("Unexpected message received_val: %d , expected_val: %d\n",
			received_val,
			expected_val);
	}

	expected_val++;
	if (pin_recv.port) {
		gpio_pin_set_dt(&pin_recv, 0);
	}
}

static struct ipc_ept_cfg ep_cfg = {
	.name = "ep0",
	.cb = {
		.bound    = ep_bound,
		.received = ep_recv,
	},
};

static void check_task(void *arg1, void *arg2, void *arg3)
{
	ARG_UNUSED(arg1);
	ARG_UNUSED(arg2);
	ARG_UNUSED(arg3);

	unsigned long last_cnt = p_payload->cnt;
	unsigned long delta;

	while (run_counter < MAX_CALCULATIONS) {
		k_sleep(K_MSEC(1000));

		delta = p_payload->cnt - last_cnt;

		printk("Δpkt: %ld (%ld B/pkt) | throughput: %ld bit/s\n",
			delta, p_payload->size, delta * CONFIG_APP_IPC_SERVICE_MESSAGE_LEN * 8);

		last_cnt = p_payload->cnt;
		run_counter++;
	}
}

int main(void)
{
	const struct device *ipc0_instance;
	struct ipc_ept ep;
	int ret;
	printk("IPC-service %s demo started\n", CONFIG_BOARD);

	if (pin_send.port) {
		gpio_pin_configure_dt(&pin_send, GPIO_OUTPUT_INACTIVE);
	}
	if (pin_recv.port) {
		gpio_pin_configure_dt(&pin_recv, GPIO_OUTPUT_INACTIVE);
	}

	memset(p_payload->data, 0xA5, CONFIG_APP_IPC_SERVICE_MESSAGE_LEN - sizeof(struct payload));

	p_payload->size = CONFIG_APP_IPC_SERVICE_MESSAGE_LEN;
	p_payload->cnt = 0;

	ipc0_instance = DEVICE_DT_GET(DT_NODELABEL(ipc0));

	ret = ipc_service_open_instance(ipc0_instance);
	if ((ret < 0) && (ret != -EALREADY)) {
		LOG_INF("ipc_service_open_instance() failure: %d", ret);
		return ret;
	}

	ret = ipc_service_register_endpoint(ipc0_instance, &ep, &ep_cfg);
	if (ret < 0) {
		printf("ipc_service_register_endpoint() failure");
		return ret;
	}

	k_sem_take(&bound_sem, K_FOREVER);

	/* Measuring throughput only if no latency timer is used */
	if (!latency_timer) {
		(void)k_thread_create(
			&check_task_data, check_task_stack,
			K_THREAD_STACK_SIZEOF(check_task_stack),
			check_task,
			NULL, NULL, NULL,
			-1, 0, K_NO_WAIT);
	}

	while (run_counter < MAX_CALCULATIONS) {
		if (pin_send.port) {
			gpio_pin_set_dt(&pin_send, 1);
		}
#if USE_LATENCY_REMOTE_START
		nrf_ipct_task_trigger(ipct_start_reg, nrf_ipct_send_task_get(ipct_start_ch));
#endif
		ret = ipc_service_send(&ep, p_payload, CONFIG_APP_IPC_SERVICE_MESSAGE_LEN);
		if (pin_send.port) {
			gpio_pin_set_dt(&pin_send, 0);
		}
		if (ret == -ENOMEM) {
			/* No space in the buffer. Retry. */
			LOG_DBG("send_message(%ld) failed with ret -ENOMEM\n", p_payload->cnt);
		} else if (ret < 0) {
			LOG_ERR("send_message(%ld) failed with ret %d\n", p_payload->cnt, ret);
			break;
		} else {
			p_payload->cnt++;
		}

		if (CONFIG_APP_IPC_SERVICE_SEND_INTERVAL < (USEC_PER_SEC / CONFIG_SYS_CLOCK_TICKS_PER_SEC)) {
			k_busy_wait(CONFIG_APP_IPC_SERVICE_SEND_INTERVAL);
		} else {
			k_usleep(CONFIG_APP_IPC_SERVICE_SEND_INTERVAL);
		}
	}

	while (k_thread_join(&check_task_data, K_MSEC(100)) != 0) {
		k_sleep(K_MSEC(100));
	}

	printk("IPC-service demo has comleted\n");

	return 0;
}
