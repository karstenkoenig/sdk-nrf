/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef __ZEPHYR_KERNEL_H
#define __ZEPHYR_KERNEL_H

/* Compatebility header for using Zephyr API in TF-M.
 *
 * The macros and functions here can be used by code that is common for both
 * Zephyr and TF-M RTOS.
 *
 * The functionality will be forwarded to TF-M equivalent of the Zephyr API.
 */

#include <stdint.h>
#include <stdbool.h>
#include <zephyr/sys/printk.h>

#include <zephyr/kernel_includes.h>
#include <errno.h>
#include <stdbool.h>

#define k_panic() tfm_core_panic()

static inline bool k_is_pre_kernel(void)
{
	return 0;
}

#define K_MUTEX_DEFINE(name) uint32_t name

#define K_FOREVER 0

static int k_mutex_lock(uint32_t *mutex, uint32_t timeout)
{
	return 0;
}

static int k_mutex_unlock(uint32_t *mutex)
{
	return 0;
}


#define K_SEM_DEFINE(name, unused_arg1, unused_arg2) uint32_t name

static int k_sem_give(uint32_t *mutex)
{
	return 0;
}

static int k_sem_take(uint32_t *mutex, uint32_t timeout)
{
	return 0;
}

#endif /* __ZEPHYR_KERNEL_H */
