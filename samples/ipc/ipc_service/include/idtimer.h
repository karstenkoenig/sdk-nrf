/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/**
 * @file
 * @brief Public APIs for interdomain timer
 */

#ifndef IDTIMER_H_
#define IDTIMER_H_ 1

/**
 * @brief Interdomain timer APIs
 * @defgroup id_timer_interface Interdomain APIs
 * @{
 */

#include <zephyr/types.h>
#include <stddef.h>
#include <zephyr/device.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Start the timer from the local domain
 *
 * This function starts the timer from the local domain (not using the IPCT).
 *
 * @param dev Pointer to the device structure for the driver instance.
 *
 * @return 0 or error code.
 */
int idtimer_start(const struct device *dev);

/**
 * @brief Stop the timer from the local domain
 *
 * This function stops the timer from the local domain (not using the IPCT).
 *
 * @note
 * This function only stops the timer, without reseting it.
 * This different from the Zephyr counter API.
 *
 * @param dev Pointer to the device structure for the driver instance.
 *
 * @return 0 or error code.
 */
int idtimer_stop(const struct device *dev);

/**
 * @brief Clear the timer from the local domain
 *
 * Clear the timer.
 *
 * @param dev Pointer to the device structure for the driver instance.
 *
 * @return 0 or error code.
 */
int idtimer_clear(const struct device *dev);

/**
 * @brief Get the timer value
 *
 * Return the current timer value.
 * The value is returned in timer ticks.
 * To convert it to any other units use counter API with @ref idtimer_get_counter.
 *
 * @param dev Pointer to the device structure for the driver instance.
 *
 * @return Current timer value.
 *
 * @sa idtimer_get_counter
 */
uint32_t idtimer_get_value(const struct device *dev);

/**
 * @brief Low-level function to access the internal counter
 *
 * This function allows to access the counter device that is used by the module.
 * This allows to use more advanced functions to operate on the timer.
 *
 * @param dev Pointer to the device structure for the driver instance.
 *
 * @return Pointer to the device structure for the counter driver instance used by this module.
 */
const struct device *idtimer_get_counter(const struct device *dev);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif
#endif /* IDTIMER_H_ */
