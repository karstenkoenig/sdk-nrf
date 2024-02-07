/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/** @file
 * @brief OpenThread infrastructure link
 */

#ifndef NRF_TBR_INCLUDE_INFRA_IF_H_
#define NRF_TBR_INCLUDE_INFRA_IF_H_

/**
 * @brief Initialize infrastructure link
 */
void infra_if_init(void);

/**
 * @brief Handle Thread's Network Data changes
 */
void infra_if_handle_netdata_change(void);

#endif /* NRF_TBR_INCLUDE_INFRA_IF_H_ */
