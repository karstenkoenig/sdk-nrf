/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/** @file
 * @brief nRF Thread Border Router's Border Agent's functions
 */

#include <stdbool.h>
#include <zephyr/net/net_ip.h>

#ifndef NRF_TBR_INCLUDE_BORDER_AGENT_H_
#define NRF_TBR_INCLUDE_BORDER_AGENT_H_

/**
 * @brief Initialize Border Agent
 *
 * Initialization of variables and data structures.
 */
void border_agent_init(void);

/**
 * @brief Start Border Agent
 *
 * Start Border Agent service publishes AAAA mDNS records for IPv6 addresses
 * reported with @ref border_agent_handle_address_event() and automatically
 * publishes the most current version of MeshCoP DNS-SD service.
 *
 * @note Border Agent must be first initialized with @ref border_agent_init().
 */
void border_agent_start(void);

/**
 * @brief Handle events related to IPv6 addreses
 *
 * This function keeps an internal list of AAAA mDNS records up to date by
 * allocating or freeing them based on network events.
 *
 * @param addr IPv6 address
 * @param is_added true if address was added, false if removed
 */
void border_agent_handle_address_event(const struct in6_addr *addr, bool is_added);

#endif /* NRF_TBR_INCLUDE_BORDER_AGENT_H_ */
