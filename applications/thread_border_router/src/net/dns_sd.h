/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/** @file
 * @brief DNS-SD services
 */

#ifndef INCLUDE_DNS_SD_
#define INCLUDE_DNS_SD_

#include "mdns_server.h"

#include <stdint.h>
#include <stdbool.h>

/**
 * @brief DNS-SD service handle
 *
 * Handle used for accessing a service with API functions.
 */
struct dns_sd_service_handle;

/**
 * @brief Service iteration callback
 *
 * Function pointer to be provided as @ref dns_sd_service_for_each() argument. It
 * is invoked until callback returns @ref NET_OK.
 *
 * The callback returns:
 *  - NET_CONTINUE if next service should be handled (e.g. if required to handle
 *    all services one by one).
 *  - NET_OK in case when needs to interrupt @ref dns_sd_service_for_each() (e.g. service is found).
 */
typedef enum net_verdict (*dns_sd_service_cb_t)(struct dns_sd_service_handle *handle, void *user_data);

/** Service's transport protocol */
enum dns_sd_service_proto {
	DNS_SD_SERVICE_PROTO_UDP,
	DNS_SD_SERVICE_PROTO_TCP,
};

/** Structure used for providing information about a service */
struct dns_sd_service_info_in {
	/** Time To Live */
	int32_t ttl;

	/** NULL-terminated string with service's instance */
	const char *instance;

	/** NULL-terminated string with service's name */
	const char *service;

	/** Optional: NULL-terminated string with service's subtype */
	const char *subtype;

	/** Service's transport protocol */
	enum dns_sd_service_proto proto;

	/** Service's weight */
	uint16_t weight;

	/** Service's priority */
	uint16_t priority;

	/** Service's port */
	uint16_t port;

	/** TXT data buffer */
	uint8_t *txt_data;

	/** TXT data length */
	uint8_t txt_data_len;

	/** Pointer to A or AAAA record providing an adress */
	struct mdns_record_handle *target;
};

/** Structure providing info about a buffer */
struct dns_sd_service_info_buf {
	uint8_t *buf;
	size_t len_max;
	size_t len_read;
};

/** Structure used for reading data about a service */
struct dns_sd_service_info_out {
	/** Time To Live */
	int32_t ttl;

	/** Buffer for reading complete service name */
	struct dns_sd_service_info_buf name;

	/** Buffer for reading subtype */
	struct dns_sd_service_info_buf subtype;

	/** Buffer for reading TXT data */
	struct dns_sd_service_info_buf txt_data;

	/** Service's weight */
	uint16_t weight;

	/** Service's priority */
	uint16_t priority;

	/** Service's port */
	uint16_t port;

	/** A or AAAA record */
	struct mdns_record_handle *target;
};

/**
 * @brief Initialize DNS-SD module
 *
 * Prepare memory buffers.
 */
void dns_sd_init(void);


/**
 * @brief Publish DNS-SD service
 *
 * Publish new DNS-SD service based on data provided with @ref dns_sd_service_info_in. Add any
 * necessary mDNS records and links between them.
 *
 * @note Function is thread safe as it locks the internal mutex at the beginning.
 *
 * @param info Service's information
 * @param timeout Time of waiting for the internal lock
 * @param output Pointer for storing allocated service's handle
 *
 * @retval 0 on success
 * @retval -EINVAL if provided service information is invalid
 * @retval -EBUSY if failed to acquire the lock
 */
int dns_sd_service_publish(struct dns_sd_service_info_in *info, k_timeout_t timeout,
			   struct dns_sd_service_handle **output);

/**
 * @brief Unpublish DNS-SD service
 *
 * @note Function is thread safe as it locks the internal mutex at the beginning.
 *
 * @param handle Service's handle
 * @param timeout Time of waiting for the internal lock
 *
 * @retval 0 on success
 * @retval -EINVAL if @p handle is invalid
 * @retval -EBUSY if failed to acquire the lock
 */
int dns_sd_service_unpublish(struct dns_sd_service_handle *handle, k_timeout_t timeout);

/**
 * @brief Iterate over published services
 *
 * Invoke a callback for every allocated service providing its handle.
 *
 * @note Function is thread safe as it locks the internal mutex at the beginning.
 *       Within the context of the callback any function that would lock the
 *       mutex (e.g., @ref dns_sd_service_get_info()) can be be called with
 *       K_NO_WAIT parameter.
 *
 * @param callback Callback to be called for every published service
 * @param user_data User data supplied by a caller
 * @param timeout Time of waiting for the internal lock
 *
 * @retval >=0 is a number of processed services
 * @retval -EINVAL if @p callback is NULL
 * @retval -EBUSY if failed to acquire the lock
 */
int dns_sd_service_for_each(dns_sd_service_cb_t callback, void *user_data, k_timeout_t timeout);

/**
 * @brief Read information about a service
 *
 * This function fills fields of @ref dns_sd_service_info_out structure. The
 * caller has to provide buffer information for the data it wants to read, e.g.
 * TXT data can be read without filling the service's name.
 *
 * @note Function is thread safe as it locks the internal mutex at the beginning.
 *
 * @param handle Service's handle
 * @param info Structure to be filled by the function
 * @param timeout Time of waiting for the internal lock
 *
 * @retval 0 on success
 * @retval -EINVAL if @p handle or @p info are invalid
 * @retval -EBUSY if failed to acquire the lock
 */
int dns_sd_service_get_info(struct dns_sd_service_handle *handle,
			    struct dns_sd_service_info_out *info, k_timeout_t timeout);

#endif
