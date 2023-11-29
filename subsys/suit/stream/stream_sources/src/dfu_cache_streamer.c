/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <dfu_cache_streamer.h>
#include <dfu_cache.h>
#include <zcbor_decode.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(dfu_cache_streamer, CONFIG_SUIT_LOG_LEVEL);

suit_plat_err_t dfu_cache_streamer(const uint8_t *uri, size_t uri_size, struct stream_sink *sink)
{
	LOG_ERR("Running dfu_cache_streamer function");
	if ((uri != NULL) && (sink != NULL) && (sink->write != NULL) && (uri_size > 0)) {
		suit_plat_err_t err = SUIT_PLAT_SUCCESS;
		uint8_t *payload = NULL;
		size_t payload_size = 0;

		err = suit_dfu_cache_search(uri, uri_size, &payload, &payload_size);

		if (err == SUIT_PLAT_SUCCESS) {
			return sink->write(sink->ctx, payload, &payload_size);
		}

		return SUIT_PLAT_ERR_NOT_FOUND;
	}

	LOG_ERR("Invalid arguments.");
	return SUIT_PLAT_ERR_INVAL;
}
