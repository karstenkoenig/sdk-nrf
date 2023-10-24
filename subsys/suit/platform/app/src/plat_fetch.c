/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/logging/log.h>
#include <suit_platform_internal.h>

#ifdef CONFIG_SUIT_STREAM
#include <sink.h>
#include <sink_selector.h>
#endif /* CONFIG_SUIT_STREAM */

#ifdef CONFIG_SUIT_STREAM_SOURCE_CACHE
#include <cache_streamer.h>
#endif /* CONFIG_SUIT_STREAM_SOURCE_CACHE */
#ifdef CONFIG_SUIT_STREAM_SOURCE_MEMPTR
#include <memptr_streamer.h>
#endif /* CONFIG_SUIT_STREAM_SOURCE_MEMPTR */

#ifdef CONFIG_SUIT_STREAM_FETCH_SOURCE_MGR
#include "fetch_source_mgr.h"
#endif /* CONFIG_SUIT_STREAM_FETCH_SOURCE_MGR */

#include <stdbool.h>
#include <suit_platform.h>
#include <suit_memptr_storage.h>

LOG_MODULE_REGISTER(suit_plat_fetch_app, CONFIG_SUIT_LOG_LEVEL);

#ifdef CONFIG_SUIT_STREAM
static bool is_type_supported(suit_component_type_t *component_type)
{
	/* Check if compoenent type is supported by fetch command */
	if ((*component_type != SUIT_COMPONENT_TYPE_CAND_IMG) &&
	    (*component_type != SUIT_COMPONENT_TYPE_CAND_MFST) &&
	    (*component_type != SUIT_COMPONENT_TYPE_CACHE_POOL)) {
		return false;
	}

	return true;
}

static int verify_and_get_sink(suit_component_t dst_handle, struct stream_sink *sink,
			       struct zcbor_string *uri, suit_component_type_t *component_type)
{
	uint32_t number;
	struct zcbor_string *component_id;

	int ret = suit_plat_component_id_get(dst_handle, &component_id);
	if (ret != SUIT_SUCCESS) {
		LOG_ERR("suit_plat_component_id_get failed: %i", ret);
		return SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
	}

	if (!suit_plat_decode_component_type(component_id, component_type)) {
		LOG_ERR("suit_plat_decode_component_type failed");
		return SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
	}

	if (!is_type_supported(component_type)) {
		return SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
	}

	if (!suit_plat_decode_component_number(component_id, &number)) {
		LOG_ERR("Missing component id number in candidate image component");
		return SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
	}

	/* Select sink */
	switch (*component_type) {
#ifdef CONFIG_SUIT_STREAM_SINK_MEMPTR
	case SUIT_COMPONENT_TYPE_CAND_IMG:
	case SUIT_COMPONENT_TYPE_CAND_MFST: { /* memptr_sink */
		memptr_storage_handle handle;

		ret = suit_plat_component_impl_data_get(dst_handle, &handle);
		if (ret != SUIT_SUCCESS) {
			LOG_ERR("Unable to get component data for candidate image (err: %d)", ret);
			return ret;
		}

		return memptr_sink_get(&dst_sink, handle);
	} break;
#endif /* CONFIG_SUIT_STREAM_SINK_MEMPTR */
#ifdef CONFIG_SUIT_CACHE_RW
	case SUIT_COMPONENT_TYPE_CACHE_POOL: {
		ret = dfu_get_cache_sink(&dst_sink, number, uri->value, uri->len);
		if (ret != SUIT_SUCCESS) {
			LOG_ERR("Getting cache sink failed");
			return ret;
		}
	} break;
#endif /* CONFIG_SUIT_CACHE_RW */
	default:
		LOG_ERR("Unsupported component type: %c", *component_type);
		return SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
	}

	return SUIT_SUCCESS;
}
#endif /* CONFIG_SUIT_STREAM */

int suit_plat_check_fetch(suit_component_t dst_handle, struct zcbor_string *uri)
{
#ifdef CONFIG_SUIT_STREAM
	struct stream_sink dst_sink;
	suit_component_type_t component_type = SUIT_COMPONENT_TYPE_UNSUPPORTED;

	int ret = verify_and_get_sink(dst_handle, &dst_sink, uri, &component_type);
	if (ret != SUIT_SUCCESS) {
		LOG_ERR("Failed to verify component end get end sink");
	}

	if (dst_sink.release != NULL) {
		int err = sink.release(sink.ctx);

		if (err != SUCCESS) {
			LOG_ERR("sink release failed: %i", err);
			return err;
		}
	}

	return SUIT_SUCCESS;
#else
	return SUIT_ERR_UNSUPPORTED_COMMAND;
#endif /* CONFIG_SUIT_STREAM */
}

int suit_plat_fetch(suit_component_t dst_handle, struct zcbor_string *uri)
{
#ifdef CONFIG_SUIT_STREAM
	struct stream_sink dst_sink;
	suit_component_type_t component_type = SUIT_COMPONENT_TYPE_UNSUPPORTED;

	int ret = verify_and_get_sink(dst_handle, &dst_sink, uri, &component_type);
	if (ret != SUIT_SUCCESS) {
		LOG_ERR("Failed to verify component end get end sink");
	}

	/* Here other parts of pipe will be instantiated.
	 *	Like decryption and/or decompression sinks.
	 */

	/* Select streamer */
	switch (component_type) {
#ifdef CONFIG_SUIT_STREAM_FETCH_SOURCE_MGR
	case SUIT_COMPONENT_TYPE_CACHE_POOL:
	case SUIT_COMPONENT_TYPE_MEM: {
		ret = fetch_source_stream(uri->value, uri->len, &dst_sink);
	} break;
#endif /* SUIT_STREAM_FETCH_SOURCE_MGR */
#if defined(CONFIG_SUIT_CACHE_RW) || defined(SUIT_CACHE)
	case SUIT_COMPONENT_TYPE_CAND_MFST:
	case SUIT_COMPONENT_TYPE_CAND_IMG: {
		ret = cache_streamer(uri->value, uri->len, &dst_sink);
	} break;
#endif
	default:
		ret = SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
		break;
	}

	/* If possible update component size */
	if ((ret == SUIT_SUCCESS) && (SUIT_SUCCESS) && (dst_sink.used_storage != NULL)) {
		size_t size;

		ret = dst_sink.used_storage(dst_sink.ctx, &size);
		if (ret != SUIT_SUCCESS) {
			LOG_ERR("Failed to retrieve amount of used space");
			return ret;
		}

		ret = suit_plat_override_image_size(dst_handle, size);
		if (ret != SUIT_SUCCESS) {
			LOG_ERR("Failed to update component size");
			return ret;
		}
	}

	if (dst_sink.release != NULL) {
		int err = dst_sink.release(sink.ctx);

		if (err != SUCCESS) {
			LOG_ERR("sink release failed: %i", err);
			return err;
		}
	}

	return ret;
#else
	return SUIT_ERR_UNSUPPORTED_COMMAND;
#endif /* CONFIG_SUIT_STREAM */
}

int suit_plat_check_fetch_integrated(suit_component_t dst_handle, struct zcbor_string *payload)
{
	return SUIT_ERR_UNSUPPORTED_COMMAND;
}

int suit_plat_fetch_integrated(suit_component_t dst_handle, struct zcbor_string *payload)
{
	return SUIT_ERR_UNSUPPORTED_COMMAND;
}
