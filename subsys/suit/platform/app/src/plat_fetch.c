/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/logging/log.h>
#include <suit_platform_internal.h>
#include <suit_plat_error_convert.h>

#ifdef CONFIG_SUIT_STREAM
#include <sink.h>
#include <sink_selector.h>
#include <dfu_cache_sink.h>
#include <dfu_cache_streamer.h>
#include <generic_address_streamer.h>
#endif /* CONFIG_SUIT_STREAM */

#ifdef CONFIG_SUIT_STREAM_SOURCE_CACHE
#include <dfu_cache_streamer.h>
#endif /* CONFIG_SUIT_STREAM_SOURCE_CACHE */

#ifdef CONFIG_SUIT_STREAM_FETCH_SOURCE_MGR
#include "fetch_source_streamer.h"
#endif /* CONFIG_SUIT_STREAM_FETCH_SOURCE_MGR */

#ifdef CONFIG_SUIT_STREAM_SINK_MEMPTR
#include <memptr_sink.h>
#endif /* CONFIG_SUIT_STREAM_SINK_MEMPTR */

#include <stdbool.h>
#include <suit_platform.h>
#include <suit_memptr_storage.h>
#include <suit_plat_decode_util.h>

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
			       struct zcbor_string *uri, suit_component_type_t *component_type,
			       bool write_enabled)
{
	uint32_t number;
	struct zcbor_string *component_id;

	int ret = suit_plat_component_id_get(dst_handle, &component_id);
	if (ret != SUIT_SUCCESS) {
		LOG_ERR("suit_plat_component_id_get failed: %i", ret);
		return SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
	}

	if (suit_plat_decode_component_type(component_id, component_type) != SUIT_PLAT_SUCCESS) {
		LOG_ERR("suit_plat_decode_component_type failed");
		return SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
	}

	if (!is_type_supported(component_type)) {
		return SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
	}

	if (suit_plat_decode_component_number(component_id, &number) != SUIT_PLAT_SUCCESS) {
		LOG_ERR("Missing component id number in candidate image component");
		return SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
	}

	/* Select sink */
	switch (*component_type) {
#ifdef CONFIG_SUIT_STREAM_SINK_MEMPTR
	case SUIT_COMPONENT_TYPE_CAND_IMG:
	case SUIT_COMPONENT_TYPE_CAND_MFST: { /* memptr_sink */
		memptr_storage_handle_t handle;

		ret = suit_plat_component_impl_data_get(dst_handle, &handle);
		if (ret != SUIT_SUCCESS) {
			LOG_ERR("Unable to get component data for candidate image (err: %d)", ret);
			return ret;
		}

		return suit_plat_err_to_processor_err_convert(suit_memptr_sink_get(sink,
							       handle));
	} break;
#endif /* CONFIG_SUIT_STREAM_SINK_MEMPTR */
#ifdef CONFIG_SUIT_CACHE_RW
	case SUIT_COMPONENT_TYPE_CACHE_POOL: {
		ret = suit_dfu_cache_sink_get(sink, number, uri->value, uri->len, write_enabled);
		if (ret != SUIT_PLAT_SUCCESS) {
			LOG_ERR("Getting cache sink failed");
			return suit_plat_err_to_processor_err_convert(ret);
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

	int ret = verify_and_get_sink(dst_handle, &dst_sink, uri, &component_type, false);
	if (ret != SUIT_SUCCESS) {
		LOG_ERR("Failed to verify component end get end sink");
	}

	if (dst_sink.release != NULL) {
		suit_plat_err_t err = dst_sink.release(dst_sink.ctx);

		if (err != SUIT_PLAT_SUCCESS) {
			LOG_ERR("sink release failed: %i", err);
			return suit_plat_err_to_processor_err_convert(err);
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

	int ret = verify_and_get_sink(dst_handle, &dst_sink, uri, &component_type, true);
	if (ret != SUIT_SUCCESS) {
		LOG_ERR("Failed to verify component end get end sink");
		return ret;
	}

	/* Here other parts of pipe will be instantiated.
	 *	Like decryption and/or decompression sinks.
	 */

	if (dst_sink.erase != NULL) {
		ret = dst_sink.erase(dst_sink.ctx);
		if (ret != SUIT_PLAT_SUCCESS) {
			LOG_ERR("Sink mem erase failed: %i", ret);
			return suit_plat_err_to_processor_err_convert(ret);
		}
	}

	/* Select streamer */
	switch (component_type) {
#ifdef CONFIG_SUIT_STREAM_FETCH_SOURCE_MGR
	case SUIT_COMPONENT_TYPE_CACHE_POOL:
	case SUIT_COMPONENT_TYPE_MEM: {
		ret = suit_fetch_source_stream(uri->value, uri->len, &dst_sink);
		ret = suit_plat_err_to_processor_err_convert(ret);
	} break;
#endif /* SUIT_STREAM_FETCH_SOURCE_MGR */
#if defined(CONFIG_SUIT_CACHE_RW) || defined(SUIT_CACHE)
	case SUIT_COMPONENT_TYPE_CAND_MFST:
	case SUIT_COMPONENT_TYPE_CAND_IMG: {
		ret = suit_dfu_cache_streamer_stream(uri->value, uri->len, &dst_sink);
		ret = suit_plat_err_to_processor_err_convert(ret);
	} break;
#endif
	default:
		ret = SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
		break;
	}

	if (ret == SUIT_SUCCESS && component_type == SUIT_COMPONENT_TYPE_CACHE_POOL)
	{
		suit_dfu_cache_sink_commit(dst_sink.ctx);
	}

	if (dst_sink.release != NULL) {
		suit_plat_err_t err = dst_sink.release(dst_sink.ctx);

		if (err != SUIT_PLAT_SUCCESS) {
			LOG_ERR("sink release failed: %i", err);
			return suit_plat_err_to_processor_err_convert(err);
		}
	}

	return ret;
#else
	return SUIT_ERR_UNSUPPORTED_COMMAND;
#endif /* CONFIG_SUIT_STREAM */
}

int suit_plat_check_fetch_integrated(suit_component_t dst_handle, struct zcbor_string *payload)
{
#ifdef CONFIG_SUIT_STREAM
	struct stream_sink dst_sink;
	suit_component_type_t component_type = SUIT_COMPONENT_TYPE_UNSUPPORTED;

	/* Get component type based on component handle*/
	int ret = suit_plat_component_type_get(dst_handle, &component_type);
	if (ret != SUIT_SUCCESS) {
		LOG_ERR("Failed to decode component type %i", ret);
		return ret;
	}

	if ((component_type != SUIT_COMPONENT_TYPE_CAND_IMG) &&
	    (component_type != SUIT_COMPONENT_TYPE_CAND_MFST)) {
		return SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
	}

#ifndef CONFIG_SUIT_STREAM_SOURCE_MEMPTR
	return SUIT_ERR_UNSUPPORTED_COMMAND;
#endif /* CONFIG_SUIT_STREAM_SOURCE_MEMPTR */

	/* Get dst_sink */
	ret = suit_sink_select(dst_handle, &dst_sink);
	if (ret != SUIT_SUCCESS) {
		LOG_ERR("Selecting sink failed: %i", ret);
		return ret;
	}

	/* Here other parts of pipe will be instantiated.
	 *	Like decryption and/or decompression sinks.
	 */

	if (dst_sink.release != NULL) {
		int err = dst_sink.release(dst_sink.ctx);

		if (err != SUIT_PLAT_SUCCESS) {
			LOG_ERR("sink release failed: %i", err);
			return suit_plat_err_to_processor_err_convert(err);
		}
	}

	return ret;
#else
	return SUIT_ERR_UNSUPPORTED_COMMAND;
#endif /* CONFIG_SUIT_STREAM */
}

int suit_plat_fetch_integrated(suit_component_t dst_handle, struct zcbor_string *payload)
{
#ifdef CONFIG_SUIT_STREAM
	struct stream_sink dst_sink;
	suit_component_type_t component_type = SUIT_COMPONENT_TYPE_UNSUPPORTED;

	/* Get component type based on component handle*/
	int ret = suit_plat_component_type_get(dst_handle, &component_type);
	if (ret != SUIT_SUCCESS) {
		LOG_ERR("Failed to decode component type: %i", ret);
		return ret;
	}

	if ((component_type != SUIT_COMPONENT_TYPE_CAND_IMG) &&
	    (component_type != SUIT_COMPONENT_TYPE_CAND_MFST)) {
		return SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
	}

#ifndef CONFIG_SUIT_STREAM_SOURCE_MEMPTR
	return SUIT_ERR_UNSUPPORTED_COMMAND;
#endif /* CONFIG_SUIT_STREAM_SOURCE_MEMPTR */

	/* Get dst_sink - final destination sink */
	ret = suit_sink_select(dst_handle, &dst_sink);
	if (ret != SUIT_SUCCESS) {
		LOG_ERR("Selecting sink failed: %i", ret);
		return ret;
	}

	/* Here other parts of pipe will be instantiated.
	 *	Like decryption and/or decompression sinks.
	 */

	if (dst_sink.erase != NULL) {
		ret = dst_sink.erase(dst_sink.ctx);
		if (ret != SUIT_PLAT_SUCCESS) {
			LOG_ERR("Sink mem erase failed: %i", ret);
			return suit_plat_err_to_processor_err_convert(ret);
		}
	}

	ret = suit_generic_address_streamer_stream(payload->value, payload->len, &dst_sink);

	if (dst_sink.release != NULL) {
		int err = dst_sink.release(dst_sink.ctx);

		if (err != SUIT_PLAT_SUCCESS) {
			LOG_ERR("sink release failed: %i", err);
			return suit_plat_err_to_processor_err_convert(err);
		}
	}

	return suit_plat_err_to_processor_err_convert(ret);
#else
	return SUIT_ERR_UNSUPPORTED_COMMAND;
#endif /* CONFIG_SUIT_STREAM */
}
