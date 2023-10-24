/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/logging/log.h>
#include <sink_selector.h>
#include <suit_platform_internal.h>
#include <suit_plat_decode_util.h>

#ifdef CONFIG_SUIT_STREAM_SINK_MEMPTR
#include <memptr_sink.h>
#endif /* CONFIG_SUIT_STREAM_SINK_MEMPTR */
#ifdef CONFIG_SUIT_STREAM_SINK_FLASH
#include <flash_sink.h>
#endif /* CONFIG_SUIT_STREAM_SINK_FLASH */
#ifdef CONFIG_SUIT_STREAM_SINK_SDFW
#include <sdfw_sink.h>
#endif /* CONFIG_SUIT_STREAM_SINK_SDFW */

LOG_MODULE_REGISTER(suit_plat_sink_selector, CONFIG_SUIT_LOG_LEVEL);

int select_sink(suit_component_t dst_handle, struct stream_sink *sink)
{
	struct zcbor_string *component_id;
	int ret = 0;
	suit_component_type_t component_type = SUIT_COMPONENT_TYPE_UNSUPPORTED;

	ret = suit_plat_component_id_get(dst_handle, &component_id);

	if (ret != SUIT_SUCCESS) {
		LOG_ERR("suit_plat_component_id_get failed: %i", ret);
		return SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
	}

	if (!suit_plat_decode_component_type(component_id, &component_type)) {
		LOG_ERR("suit_plat_decode_component_type failed");
		return SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
	}

	/* Select sink based on component type */
	switch (component_type) {
#ifdef CONFIG_SUIT_STREAM_SINK_MEMPTR
	case SUIT_COMPONENT_TYPE_CAND_IMG:
	case SUIT_COMPONENT_TYPE_CAND_MFST: { /* memptr_sink */
		uint32_t number;
		memptr_storage_handle handle;

		if (!suit_plat_decode_component_number(component_id, &number)) {
			LOG_ERR("Missing component id number in candidate image component");
			return SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
		}

		ret = suit_plat_component_impl_data_get(dst_handle, &handle);
		if (ret != 0) {
			LOG_ERR("Unable to get component data for candidate image (err: %d)", ret);
			return ret;
		}

		return memptr_sink_get(sink, handle);
	} break;
#endif /* CONFIG_SUIT_STREAM_SINK_MEMPTR */

#ifdef CONFIG_SUIT_STREAM_SINK_FLASH
	case SUIT_COMPONENT_TYPE_MEM: { /* flash_sink */
		memptr_storage_handle handle;
		intptr_t run_address;
		size_t size;

		ret = suit_plat_component_impl_data_get(dst_handle, &handle);
		if (ret != 0) {
			LOG_ERR("Unable to get component data for candidate image (err: %d)", ret);
			return ret;
		}

		if (!suit_plat_decode_address_size(component_id, &run_address, &size)) {
			LOG_ERR("suit_plat_decode_address_size failed");
			return SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
		}

		/* Based on address span given by run_address-(run_address + size), check what type
		 *memory configuration we're working with. Possible cases include:
		 * - Internal MRAM on single controller
		 * - Internal MRAM spanning between two memory controllers
		 * - RAM
		 * - External Flash
		 * - ...
		 *
		 * Select sink based on detected memory configuration.
		 */

		/* Internal MRAM/Flash on single controller */
		ret = flash_sink_get(sink, (uint8_t *)run_address, size, handle);
		if (ret) {
			LOG_ERR("Failed to get flash sink: %i", ret);
			return ret;
		}

		return SUCCESS;
	} break;
#endif /* CONFIG_SUIT_STREAM_SINK_FLASH */
#ifdef CONFIG_SUIT_STREAM_SINK_SDFW
	case SUIT_COMPONENT_TYPE_SOC_SPEC: { /* sdfw_sink */
		uint32_t number;

		if (!suit_plat_decode_component_number(component_id, &number)) {
			LOG_ERR("Missing component id number");
			return SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
		}

		if (1 == number) {
			if (IS_ENABLED(CONFIG_SUIT_STREAM_SINK_SDFW)) {
				return sdfw_sink_get(sink);
			}

			LOG_ERR("SDFW sink not enabled");
		}

		LOG_ERR("Unsupported special component %d", number);
		return SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
	} break;
#endif /* CONFIG_SUIT_STREAM_SINK_SDFW */
	default: {
		LOG_ERR("Unsupported component type: %d", component_type);
		return SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
	}
	}

	return SUIT_ERR_UNSUPPORTED_COMPONENT_ID;
}
