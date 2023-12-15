/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef RAM_SINK_H__
#define RAM_SINK_H__

#include <sink.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Get the ram_sink object
 *
 * @param sink Pointer to sink_stream to be filled
 * @param dst Destination address - start of write area
 * @param size Write area size
 * @return SUIT_PLAT_SUCCESS if success otherwise error code.
 */
suit_plat_err_t suit_ram_sink_get(struct stream_sink *sink, uint8_t *dst, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* RAM_SINK_H__ */
