#
# Copyright (c) 2024 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(nrf_tbr_utils)

set(NRF_TBR_SRC ${ZEPHYR_NRF_MODULE_DIR}/applications/thread_border_router/src)

# GCC 12 show false warnings about array bounds when
# setting IPv4 addr sockaddr struct.
set(CMAKE_C_FLAGS -Wno-array-bounds)

target_include_directories(app PRIVATE
    ${NRF_TBR_SRC}/
    ${ZEPHYR_BASE}/subsys/net/ip
)


FILE(GLOB app_sources src/*.c)
target_sources(app PRIVATE
    ${app_sources}
    # Test file
    ${NRF_TBR_SRC}/net/mdns_server.c
    ${NRF_TBR_SRC}/net/mdns_internal.c
)
