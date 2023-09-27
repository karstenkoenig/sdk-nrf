#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#
target_include_directories(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_sources_ifdef(CONFIG_INTERDOMAIN_TIMER app PRIVATE idtimer.c)
