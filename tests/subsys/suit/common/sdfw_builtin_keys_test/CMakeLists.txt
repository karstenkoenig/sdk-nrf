# Copyright (c) 2024 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

if ( (NOT CONFIG_SDFW_IS_UROT) AND (CONFIG_MBEDTLS OR CONFIG_NRF_SECURITY))
  #  Link module with mbedTLS library, that provides PSA crypto APIs.
  zephyr_library_named(sdfw_builtin_keys_test)

if (CONFIG_MBEDTLS)
  zephyr_library_link_libraries(mbedTLS)
endif()

  # Add harmless stub implementations of builtin keys functions if
  # not operating in real SDFW.
  zephyr_library_sources(sdfw_builtin_keys_test.c)
  target_link_libraries(app PUBLIC sdfw_builtin_keys_test)
endif() #  NOT CONFIG_SDFW_IS_UROT AND CONFIG_MBEDTLS
