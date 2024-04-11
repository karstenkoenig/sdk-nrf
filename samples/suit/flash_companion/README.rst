.. _suit_flash_companion:

SUIT flash companion
####################

.. contents::
   :local:
   :depth: 2

The flash companion application allows the secure domain firmware to access the external memory during the SUIT firmware upgrade.

Application overview
********************

The flash companion implements a device driver for the external flash device and provides an IPC service to the secure domain.
The secure domain firmware can request from the flash companion to read, erase, or write data to the external memory.

The application is meant to be booted by the secure domain while performing the firmware update process using the SUIT firmware upgrade.

The flash companion firmware is not a stand-alone application.
The application must be built as a child image of a different sample as it inherits the device tree configuration from the parent build.

The application can be build as a child image of your application by enabling the :kconfig:option:`CONFIG_SUIT_BUILD_FLASH_COMPANION` Kconfig option.
The devicetree configuration of the parent build will be automatically applied to the flash companion application.

Requirements
************

The application supports the following development kits:

.. table-from-rows:: /includes/sample_board_rows.txt
   :header: heading
   :rows: nrf54h20dk_nrf54h20_cpuapp

Configuration
*************

|config|

Setup
=====

The application is booted during SUIT firmware upgrade process. See the :ref:`ug_nrf54h20_suit_external_memory` user guide to learn how to setup your application to boot and utilize the flash companion's services during firmware upgrade.

Configuration options
=====================

Check and configure the following configuration option:

.. _CONFIG_SUIT_BUILD_FLASH_COMPANION:

CONFIG_SUIT_BUILD_FLASH_COMPANION - Configuration for the firmware
   This option enables the firmware and builds it as a child image of your application.

Building and running
********************

.. |application path| replace:: :file:`samples/suit/flash_companion`

.. include:: /includes/application_build_and_run.txt

References
**********

The :ref:`ug_nrf54h20_suit_external_memory` user guide explains how to enable external flash support in SUIT firmware upgrade.

Related samples
===============

* :ref:`nrf54h_suit_sample`

Dependencies
************

This application uses the following |NCS| libraries:

* :file:`include/sdfw_services/ssf_client.h`
* `zcbor`_

It uses the following Zephyr libraries:

* :ref:`zephyr:flash_api`

The application also uses drivers from `nrfx`_.
