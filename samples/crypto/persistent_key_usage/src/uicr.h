/*
 * Copyright (c) 2025 Nordic Semiconductor ASA.
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-4-Clause
 */
#ifndef SECDOM_INCLUDE_UICR_V2_DEF_H__
#define SECDOM_INCLUDE_UICR_V2_DEF_H__

#include <nrfx.h>

#ifdef __cplusplus
extern "C" {
#endif

/* clang-format off */

/* ================================================= Struct UICRV2_APPROTECT ================================================= */
/**
  * @brief APPROTECT [UICRV2_APPROTECT] (unspecified)
  */
typedef struct {
  __IOM uint32_t  APPLICATION;                       /*!< (@ 0x00000000) APPLICATION access port protection                    */
  __IOM uint32_t  RADIOCORE;                         /*!< (@ 0x00000004) RADIOCORE access port protection                      */
  __IM  uint32_t  RESERVED;
  __IOM uint32_t  CORESIGHT;                         /*!< (@ 0x0000000C) CoreSight access port protection                      */
} NRF_UICRV2_APPROTECT_Type;                         /*!< Size = 16 (0x010)                                                    */

/* UICRV2_APPROTECT_APPLICATION: APPLICATION access port protection */
  #define UICRV2_APPROTECT_APPLICATION_ResetValue (0xBD2328A8UL) /*!< Reset value of APPLICATION register.                     */

/* PALL @Bits 0..31 : (unspecified) */
  #define UICRV2_APPROTECT_APPLICATION_PALL_Pos (0UL) /*!< Position of PALL field.                                             */
  #define UICRV2_APPROTECT_APPLICATION_PALL_Msk (0xFFFFFFFFUL << UICRV2_APPROTECT_APPLICATION_PALL_Pos) /*!< Bit mask of PALL
                                                                            field.*/
  #define UICRV2_APPROTECT_APPLICATION_PALL_Min (0x1730C77FUL) /*!< Min enumerator value of PALL field.                        */
  #define UICRV2_APPROTECT_APPLICATION_PALL_Max (0xFFFFFFFFUL) /*!< Max enumerator value of PALL field.                        */
  #define UICRV2_APPROTECT_APPLICATION_PALL_Unprotected (0xBD2328A8UL) /*!< (unspecified)                                      */
  #define UICRV2_APPROTECT_APPLICATION_PALL_Profile1 (0x1730C77FUL) /*!< (unspecified)                                         */
  #define UICRV2_APPROTECT_APPLICATION_PALL_Profile2 (0xF05F1363UL) /*!< (unspecified)                                         */
  #define UICRV2_APPROTECT_APPLICATION_PALL_Profile3 (0x488C5ED6UL) /*!< (unspecified)                                         */
  #define UICRV2_APPROTECT_APPLICATION_PALL_Profile4 (0x83C6B58DUL) /*!< (unspecified)                                         */
  #define UICRV2_APPROTECT_APPLICATION_PALL_Protected (0xFFFFFFFFUL) /*!< (unspecified)                                        */


/* UICRV2_APPROTECT_RADIOCORE: RADIOCORE access port protection */
  #define UICRV2_APPROTECT_RADIOCORE_ResetValue (0xBD2328A8UL) /*!< Reset value of RADIOCORE register.                         */

/* PALL @Bits 0..31 : (unspecified) */
  #define UICRV2_APPROTECT_RADIOCORE_PALL_Pos (0UL)  /*!< Position of PALL field.                                              */
  #define UICRV2_APPROTECT_RADIOCORE_PALL_Msk (0xFFFFFFFFUL << UICRV2_APPROTECT_RADIOCORE_PALL_Pos) /*!< Bit mask of PALL
                                                                            field.*/
  #define UICRV2_APPROTECT_RADIOCORE_PALL_Min (0x1730C77FUL) /*!< Min enumerator value of PALL field.                          */
  #define UICRV2_APPROTECT_RADIOCORE_PALL_Max (0xFFFFFFFFUL) /*!< Max enumerator value of PALL field.                          */
  #define UICRV2_APPROTECT_RADIOCORE_PALL_Unprotected (0xBD2328A8UL) /*!< (unspecified)                                        */
  #define UICRV2_APPROTECT_RADIOCORE_PALL_Profile1 (0x1730C77FUL) /*!< (unspecified)                                           */
  #define UICRV2_APPROTECT_RADIOCORE_PALL_Profile2 (0xF05F1363UL) /*!< (unspecified)                                           */
  #define UICRV2_APPROTECT_RADIOCORE_PALL_Profile3 (0x488C5ED6UL) /*!< (unspecified)                                           */
  #define UICRV2_APPROTECT_RADIOCORE_PALL_Profile4 (0x83C6B58DUL) /*!< (unspecified)                                           */
  #define UICRV2_APPROTECT_RADIOCORE_PALL_Protected (0xFFFFFFFFUL) /*!< (unspecified)                                          */


/* UICRV2_APPROTECT_CORESIGHT: CoreSight access port protection */
  #define UICRV2_APPROTECT_CORESIGHT_ResetValue (0xBD2328A8UL) /*!< Reset value of CORESIGHT register.                         */

/* PALL @Bits 0..31 : (unspecified) */
  #define UICRV2_APPROTECT_CORESIGHT_PALL_Pos (0UL)  /*!< Position of PALL field.                                              */
  #define UICRV2_APPROTECT_CORESIGHT_PALL_Msk (0xFFFFFFFFUL << UICRV2_APPROTECT_CORESIGHT_PALL_Pos) /*!< Bit mask of PALL
                                                                            field.*/
  #define UICRV2_APPROTECT_CORESIGHT_PALL_Min (0x1730C77FUL) /*!< Min enumerator value of PALL field.                          */
  #define UICRV2_APPROTECT_CORESIGHT_PALL_Max (0xFFFFFFFFUL) /*!< Max enumerator value of PALL field.                          */
  #define UICRV2_APPROTECT_CORESIGHT_PALL_Unprotected (0xBD2328A8UL) /*!< (unspecified)                                        */
  #define UICRV2_APPROTECT_CORESIGHT_PALL_Profile1 (0x1730C77FUL) /*!< (unspecified)                                           */
  #define UICRV2_APPROTECT_CORESIGHT_PALL_Profile2 (0xF05F1363UL) /*!< (unspecified)                                           */
  #define UICRV2_APPROTECT_CORESIGHT_PALL_Profile3 (0x488C5ED6UL) /*!< (unspecified)                                           */
  #define UICRV2_APPROTECT_CORESIGHT_PALL_Profile4 (0x83C6B58DUL) /*!< (unspecified)                                           */
  #define UICRV2_APPROTECT_CORESIGHT_PALL_Protected (0xFFFFFFFFUL) /*!< (unspecified)                                          */



/* =============================================== Struct UICRV2_PROTECTEDMEM ================================================ */
/**
  * @brief PROTECTEDMEM [UICRV2_PROTECTEDMEM] (unspecified)
  */
typedef struct {
  __IOM uint32_t  ENABLE;                            /*!< (@ 0x00000000) Enable the Protected Memory region                    */
  __IOM uint32_t  SIZE4KB;                           /*!< (@ 0x00000004) Protected Memory region size in 4 kiB blocks.         */
} NRF_UICRV2_PROTECTEDMEM_Type;                      /*!< Size = 8 (0x008)                                                     */

/* UICRV2_PROTECTEDMEM_ENABLE: Enable the Protected Memory region */
  #define UICRV2_PROTECTEDMEM_ENABLE_ResetValue (0xBD2328A8UL) /*!< Reset value of ENABLE register.                            */

/* ENABLE @Bits 0..31 : (unspecified) */
  #define UICRV2_PROTECTEDMEM_ENABLE_ENABLE_Pos (0UL) /*!< Position of ENABLE field.                                           */
  #define UICRV2_PROTECTEDMEM_ENABLE_ENABLE_Msk (0xFFFFFFFFUL << UICRV2_PROTECTEDMEM_ENABLE_ENABLE_Pos) /*!< Bit mask of ENABLE
                                                                            field.*/
  #define UICRV2_PROTECTEDMEM_ENABLE_ENABLE_Min (0xBD2328A8UL) /*!< Min enumerator value of ENABLE field.                      */
  #define UICRV2_PROTECTEDMEM_ENABLE_ENABLE_Max (0xFFFFFFFFUL) /*!< Max enumerator value of ENABLE field.                      */
  #define UICRV2_PROTECTEDMEM_ENABLE_ENABLE_Disabled (0xBD2328A8UL) /*!< (unspecified)                                         */
  #define UICRV2_PROTECTEDMEM_ENABLE_ENABLE_Enabled (0xFFFFFFFFUL) /*!< (unspecified)                                          */


/* UICRV2_PROTECTEDMEM_SIZE4KB: Protected Memory region size in 4 kiB blocks. */
  #define UICRV2_PROTECTEDMEM_SIZE4KB_ResetValue (0xBD2328A8UL) /*!< Reset value of SIZE4KB register.                          */

/* SIZE4KB @Bits 0..31 : (unspecified) */
  #define UICRV2_PROTECTEDMEM_SIZE4KB_SIZE4KB_Pos (0UL) /*!< Position of SIZE4KB field.                                        */
  #define UICRV2_PROTECTEDMEM_SIZE4KB_SIZE4KB_Msk (0xFFFFFFFFUL << UICRV2_PROTECTEDMEM_SIZE4KB_SIZE4KB_Pos) /*!< Bit mask of
                                                                            SIZE4KB field.*/



/* ================================================= Struct UICRV2_WDTSTART ================================================== */
/**
  * @brief WDTSTART [UICRV2_WDTSTART] Start a local watchdog timer ahead of the CPU boot.
  */
typedef struct {
  __IOM uint32_t  ENABLE;                            /*!< (@ 0x00000000) Enable watchdog timer start.                          */
  __IOM uint32_t  INSTANCE;                          /*!< (@ 0x00000004) Watchdog timer instance.                              */
  __IOM uint32_t  CRV;                               /*!< (@ 0x00000008) Initial CRV (Counter Reload Value) register value.    */
} NRF_UICRV2_WDTSTART_Type;                          /*!< Size = 12 (0x00C)                                                    */

/* UICRV2_WDTSTART_ENABLE: Enable watchdog timer start. */
  #define UICRV2_WDTSTART_ENABLE_ResetValue (0xBD2328A8UL) /*!< Reset value of ENABLE register.                                */

/* ENABLE @Bits 0..31 : (unspecified) */
  #define UICRV2_WDTSTART_ENABLE_ENABLE_Pos (0UL)    /*!< Position of ENABLE field.                                            */
  #define UICRV2_WDTSTART_ENABLE_ENABLE_Msk (0xFFFFFFFFUL << UICRV2_WDTSTART_ENABLE_ENABLE_Pos) /*!< Bit mask of ENABLE field. */
  #define UICRV2_WDTSTART_ENABLE_ENABLE_Min (0xBD2328A8UL) /*!< Min enumerator value of ENABLE field.                          */
  #define UICRV2_WDTSTART_ENABLE_ENABLE_Max (0xFFFFFFFFUL) /*!< Max enumerator value of ENABLE field.                          */
  #define UICRV2_WDTSTART_ENABLE_ENABLE_Disabled (0xBD2328A8UL) /*!< (unspecified)                                             */
  #define UICRV2_WDTSTART_ENABLE_ENABLE_Enabled (0xFFFFFFFFUL) /*!< (unspecified)                                              */


/* UICRV2_WDTSTART_INSTANCE: Watchdog timer instance. */
  #define UICRV2_WDTSTART_INSTANCE_ResetValue (0xBD2328A8UL) /*!< Reset value of INSTANCE register.                            */

/* INSTANCE @Bits 0..31 : (unspecified) */
  #define UICRV2_WDTSTART_INSTANCE_INSTANCE_Pos (0UL) /*!< Position of INSTANCE field.                                         */
  #define UICRV2_WDTSTART_INSTANCE_INSTANCE_Msk (0xFFFFFFFFUL << UICRV2_WDTSTART_INSTANCE_INSTANCE_Pos) /*!< Bit mask of
                                                                            INSTANCE field.*/
  #define UICRV2_WDTSTART_INSTANCE_INSTANCE_Min (0x1730C77FUL) /*!< Min enumerator value of INSTANCE field.                    */
  #define UICRV2_WDTSTART_INSTANCE_INSTANCE_Max (0xBD2328A8UL) /*!< Max enumerator value of INSTANCE field.                    */
  #define UICRV2_WDTSTART_INSTANCE_INSTANCE_WDT0 (0xBD2328A8UL) /*!< (unspecified)                                             */
  #define UICRV2_WDTSTART_INSTANCE_INSTANCE_WDT1 (0x1730C77FUL) /*!< (unspecified)                                             */


/* UICRV2_WDTSTART_CRV: Initial CRV (Counter Reload Value) register value. */
  #define UICRV2_WDTSTART_CRV_ResetValue (0xBD2328A8UL) /*!< Reset value of CRV register.                                      */

/* CRV @Bits 0..31 : Initial CRV value for the WDT */
  #define UICRV2_WDTSTART_CRV_CRV_Pos (0UL)          /*!< Position of CRV field.                                               */
  #define UICRV2_WDTSTART_CRV_CRV_Msk (0xFFFFFFFFUL << UICRV2_WDTSTART_CRV_CRV_Pos) /*!< Bit mask of CRV field.                */
  #define UICRV2_WDTSTART_CRV_CRV_Min (0xFUL)        /*!< Min value of CRV field.                                              */
  #define UICRV2_WDTSTART_CRV_CRV_Max (0xFFFFFFFFUL) /*!< Max size of CRV field.                                               */



/* =========================================== Struct UICRV2_SECURESTORAGE_CRYPTO ============================================ */
/**
  * @brief CRYPTO [UICRV2_SECURESTORAGE_CRYPTO] Secure Storage partitions for the Cryptographic service
  */
typedef struct {
  __IOM uint32_t  APPLICATIONSIZE1KB;                /*!< (@ 0x00000000) Size of the APPLICATION partition in 1 kiB blocks     */
  __IOM uint32_t  RADIOCORESIZE1KB;                  /*!< (@ 0x00000004) Size of the RADIOCORE partition in 1 kiB blocks       */
} NRF_UICRV2_SECURESTORAGE_CRYPTO_Type;              /*!< Size = 8 (0x008)                                                     */

/* UICRV2_SECURESTORAGE_CRYPTO_APPLICATIONSIZE1KB: Size of the APPLICATION partition in 1 kiB blocks */
  #define UICRV2_SECURESTORAGE_CRYPTO_APPLICATIONSIZE1KB_ResetValue (0xBD2328A8UL) /*!< Reset value of APPLICATIONSIZE1KB
                                                                            register.*/

/* SIZE1KB @Bits 0..31 : (unspecified) */
  #define UICRV2_SECURESTORAGE_CRYPTO_APPLICATIONSIZE1KB_SIZE1KB_Pos (0UL) /*!< Position of SIZE1KB field.                     */
  #define UICRV2_SECURESTORAGE_CRYPTO_APPLICATIONSIZE1KB_SIZE1KB_Msk (0xFFFFFFFFUL << UICRV2_SECURESTORAGE_CRYPTO_APPLICATIONSIZE1KB_SIZE1KB_Pos)
                                                                            /*!< Bit mask of SIZE1KB field.*/


/* UICRV2_SECURESTORAGE_CRYPTO_RADIOCORESIZE1KB: Size of the RADIOCORE partition in 1 kiB blocks */
  #define UICRV2_SECURESTORAGE_CRYPTO_RADIOCORESIZE1KB_ResetValue (0xBD2328A8UL) /*!< Reset value of RADIOCORESIZE1KB register.*/

/* SIZE1KB @Bits 0..31 : (unspecified) */
  #define UICRV2_SECURESTORAGE_CRYPTO_RADIOCORESIZE1KB_SIZE1KB_Pos (0UL) /*!< Position of SIZE1KB field.                       */
  #define UICRV2_SECURESTORAGE_CRYPTO_RADIOCORESIZE1KB_SIZE1KB_Msk (0xFFFFFFFFUL << UICRV2_SECURESTORAGE_CRYPTO_RADIOCORESIZE1KB_SIZE1KB_Pos)
                                                                            /*!< Bit mask of SIZE1KB field.*/



/* ============================================= Struct UICRV2_SECURESTORAGE_ITS ============================================= */
/**
  * @brief ITS [UICRV2_SECURESTORAGE_ITS] Secure Storage partitions for the Internal Trusted Storage service
  */
typedef struct {
  __IOM uint32_t  APPLICATIONSIZE1KB;                /*!< (@ 0x00000000) Size of the APPLICATION partition in 1 kiB blocks     */
  __IOM uint32_t  RADIOCORESIZE1KB;                  /*!< (@ 0x00000004) Size of the RADIOCORE partition in 1 kiB blocks       */
} NRF_UICRV2_SECURESTORAGE_ITS_Type;                 /*!< Size = 8 (0x008)                                                     */

/* UICRV2_SECURESTORAGE_ITS_APPLICATIONSIZE1KB: Size of the APPLICATION partition in 1 kiB blocks */
  #define UICRV2_SECURESTORAGE_ITS_APPLICATIONSIZE1KB_ResetValue (0xBD2328A8UL) /*!< Reset value of APPLICATIONSIZE1KB
                                                                            register.*/

/* SIZE1KB @Bits 0..31 : (unspecified) */
  #define UICRV2_SECURESTORAGE_ITS_APPLICATIONSIZE1KB_SIZE1KB_Pos (0UL) /*!< Position of SIZE1KB field.                        */
  #define UICRV2_SECURESTORAGE_ITS_APPLICATIONSIZE1KB_SIZE1KB_Msk (0xFFFFFFFFUL << UICRV2_SECURESTORAGE_ITS_APPLICATIONSIZE1KB_SIZE1KB_Pos)
                                                                            /*!< Bit mask of SIZE1KB field.*/


/* UICRV2_SECURESTORAGE_ITS_RADIOCORESIZE1KB: Size of the RADIOCORE partition in 1 kiB blocks */
  #define UICRV2_SECURESTORAGE_ITS_RADIOCORESIZE1KB_ResetValue (0xBD2328A8UL) /*!< Reset value of RADIOCORESIZE1KB register.   */

/* SIZE1KB @Bits 0..31 : (unspecified) */
  #define UICRV2_SECURESTORAGE_ITS_RADIOCORESIZE1KB_SIZE1KB_Pos (0UL) /*!< Position of SIZE1KB field.                          */
  #define UICRV2_SECURESTORAGE_ITS_RADIOCORESIZE1KB_SIZE1KB_Msk (0xFFFFFFFFUL << UICRV2_SECURESTORAGE_ITS_RADIOCORESIZE1KB_SIZE1KB_Pos)
                                                                            /*!< Bit mask of SIZE1KB field.*/



/* =============================================== Struct UICRV2_SECURESTORAGE =============================================== */
/**
  * @brief SECURESTORAGE [UICRV2_SECURESTORAGE] Secure Storage configuration
  */
typedef struct {
  __IOM uint32_t  ENABLE;                            /*!< (@ 0x00000000) Enable the Secure Storage                             */
  __IOM uint32_t  ADDRESS;                           /*!< (@ 0x00000004) Start address of the Secure Storage region            */
  __IOM NRF_UICRV2_SECURESTORAGE_CRYPTO_Type CRYPTO; /*!< (@ 0x00000008) Secure Storage partitions for the Cryptographic
                                                                         service*/
  __IOM NRF_UICRV2_SECURESTORAGE_ITS_Type ITS;       /*!< (@ 0x00000010) Secure Storage partitions for the Internal Trusted
                                                                         Storage service*/
} NRF_UICRV2_SECURESTORAGE_Type;                     /*!< Size = 24 (0x018)                                                    */

/* UICRV2_SECURESTORAGE_ENABLE: Enable the Secure Storage */
  #define UICRV2_SECURESTORAGE_ENABLE_ResetValue (0xBD2328A8UL) /*!< Reset value of ENABLE register.                           */

/* ENABLE @Bits 0..31 : (unspecified) */
  #define UICRV2_SECURESTORAGE_ENABLE_ENABLE_Pos (0UL) /*!< Position of ENABLE field.                                          */
  #define UICRV2_SECURESTORAGE_ENABLE_ENABLE_Msk (0xFFFFFFFFUL << UICRV2_SECURESTORAGE_ENABLE_ENABLE_Pos) /*!< Bit mask of
                                                                            ENABLE field.*/
  #define UICRV2_SECURESTORAGE_ENABLE_ENABLE_Min (0xBD2328A8UL) /*!< Min enumerator value of ENABLE field.                     */
  #define UICRV2_SECURESTORAGE_ENABLE_ENABLE_Max (0xFFFFFFFFUL) /*!< Max enumerator value of ENABLE field.                     */
  #define UICRV2_SECURESTORAGE_ENABLE_ENABLE_Disabled (0xBD2328A8UL) /*!< (unspecified)                                        */
  #define UICRV2_SECURESTORAGE_ENABLE_ENABLE_Enabled (0xFFFFFFFFUL) /*!< (unspecified)                                         */


/* UICRV2_SECURESTORAGE_ADDRESS: Start address of the Secure Storage region */
  #define UICRV2_SECURESTORAGE_ADDRESS_ResetValue (0xBD2328A8UL) /*!< Reset value of ADDRESS register.                         */

/* ADDRESS @Bits 0..31 : (unspecified) */
  #define UICRV2_SECURESTORAGE_ADDRESS_ADDRESS_Pos (0UL) /*!< Position of ADDRESS field.                                       */
  #define UICRV2_SECURESTORAGE_ADDRESS_ADDRESS_Msk (0xFFFFFFFFUL << UICRV2_SECURESTORAGE_ADDRESS_ADDRESS_Pos) /*!< Bit mask of
                                                                            ADDRESS field.*/



/* ================================================ Struct UICRV2_PERIPHCONF ================================================= */
/**
  * @brief PERIPHCONF [UICRV2_PERIPHCONF] Global domain peripheral configuration
  */
typedef struct {
  __IOM uint32_t  ENABLE;                            /*!< (@ 0x00000000) Enable the global domain peripheral configuration     */
  __IOM uint32_t  ADDRESS;                           /*!< (@ 0x00000004) Start address of the array of peripheral configuration
                                                                         entries*/
  __IOM uint32_t  MAXCOUNT;                          /*!< (@ 0x00000008) Maximum number of peripheral configuration entries    */
} NRF_UICRV2_PERIPHCONF_Type;                        /*!< Size = 12 (0x00C)                                                    */

/* UICRV2_PERIPHCONF_ENABLE: Enable the global domain peripheral configuration */
  #define UICRV2_PERIPHCONF_ENABLE_ResetValue (0xBD2328A8UL) /*!< Reset value of ENABLE register.                              */

/* ENABLE @Bits 0..31 : (unspecified) */
  #define UICRV2_PERIPHCONF_ENABLE_ENABLE_Pos (0UL)  /*!< Position of ENABLE field.                                            */
  #define UICRV2_PERIPHCONF_ENABLE_ENABLE_Msk (0xFFFFFFFFUL << UICRV2_PERIPHCONF_ENABLE_ENABLE_Pos) /*!< Bit mask of ENABLE
                                                                            field.*/
  #define UICRV2_PERIPHCONF_ENABLE_ENABLE_Min (0xBD2328A8UL) /*!< Min enumerator value of ENABLE field.                        */
  #define UICRV2_PERIPHCONF_ENABLE_ENABLE_Max (0xFFFFFFFFUL) /*!< Max enumerator value of ENABLE field.                        */
  #define UICRV2_PERIPHCONF_ENABLE_ENABLE_Disabled (0xBD2328A8UL) /*!< (unspecified)                                           */
  #define UICRV2_PERIPHCONF_ENABLE_ENABLE_Enabled (0xFFFFFFFFUL) /*!< (unspecified)                                            */


/* UICRV2_PERIPHCONF_ADDRESS: Start address of the array of peripheral configuration entries */
  #define UICRV2_PERIPHCONF_ADDRESS_ResetValue (0xBD2328A8UL) /*!< Reset value of ADDRESS register.                            */

/* ADDRESS @Bits 0..31 : (unspecified) */
  #define UICRV2_PERIPHCONF_ADDRESS_ADDRESS_Pos (0UL) /*!< Position of ADDRESS field.                                          */
  #define UICRV2_PERIPHCONF_ADDRESS_ADDRESS_Msk (0xFFFFFFFFUL << UICRV2_PERIPHCONF_ADDRESS_ADDRESS_Pos) /*!< Bit mask of ADDRESS
                                                                            field.*/


/* UICRV2_PERIPHCONF_MAXCOUNT: Maximum number of peripheral configuration entries */
  #define UICRV2_PERIPHCONF_MAXCOUNT_ResetValue (0xBD2328A8UL) /*!< Reset value of MAXCOUNT register.                          */

/* MAXCOUNT @Bits 0..31 : (unspecified) */
  #define UICRV2_PERIPHCONF_MAXCOUNT_MAXCOUNT_Pos (0UL) /*!< Position of MAXCOUNT field.                                       */
  #define UICRV2_PERIPHCONF_MAXCOUNT_MAXCOUNT_Msk (0xFFFFFFFFUL << UICRV2_PERIPHCONF_MAXCOUNT_MAXCOUNT_Pos) /*!< Bit mask of
                                                                            MAXCOUNT field.*/



/* ================================================== Struct UICRV2_MPCCONF ================================================== */
/**
  * @brief MPCCONF [UICRV2_MPCCONF] Global domain MPC configuration
  */
typedef struct {
  __IOM uint32_t  ENABLE;                            /*!< (@ 0x00000000) Enable the global domain MPC configuration            */
  __IOM uint32_t  ADDRESS;                           /*!< (@ 0x00000004) Start address of the array of MPC configuration
                                                                         entries*/
  __IOM uint32_t  MAXCOUNT;                          /*!< (@ 0x00000008) Maximum number of MPC configuration entries           */
} NRF_UICRV2_MPCCONF_Type;                           /*!< Size = 12 (0x00C)                                                    */

/* UICRV2_MPCCONF_ENABLE: Enable the global domain MPC configuration */
  #define UICRV2_MPCCONF_ENABLE_ResetValue (0xBD2328A8UL) /*!< Reset value of ENABLE register.                                 */

/* ENABLE @Bits 0..31 : (unspecified) */
  #define UICRV2_MPCCONF_ENABLE_ENABLE_Pos (0UL)     /*!< Position of ENABLE field.                                            */
  #define UICRV2_MPCCONF_ENABLE_ENABLE_Msk (0xFFFFFFFFUL << UICRV2_MPCCONF_ENABLE_ENABLE_Pos) /*!< Bit mask of ENABLE field.   */
  #define UICRV2_MPCCONF_ENABLE_ENABLE_Min (0xBD2328A8UL) /*!< Min enumerator value of ENABLE field.                           */
  #define UICRV2_MPCCONF_ENABLE_ENABLE_Max (0xFFFFFFFFUL) /*!< Max enumerator value of ENABLE field.                           */
  #define UICRV2_MPCCONF_ENABLE_ENABLE_Disabled (0xBD2328A8UL) /*!< (unspecified)                                              */
  #define UICRV2_MPCCONF_ENABLE_ENABLE_Enabled (0xFFFFFFFFUL) /*!< (unspecified)                                               */


/* UICRV2_MPCCONF_ADDRESS: Start address of the array of MPC configuration entries */
  #define UICRV2_MPCCONF_ADDRESS_ResetValue (0xBD2328A8UL) /*!< Reset value of ADDRESS register.                               */

/* ADDRESS @Bits 0..31 : (unspecified) */
  #define UICRV2_MPCCONF_ADDRESS_ADDRESS_Pos (0UL)   /*!< Position of ADDRESS field.                                           */
  #define UICRV2_MPCCONF_ADDRESS_ADDRESS_Msk (0xFFFFFFFFUL << UICRV2_MPCCONF_ADDRESS_ADDRESS_Pos) /*!< Bit mask of ADDRESS
                                                                            field.*/


/* UICRV2_MPCCONF_MAXCOUNT: Maximum number of MPC configuration entries */
  #define UICRV2_MPCCONF_MAXCOUNT_ResetValue (0xBD2328A8UL) /*!< Reset value of MAXCOUNT register.                             */

/* MAXCOUNT @Bits 0..31 : (unspecified) */
  #define UICRV2_MPCCONF_MAXCOUNT_MAXCOUNT_Pos (0UL) /*!< Position of MAXCOUNT field.                                          */
  #define UICRV2_MPCCONF_MAXCOUNT_MAXCOUNT_Msk (0xFFFFFFFFUL << UICRV2_MPCCONF_MAXCOUNT_MAXCOUNT_Pos) /*!< Bit mask of MAXCOUNT
                                                                            field.*/



/* ============================================= Struct UICRV2_SECONDARY_TRIGGER ============================================= */
/**
  * @brief TRIGGER [UICRV2_SECONDARY_TRIGGER] Automatic triggers for reset into secondary firmware
  */
typedef struct {
  __IOM uint32_t  ENABLE;                            /*!< (@ 0x00000000) Enable automatic triggers for reset into secondary
                                                                         firmware*/
  __IOM uint32_t  RESETREAS;                         /*!< (@ 0x00000004) Reset reasons that trigger automatic reset into
                                                                         secondary firmware*/
  __IM  uint32_t  RESERVED;
} NRF_UICRV2_SECONDARY_TRIGGER_Type;                 /*!< Size = 12 (0x00C)                                                    */

/* UICRV2_SECONDARY_TRIGGER_ENABLE: Enable automatic triggers for reset into secondary firmware */
  #define UICRV2_SECONDARY_TRIGGER_ENABLE_ResetValue (0xBD2328A8UL) /*!< Reset value of ENABLE register.                       */

/* ENABLE @Bits 0..31 : (unspecified) */
  #define UICRV2_SECONDARY_TRIGGER_ENABLE_ENABLE_Pos (0UL) /*!< Position of ENABLE field.                                      */
  #define UICRV2_SECONDARY_TRIGGER_ENABLE_ENABLE_Msk (0xFFFFFFFFUL << UICRV2_SECONDARY_TRIGGER_ENABLE_ENABLE_Pos) /*!< Bit mask
                                                                            of ENABLE field.*/
  #define UICRV2_SECONDARY_TRIGGER_ENABLE_ENABLE_Min (0xBD2328A8UL) /*!< Min enumerator value of ENABLE field.                 */
  #define UICRV2_SECONDARY_TRIGGER_ENABLE_ENABLE_Max (0xFFFFFFFFUL) /*!< Max enumerator value of ENABLE field.                 */
  #define UICRV2_SECONDARY_TRIGGER_ENABLE_ENABLE_Disabled (0xBD2328A8UL) /*!< (unspecified)                                    */
  #define UICRV2_SECONDARY_TRIGGER_ENABLE_ENABLE_Enabled (0xFFFFFFFFUL) /*!< (unspecified)                                     */


/* UICRV2_SECONDARY_TRIGGER_RESETREAS: Reset reasons that trigger automatic reset into secondary firmware */
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_ResetValue (0xBD2328A8UL) /*!< Reset value of RESETREAS register.                 */

/* APPLICATIONWDT0 @Bit 0 : (unspecified) */
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_APPLICATIONWDT0_Pos (0UL) /*!< Position of APPLICATIONWDT0 field.                 */
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_APPLICATIONWDT0_Msk (0x1UL << UICRV2_SECONDARY_TRIGGER_RESETREAS_APPLICATIONWDT0_Pos)
                                                                            /*!< Bit mask of APPLICATIONWDT0 field.*/
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_APPLICATIONWDT0_Min (0x0UL) /*!< Min enumerator value of APPLICATIONWDT0 field.   */
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_APPLICATIONWDT0_Max (0x1UL) /*!< Max enumerator value of APPLICATIONWDT0 field.   */
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_APPLICATIONWDT0_Enabled (0x1UL) /*!< (unspecified)                                */
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_APPLICATIONWDT0_Disabled (0x0UL) /*!< (unspecified)                               */

/* APPLICATIONWDT1 @Bit 1 : (unspecified) */
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_APPLICATIONWDT1_Pos (1UL) /*!< Position of APPLICATIONWDT1 field.                 */
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_APPLICATIONWDT1_Msk (0x1UL << UICRV2_SECONDARY_TRIGGER_RESETREAS_APPLICATIONWDT1_Pos)
                                                                            /*!< Bit mask of APPLICATIONWDT1 field.*/
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_APPLICATIONWDT1_Min (0x0UL) /*!< Min enumerator value of APPLICATIONWDT1 field.   */
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_APPLICATIONWDT1_Max (0x1UL) /*!< Max enumerator value of APPLICATIONWDT1 field.   */
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_APPLICATIONWDT1_Enabled (0x1UL) /*!< (unspecified)                                */
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_APPLICATIONWDT1_Disabled (0x0UL) /*!< (unspecified)                               */

/* APPLICATIONLOCKUP @Bit 3 : (unspecified) */
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_APPLICATIONLOCKUP_Pos (3UL) /*!< Position of APPLICATIONLOCKUP field.             */
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_APPLICATIONLOCKUP_Msk (0x1UL << UICRV2_SECONDARY_TRIGGER_RESETREAS_APPLICATIONLOCKUP_Pos)
                                                                            /*!< Bit mask of APPLICATIONLOCKUP field.*/
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_APPLICATIONLOCKUP_Min (0x0UL) /*!< Min enumerator value of APPLICATIONLOCKUP
                                                                            field.*/
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_APPLICATIONLOCKUP_Max (0x1UL) /*!< Max enumerator value of APPLICATIONLOCKUP
                                                                            field.*/
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_APPLICATIONLOCKUP_Enabled (0x1UL) /*!< (unspecified)                              */
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_APPLICATIONLOCKUP_Disabled (0x0UL) /*!< (unspecified)                             */

/* RADIOCOREWDT0 @Bit 5 : (unspecified) */
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_RADIOCOREWDT0_Pos (5UL) /*!< Position of RADIOCOREWDT0 field.                     */
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_RADIOCOREWDT0_Msk (0x1UL << UICRV2_SECONDARY_TRIGGER_RESETREAS_RADIOCOREWDT0_Pos)
                                                                            /*!< Bit mask of RADIOCOREWDT0 field.*/
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_RADIOCOREWDT0_Min (0x0UL) /*!< Min enumerator value of RADIOCOREWDT0 field.       */
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_RADIOCOREWDT0_Max (0x1UL) /*!< Max enumerator value of RADIOCOREWDT0 field.       */
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_RADIOCOREWDT0_Enabled (0x1UL) /*!< (unspecified)                                  */
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_RADIOCOREWDT0_Disabled (0x0UL) /*!< (unspecified)                                 */

/* RADIOCOREWDT1 @Bit 6 : (unspecified) */
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_RADIOCOREWDT1_Pos (6UL) /*!< Position of RADIOCOREWDT1 field.                     */
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_RADIOCOREWDT1_Msk (0x1UL << UICRV2_SECONDARY_TRIGGER_RESETREAS_RADIOCOREWDT1_Pos)
                                                                            /*!< Bit mask of RADIOCOREWDT1 field.*/
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_RADIOCOREWDT1_Min (0x0UL) /*!< Min enumerator value of RADIOCOREWDT1 field.       */
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_RADIOCOREWDT1_Max (0x1UL) /*!< Max enumerator value of RADIOCOREWDT1 field.       */
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_RADIOCOREWDT1_Enabled (0x1UL) /*!< (unspecified)                                  */
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_RADIOCOREWDT1_Disabled (0x0UL) /*!< (unspecified)                                 */

/* RADIOCORELOCKUP @Bit 8 : (unspecified) */
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_RADIOCORELOCKUP_Pos (8UL) /*!< Position of RADIOCORELOCKUP field.                 */
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_RADIOCORELOCKUP_Msk (0x1UL << UICRV2_SECONDARY_TRIGGER_RESETREAS_RADIOCORELOCKUP_Pos)
                                                                            /*!< Bit mask of RADIOCORELOCKUP field.*/
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_RADIOCORELOCKUP_Min (0x0UL) /*!< Min enumerator value of RADIOCORELOCKUP field.   */
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_RADIOCORELOCKUP_Max (0x1UL) /*!< Max enumerator value of RADIOCORELOCKUP field.   */
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_RADIOCORELOCKUP_Enabled (0x1UL) /*!< (unspecified)                                */
  #define UICRV2_SECONDARY_TRIGGER_RESETREAS_RADIOCORELOCKUP_Disabled (0x0UL) /*!< (unspecified)                               */



/* ========================================== Struct UICRV2_SECONDARY_PROTECTEDMEM =========================================== */
/**
  * @brief PROTECTEDMEM [UICRV2_SECONDARY_PROTECTEDMEM] Protected Memory region for the secondary firmware.
  */
typedef struct {
  __IOM uint32_t  ENABLE;                            /*!< (@ 0x00000000) Enable Protected Memory region for the secondary
                                                                         firmware. The region starts at ADDRESS.*/
  __IOM uint32_t  SIZE4KB;                           /*!< (@ 0x00000004) Protected Memory region size for the secondary
                                                                         firmware.*/
} NRF_UICRV2_SECONDARY_PROTECTEDMEM_Type;            /*!< Size = 8 (0x008)                                                     */

/* UICRV2_SECONDARY_PROTECTEDMEM_ENABLE: Enable Protected Memory region for the secondary firmware. The region starts at
                                          ADDRESS. */

  #define UICRV2_SECONDARY_PROTECTEDMEM_ENABLE_ResetValue (0xBD2328A8UL) /*!< Reset value of ENABLE register.                  */

/* ENABLE @Bits 0..31 : (unspecified) */
  #define UICRV2_SECONDARY_PROTECTEDMEM_ENABLE_ENABLE_Pos (0UL) /*!< Position of ENABLE field.                                 */
  #define UICRV2_SECONDARY_PROTECTEDMEM_ENABLE_ENABLE_Msk (0xFFFFFFFFUL << UICRV2_SECONDARY_PROTECTEDMEM_ENABLE_ENABLE_Pos) /*!<
                                                                            Bit mask of ENABLE field.*/
  #define UICRV2_SECONDARY_PROTECTEDMEM_ENABLE_ENABLE_Min (0xBD2328A8UL) /*!< Min enumerator value of ENABLE field.            */
  #define UICRV2_SECONDARY_PROTECTEDMEM_ENABLE_ENABLE_Max (0xFFFFFFFFUL) /*!< Max enumerator value of ENABLE field.            */
  #define UICRV2_SECONDARY_PROTECTEDMEM_ENABLE_ENABLE_Disabled (0xBD2328A8UL) /*!< (unspecified)                               */
  #define UICRV2_SECONDARY_PROTECTEDMEM_ENABLE_ENABLE_Enabled (0xFFFFFFFFUL) /*!< (unspecified)                                */


/* UICRV2_SECONDARY_PROTECTEDMEM_SIZE4KB: Protected Memory region size for the secondary firmware. */
  #define UICRV2_SECONDARY_PROTECTEDMEM_SIZE4KB_ResetValue (0xBD2328A8UL) /*!< Reset value of SIZE4KB register.                */

/* SIZE4KB @Bits 0..31 : (unspecified) */
  #define UICRV2_SECONDARY_PROTECTEDMEM_SIZE4KB_SIZE4KB_Pos (0UL) /*!< Position of SIZE4KB field.                              */
  #define UICRV2_SECONDARY_PROTECTEDMEM_SIZE4KB_SIZE4KB_Msk (0xFFFFFFFFUL << UICRV2_SECONDARY_PROTECTEDMEM_SIZE4KB_SIZE4KB_Pos)
                                                                            /*!< Bit mask of SIZE4KB field.*/



/* ============================================ Struct UICRV2_SECONDARY_WDTSTART ============================================= */
/**
  * @brief WDTSTART [UICRV2_SECONDARY_WDTSTART] Start a local watchdog timer ahead of the CPU boot.
  */
typedef struct {
  __IOM uint32_t  ENABLE;                            /*!< (@ 0x00000000) Enable watchdog timer start.                          */
  __IOM uint32_t  INSTANCE;                          /*!< (@ 0x00000004) Watchdog timer instance.                              */
  __IOM uint32_t  CRV;                               /*!< (@ 0x00000008) Initial CRV (Counter Reload Value) register value.    */
} NRF_UICRV2_SECONDARY_WDTSTART_Type;                /*!< Size = 12 (0x00C)                                                    */

/* UICRV2_SECONDARY_WDTSTART_ENABLE: Enable watchdog timer start. */
  #define UICRV2_SECONDARY_WDTSTART_ENABLE_ResetValue (0xBD2328A8UL) /*!< Reset value of ENABLE register.                      */

/* ENABLE @Bits 0..31 : (unspecified) */
  #define UICRV2_SECONDARY_WDTSTART_ENABLE_ENABLE_Pos (0UL) /*!< Position of ENABLE field.                                     */
  #define UICRV2_SECONDARY_WDTSTART_ENABLE_ENABLE_Msk (0xFFFFFFFFUL << UICRV2_SECONDARY_WDTSTART_ENABLE_ENABLE_Pos) /*!< Bit
                                                                            mask of ENABLE field.*/
  #define UICRV2_SECONDARY_WDTSTART_ENABLE_ENABLE_Min (0xBD2328A8UL) /*!< Min enumerator value of ENABLE field.                */
  #define UICRV2_SECONDARY_WDTSTART_ENABLE_ENABLE_Max (0xFFFFFFFFUL) /*!< Max enumerator value of ENABLE field.                */
  #define UICRV2_SECONDARY_WDTSTART_ENABLE_ENABLE_Disabled (0xBD2328A8UL) /*!< (unspecified)                                   */
  #define UICRV2_SECONDARY_WDTSTART_ENABLE_ENABLE_Enabled (0xFFFFFFFFUL) /*!< (unspecified)                                    */


/* UICRV2_SECONDARY_WDTSTART_INSTANCE: Watchdog timer instance. */
  #define UICRV2_SECONDARY_WDTSTART_INSTANCE_ResetValue (0xBD2328A8UL) /*!< Reset value of INSTANCE register.                  */

/* INSTANCE @Bits 0..31 : (unspecified) */
  #define UICRV2_SECONDARY_WDTSTART_INSTANCE_INSTANCE_Pos (0UL) /*!< Position of INSTANCE field.                               */
  #define UICRV2_SECONDARY_WDTSTART_INSTANCE_INSTANCE_Msk (0xFFFFFFFFUL << UICRV2_SECONDARY_WDTSTART_INSTANCE_INSTANCE_Pos) /*!<
                                                                            Bit mask of INSTANCE field.*/
  #define UICRV2_SECONDARY_WDTSTART_INSTANCE_INSTANCE_Min (0x1730C77FUL) /*!< Min enumerator value of INSTANCE field.          */
  #define UICRV2_SECONDARY_WDTSTART_INSTANCE_INSTANCE_Max (0xBD2328A8UL) /*!< Max enumerator value of INSTANCE field.          */
  #define UICRV2_SECONDARY_WDTSTART_INSTANCE_INSTANCE_WDT0 (0xBD2328A8UL) /*!< (unspecified)                                   */
  #define UICRV2_SECONDARY_WDTSTART_INSTANCE_INSTANCE_WDT1 (0x1730C77FUL) /*!< (unspecified)                                   */


/* UICRV2_SECONDARY_WDTSTART_CRV: Initial CRV (Counter Reload Value) register value. */
  #define UICRV2_SECONDARY_WDTSTART_CRV_ResetValue (0xBD2328A8UL) /*!< Reset value of CRV register.                            */

/* CRV @Bits 0..31 : Initial CRV value for the WDT */
  #define UICRV2_SECONDARY_WDTSTART_CRV_CRV_Pos (0UL) /*!< Position of CRV field.                                              */
  #define UICRV2_SECONDARY_WDTSTART_CRV_CRV_Msk (0xFFFFFFFFUL << UICRV2_SECONDARY_WDTSTART_CRV_CRV_Pos) /*!< Bit mask of CRV
                                                                            field.*/
  #define UICRV2_SECONDARY_WDTSTART_CRV_CRV_Min (0xFUL) /*!< Min value of CRV field.                                           */
  #define UICRV2_SECONDARY_WDTSTART_CRV_CRV_Max (0xFFFFFFFFUL) /*!< Max size of CRV field.                                     */



/* =========================================== Struct UICRV2_SECONDARY_PERIPHCONF ============================================ */
/**
  * @brief PERIPHCONF [UICRV2_SECONDARY_PERIPHCONF] Global domain peripheral configuration used when booting the secondary
            firmware.

  */
typedef struct {
  __IOM uint32_t  ENABLE;                            /*!< (@ 0x00000000) Enable global domain peripheral configuration for the
                                                                         secondary firmware.*/
  __IOM uint32_t  ADDRESS;                           /*!< (@ 0x00000004) Start address of the array of peripheral configuration
                                                                         entries for the secondary firmware.*/
  __IOM uint32_t  MAXCOUNT;                          /*!< (@ 0x00000008) Maximum number of peripheral configuration entries for
                                                                         the secondary firmware.*/
} NRF_UICRV2_SECONDARY_PERIPHCONF_Type;              /*!< Size = 12 (0x00C)                                                    */

/* UICRV2_SECONDARY_PERIPHCONF_ENABLE: Enable global domain peripheral configuration for the secondary firmware. */
  #define UICRV2_SECONDARY_PERIPHCONF_ENABLE_ResetValue (0xBD2328A8UL) /*!< Reset value of ENABLE register.                    */

/* ENABLE @Bits 0..31 : (unspecified) */
  #define UICRV2_SECONDARY_PERIPHCONF_ENABLE_ENABLE_Pos (0UL) /*!< Position of ENABLE field.                                   */
  #define UICRV2_SECONDARY_PERIPHCONF_ENABLE_ENABLE_Msk (0xFFFFFFFFUL << UICRV2_SECONDARY_PERIPHCONF_ENABLE_ENABLE_Pos) /*!< Bit
                                                                            mask of ENABLE field.*/
  #define UICRV2_SECONDARY_PERIPHCONF_ENABLE_ENABLE_Min (0xBD2328A8UL) /*!< Min enumerator value of ENABLE field.              */
  #define UICRV2_SECONDARY_PERIPHCONF_ENABLE_ENABLE_Max (0xFFFFFFFFUL) /*!< Max enumerator value of ENABLE field.              */
  #define UICRV2_SECONDARY_PERIPHCONF_ENABLE_ENABLE_Disabled (0xBD2328A8UL) /*!< (unspecified)                                 */
  #define UICRV2_SECONDARY_PERIPHCONF_ENABLE_ENABLE_Enabled (0xFFFFFFFFUL) /*!< (unspecified)                                  */


/* UICRV2_SECONDARY_PERIPHCONF_ADDRESS: Start address of the array of peripheral configuration entries for the secondary
                                         firmware. */

  #define UICRV2_SECONDARY_PERIPHCONF_ADDRESS_ResetValue (0xBD2328A8UL) /*!< Reset value of ADDRESS register.                  */

/* ADDRESS @Bits 0..31 : (unspecified) */
  #define UICRV2_SECONDARY_PERIPHCONF_ADDRESS_ADDRESS_Pos (0UL) /*!< Position of ADDRESS field.                                */
  #define UICRV2_SECONDARY_PERIPHCONF_ADDRESS_ADDRESS_Msk (0xFFFFFFFFUL << UICRV2_SECONDARY_PERIPHCONF_ADDRESS_ADDRESS_Pos) /*!<
                                                                            Bit mask of ADDRESS field.*/


/* UICRV2_SECONDARY_PERIPHCONF_MAXCOUNT: Maximum number of peripheral configuration entries for the secondary firmware. */
  #define UICRV2_SECONDARY_PERIPHCONF_MAXCOUNT_ResetValue (0xBD2328A8UL) /*!< Reset value of MAXCOUNT register.                */

/* MAXCOUNT @Bits 0..31 : (unspecified) */
  #define UICRV2_SECONDARY_PERIPHCONF_MAXCOUNT_MAXCOUNT_Pos (0UL) /*!< Position of MAXCOUNT field.                             */
  #define UICRV2_SECONDARY_PERIPHCONF_MAXCOUNT_MAXCOUNT_Msk (0xFFFFFFFFUL << UICRV2_SECONDARY_PERIPHCONF_MAXCOUNT_MAXCOUNT_Pos)
                                                                            /*!< Bit mask of MAXCOUNT field.*/



/* ============================================= Struct UICRV2_SECONDARY_MPCCONF ============================================= */
/**
  * @brief MPCCONF [UICRV2_SECONDARY_MPCCONF] Global domain MPC configuration used when booting the secondary firmware
  */
typedef struct {
  __IOM uint32_t  ENABLE;                            /*!< (@ 0x00000000) Enable the global domain MPC configuration for the
                                                                         secondary firmware*/
  __IOM uint32_t  ADDRESS;                           /*!< (@ 0x00000004) Start address of the array of MPC configuration entries
                                                                         for the secondary firmware*/
  __IOM uint32_t  MAXCOUNT;                          /*!< (@ 0x00000008) Maximum number of MPC configuration entries for the
                                                                         secondary firmware*/
} NRF_UICRV2_SECONDARY_MPCCONF_Type;                 /*!< Size = 12 (0x00C)                                                    */

/* UICRV2_SECONDARY_MPCCONF_ENABLE: Enable the global domain MPC configuration for the secondary firmware */
  #define UICRV2_SECONDARY_MPCCONF_ENABLE_ResetValue (0xBD2328A8UL) /*!< Reset value of ENABLE register.                       */

/* ENABLE @Bits 0..31 : (unspecified) */
  #define UICRV2_SECONDARY_MPCCONF_ENABLE_ENABLE_Pos (0UL) /*!< Position of ENABLE field.                                      */
  #define UICRV2_SECONDARY_MPCCONF_ENABLE_ENABLE_Msk (0xFFFFFFFFUL << UICRV2_SECONDARY_MPCCONF_ENABLE_ENABLE_Pos) /*!< Bit mask
                                                                            of ENABLE field.*/
  #define UICRV2_SECONDARY_MPCCONF_ENABLE_ENABLE_Min (0xBD2328A8UL) /*!< Min enumerator value of ENABLE field.                 */
  #define UICRV2_SECONDARY_MPCCONF_ENABLE_ENABLE_Max (0xFFFFFFFFUL) /*!< Max enumerator value of ENABLE field.                 */
  #define UICRV2_SECONDARY_MPCCONF_ENABLE_ENABLE_Disabled (0xBD2328A8UL) /*!< (unspecified)                                    */
  #define UICRV2_SECONDARY_MPCCONF_ENABLE_ENABLE_Enabled (0xFFFFFFFFUL) /*!< (unspecified)                                     */


/* UICRV2_SECONDARY_MPCCONF_ADDRESS: Start address of the array of MPC configuration entries for the secondary firmware */
  #define UICRV2_SECONDARY_MPCCONF_ADDRESS_ResetValue (0xBD2328A8UL) /*!< Reset value of ADDRESS register.                     */

/* ADDRESS @Bits 0..31 : (unspecified) */
  #define UICRV2_SECONDARY_MPCCONF_ADDRESS_ADDRESS_Pos (0UL) /*!< Position of ADDRESS field.                                   */
  #define UICRV2_SECONDARY_MPCCONF_ADDRESS_ADDRESS_Msk (0xFFFFFFFFUL << UICRV2_SECONDARY_MPCCONF_ADDRESS_ADDRESS_Pos) /*!< Bit
                                                                            mask of ADDRESS field.*/


/* UICRV2_SECONDARY_MPCCONF_MAXCOUNT: Maximum number of MPC configuration entries for the secondary firmware */
  #define UICRV2_SECONDARY_MPCCONF_MAXCOUNT_ResetValue (0xBD2328A8UL) /*!< Reset value of MAXCOUNT register.                   */

/* MAXCOUNT @Bits 0..31 : (unspecified) */
  #define UICRV2_SECONDARY_MPCCONF_MAXCOUNT_MAXCOUNT_Pos (0UL) /*!< Position of MAXCOUNT field.                                */
  #define UICRV2_SECONDARY_MPCCONF_MAXCOUNT_MAXCOUNT_Msk (0xFFFFFFFFUL << UICRV2_SECONDARY_MPCCONF_MAXCOUNT_MAXCOUNT_Pos) /*!<
                                                                            Bit mask of MAXCOUNT field.*/



/* ================================================= Struct UICRV2_SECONDARY ================================================= */
/**
  * @brief SECONDARY [UICRV2_SECONDARY] Secondary firmware configuration
  */
typedef struct {
  __IOM uint32_t  ENABLE;                            /*!< (@ 0x00000000) Enable booting of secondary firmware.                 */
  __IOM uint32_t  PROCESSOR;                         /*!< (@ 0x00000004) Processor to boot for the secondary firmware.         */
  __IOM NRF_UICRV2_SECONDARY_TRIGGER_Type TRIGGER;   /*!< (@ 0x00000008) Automatic triggers for reset into secondary firmware  */
  __IOM uint32_t  ADDRESS;                           /*!< (@ 0x00000014) Start address of the secondary firmware. This value is
                                                                         used as the initial value of the secure VTOR (Vector
                                                                         Table Offset Register) after CPU reset.*/
  __IOM NRF_UICRV2_SECONDARY_PROTECTEDMEM_Type PROTECTEDMEM; /*!< (@ 0x00000018) Protected Memory region for the secondary
                                                                            firmware.*/
  __IOM NRF_UICRV2_SECONDARY_WDTSTART_Type WDTSTART; /*!< (@ 0x00000020) Start a local watchdog timer ahead of the CPU boot.   */
  __IOM NRF_UICRV2_SECONDARY_PERIPHCONF_Type PERIPHCONF; /*!< (@ 0x0000002C) Global domain peripheral configuration used when
                                                                            booting the secondary firmware.*/
  __IOM NRF_UICRV2_SECONDARY_MPCCONF_Type MPCCONF;   /*!< (@ 0x00000038) Global domain MPC configuration used when booting the
                                                                         secondary firmware*/
} NRF_UICRV2_SECONDARY_Type;                         /*!< Size = 68 (0x044)                                                    */

/* UICRV2_SECONDARY_ENABLE: Enable booting of secondary firmware. */
  #define UICRV2_SECONDARY_ENABLE_ResetValue (0xBD2328A8UL) /*!< Reset value of ENABLE register.                               */

/* ENABLE @Bits 0..31 : (unspecified) */
  #define UICRV2_SECONDARY_ENABLE_ENABLE_Pos (0UL)   /*!< Position of ENABLE field.                                            */
  #define UICRV2_SECONDARY_ENABLE_ENABLE_Msk (0xFFFFFFFFUL << UICRV2_SECONDARY_ENABLE_ENABLE_Pos) /*!< Bit mask of ENABLE
                                                                            field.*/
  #define UICRV2_SECONDARY_ENABLE_ENABLE_Min (0xBD2328A8UL) /*!< Min enumerator value of ENABLE field.                         */
  #define UICRV2_SECONDARY_ENABLE_ENABLE_Max (0xFFFFFFFFUL) /*!< Max enumerator value of ENABLE field.                         */
  #define UICRV2_SECONDARY_ENABLE_ENABLE_Disabled (0xBD2328A8UL) /*!< (unspecified)                                            */
  #define UICRV2_SECONDARY_ENABLE_ENABLE_Enabled (0xFFFFFFFFUL) /*!< (unspecified)                                             */


/* UICRV2_SECONDARY_PROCESSOR: Processor to boot for the secondary firmware. */
  #define UICRV2_SECONDARY_PROCESSOR_ResetValue (0xBD2328A8UL) /*!< Reset value of PROCESSOR register.                         */

/* PROCESSOR @Bits 0..31 : (unspecified) */
  #define UICRV2_SECONDARY_PROCESSOR_PROCESSOR_Pos (0UL) /*!< Position of PROCESSOR field.                                     */
  #define UICRV2_SECONDARY_PROCESSOR_PROCESSOR_Msk (0xFFFFFFFFUL << UICRV2_SECONDARY_PROCESSOR_PROCESSOR_Pos) /*!< Bit mask of
                                                                            PROCESSOR field.*/
  #define UICRV2_SECONDARY_PROCESSOR_PROCESSOR_Min (0x1730C77FUL) /*!< Min enumerator value of PROCESSOR field.                */
  #define UICRV2_SECONDARY_PROCESSOR_PROCESSOR_Max (0xBD2328A8UL) /*!< Max enumerator value of PROCESSOR field.                */
  #define UICRV2_SECONDARY_PROCESSOR_PROCESSOR_APPLICATION (0xBD2328A8UL) /*!< Boot the APPLICATION processor.                 */
  #define UICRV2_SECONDARY_PROCESSOR_PROCESSOR_RADIOCORE (0x1730C77FUL) /*!< Boot the RADIOCORE processor.                     */


/* UICRV2_SECONDARY_ADDRESS: Start address of the secondary firmware. This value is used as the initial value of the secure VTOR
                              (Vector Table Offset Register) after CPU reset. */

  #define UICRV2_SECONDARY_ADDRESS_ResetValue (0xBD2328A8UL) /*!< Reset value of ADDRESS register.                             */

/* ADDRESS @Bits 12..31 : (unspecified) */
  #define UICRV2_SECONDARY_ADDRESS_ADDRESS_Pos (12UL) /*!< Position of ADDRESS field.                                          */
  #define UICRV2_SECONDARY_ADDRESS_ADDRESS_Msk (0xFFFFFUL << UICRV2_SECONDARY_ADDRESS_ADDRESS_Pos) /*!< Bit mask of ADDRESS
                                                                            field.*/


/* ====================================================== Struct UICRV2 ====================================================== */
/**
  * @brief User information configuration registers
  */
  typedef struct {                                   /*!< UICRV2 Structure                                                     */
    __IOM uint32_t VERSION;                          /*!< (@ 0x00000000) Version of the UICR format                            */
    __IM uint32_t RESERVED;
    __IOM uint32_t LOCK;                             /*!< (@ 0x00000008) Lock the UICR from modification                       */
    __IM uint32_t RESERVED1;
    __IOM NRF_UICRV2_APPROTECT_Type APPROTECT;       /*!< (@ 0x00000010) (unspecified)                                         */
    __IOM uint32_t ERASEPROTECT;                     /*!< (@ 0x00000020) Erase protection                                      */
    __IOM NRF_UICRV2_PROTECTEDMEM_Type PROTECTEDMEM; /*!< (@ 0x00000024) (unspecified)                                         */
    __IOM NRF_UICRV2_WDTSTART_Type WDTSTART;         /*!< (@ 0x0000002C) Start a local watchdog timer ahead of the CPU boot.   */
    __IM uint32_t RESERVED2;
    __IOM NRF_UICRV2_SECURESTORAGE_Type SECURESTORAGE; /*!< (@ 0x0000003C) Secure Storage configuration                        */
    __IM uint32_t RESERVED3[5];
    __IOM NRF_UICRV2_PERIPHCONF_Type PERIPHCONF;     /*!< (@ 0x00000068) Global domain peripheral configuration                */
    __IOM NRF_UICRV2_MPCCONF_Type MPCCONF;           /*!< (@ 0x00000074) Global domain MPC configuration                       */
    __IOM NRF_UICRV2_SECONDARY_Type SECONDARY;       /*!< (@ 0x00000080) Secondary firmware configuration                      */
    __IOM uint32_t PADDING[15];                      /*!< (@ 0x000000C4) (unspecified)                                         */
  } NRF_UICRV2_Type;                                 /*!< Size = 256 (0x100)                                                   */

/* UICRV2_VERSION: Version of the UICR format */

/* MINOR @Bits 0..15 : Minor version */
  #define UICRV2_VERSION_MINOR_Pos (0UL)             /*!< Position of MINOR field.                                             */
  #define UICRV2_VERSION_MINOR_Msk (0xFFFFUL << UICRV2_VERSION_MINOR_Pos) /*!< Bit mask of MINOR field.                        */

/* MAJOR @Bits 16..31 : Major version */
  #define UICRV2_VERSION_MAJOR_Pos (16UL)            /*!< Position of MAJOR field.                                             */
  #define UICRV2_VERSION_MAJOR_Msk (0xFFFFUL << UICRV2_VERSION_MAJOR_Pos) /*!< Bit mask of MAJOR field.                        */


/* UICRV2_LOCK: Lock the UICR from modification */
  #define UICRV2_LOCK_ResetValue (0xBD2328A8UL)      /*!< Reset value of LOCK register.                                        */

/* PALL @Bits 0..31 : (unspecified) */
  #define UICRV2_LOCK_PALL_Pos (0UL)                 /*!< Position of PALL field.                                              */
  #define UICRV2_LOCK_PALL_Msk (0xFFFFFFFFUL << UICRV2_LOCK_PALL_Pos) /*!< Bit mask of PALL field.                             */
  #define UICRV2_LOCK_PALL_Min (0xBD2328A8UL)        /*!< Min enumerator value of PALL field.                                  */
  #define UICRV2_LOCK_PALL_Max (0xFFFFFFFFUL)        /*!< Max enumerator value of PALL field.                                  */
  #define UICRV2_LOCK_PALL_Unlocked (0xBD2328A8UL)   /*!< NVR page 0 can be written, and is not integrity checked by Nordic
                                                          IronSide SE*/
  #define UICRV2_LOCK_PALL_Locked (0xFFFFFFFFUL)     /*!< NVR page 0 is read-only, and is integrity checked by Nordic IronSide
                                                          SE on boot*/


/* UICRV2_ERASEPROTECT: Erase protection */
  #define UICRV2_ERASEPROTECT_ResetValue (0xBD2328A8UL) /*!< Reset value of ERASEPROTECT register.                             */

/* PALL @Bits 0..31 : (unspecified) */
  #define UICRV2_ERASEPROTECT_PALL_Pos (0UL)         /*!< Position of PALL field.                                              */
  #define UICRV2_ERASEPROTECT_PALL_Msk (0xFFFFFFFFUL << UICRV2_ERASEPROTECT_PALL_Pos) /*!< Bit mask of PALL field.             */
  #define UICRV2_ERASEPROTECT_PALL_Min (0xBD2328A8UL) /*!< Min enumerator value of PALL field.                                 */
  #define UICRV2_ERASEPROTECT_PALL_Max (0xFFFFFFFFUL) /*!< Max enumerator value of PALL field.                                 */
  #define UICRV2_ERASEPROTECT_PALL_Unprotected (0xBD2328A8UL) /*!< (unspecified)                                               */
  #define UICRV2_ERASEPROTECT_PALL_Protected (0xFFFFFFFFUL) /*!< (unspecified)                                                 */

/* clang-format on */

#ifdef __cplusplus
}
#endif
#endif /* SECDOM_INCLUDE_UICR_V2_DEF_H__ */
