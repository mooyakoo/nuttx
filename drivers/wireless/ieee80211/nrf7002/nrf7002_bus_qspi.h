/****************************************************************************
 * drivers/wireless/ieee80211/nrf7002/nrf7002_bus_qspi.h
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.  The
 * ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 ****************************************************************************/

#ifndef __DRIVERS_WIRELESS_IEEE80211_NRF7002_NRF7002_BUS_QSPI_H
#define __DRIVERS_WIRELESS_IEEE80211_NRF7002_NRF7002_BUS_QSPI_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <stddef.h>
#include <nuttx/spi/qspi.h>
#include "osal_structs.h"

/****************************************************************************
 * Public Types
 ****************************************************************************/

/* Per-device QSPI context.  One instance lives inside the global
 * nrf7002_priv and is passed as the 'priv' pointer to every
 * qspi_read_reg32 / qspi_write_reg32 / qspi_cpy_* call.
 */

struct nrf7002_qspi_ctx
{
  FAR struct qspi_dev_s *qspi_dev;  /* NuttX QSPI bus handle */
  bool                   dev_added; /* True after bus_qspi_dev_add */

  /* IRQ callback installed by bus_qspi_dev_intr_reg */

  void *intr_callbk_data;
  int (*intr_callbk_fn)(void *callbk_data);
};

/****************************************************************************
 * Public Function Prototypes
 *
 * These are referenced directly in the nrf_wifi_osal_ops struct built in
 * nrf7002_osal.c.
 ****************************************************************************/

/* QSPI register and bulk access (ops called by HAL/BAL) */

unsigned int nrf7002_qspi_read_reg32(void *priv, unsigned long addr);
void         nrf7002_qspi_write_reg32(void *priv, unsigned long addr,
                                       unsigned int val);
void         nrf7002_qspi_cpy_from(void *priv, void *dest,
                                    unsigned long addr, size_t count);
void         nrf7002_qspi_cpy_to(void *priv, unsigned long addr,
                                  const void *src, size_t count);

/* QSPI bus lifecycle (ops called by FMAC/HAL init path) */

void                   *nrf7002_qspi_bus_init(void);
void                    nrf7002_qspi_bus_deinit(void *os_qspi_priv);
void                   *nrf7002_qspi_dev_add(void *qspi_priv,
                                              void *osal_qspi_dev_ctx);
void                    nrf7002_qspi_dev_rem(void *os_qspi_dev_ctx);
enum nrf_wifi_status    nrf7002_qspi_dev_init(void *os_qspi_dev_ctx);
void                    nrf7002_qspi_dev_deinit(void *os_qspi_dev_ctx);
enum nrf_wifi_status    nrf7002_qspi_dev_intr_reg(
                          void *os_qspi_dev_ctx,
                          void *callbk_data,
                          int (*callbk_fn)(void *callbk_data));
void                    nrf7002_qspi_dev_intr_unreg(void *os_qspi_dev_ctx);
void                    nrf7002_qspi_dev_host_map_get(
                          void *os_qspi_dev_ctx,
                          struct nrf_wifi_osal_host_map *host_map);

#endif /* __DRIVERS_WIRELESS_IEEE80211_NRF7002_NRF7002_BUS_QSPI_H */
