/****************************************************************************
 * drivers/wireless/ieee80211/nrf7002/nrf7002_osal.h
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

#ifndef __DRIVERS_WIRELESS_IEEE80211_NRF7002_NRF7002_OSAL_H
#define __DRIVERS_WIRELESS_IEEE80211_NRF7002_NRF7002_OSAL_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <stddef.h>
#include "osal_ops.h"

/****************************************************************************
 * Public Types
 ****************************************************************************/

/* Network buffer used by the NCS FMAC layer.
 * Mirrors the Zephyr shim's struct nwb layout.
 */

struct nrf7002_nbuf
{
  unsigned char *data;      /* Pointer to current data start */
  unsigned char *tail;      /* Pointer to end of written data */
  int            len;       /* Length of valid data in bytes */
  int            headroom;  /* Reserved headroom bytes */
  void          *next;      /* Next buffer in chain (unused) */
  void          *priv;      /* Pointer to the raw allocation */
  unsigned int   capacity;  /* Size of the priv allocation in bytes */
  unsigned char  priority;  /* Buffer priority (QoS) */
  bool           chksum_done; /* Hardware checksum offload done */
};

/* Linked list node wrapper */

struct nrf7002_llist_node
{
  struct nrf7002_llist_node *next;
  void                      *data;
};

/* Linked list wrapper */

struct nrf7002_llist
{
  struct nrf7002_llist_node *head;
  unsigned int               len;
};

/****************************************************************************
 * Public Data
 ****************************************************************************/

/* The single nrf_wifi_osal_ops instance backed by NuttX primitives */

extern const struct nrf_wifi_osal_ops nrf7002_osal_ops;

#endif /* __DRIVERS_WIRELESS_IEEE80211_NRF7002_NRF7002_OSAL_H */
