/****************************************************************************
 * drivers/wireless/ieee80211/nrf7002/nrf7002_driver.h
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

#ifndef __DRIVERS_WIRELESS_IEEE80211_NRF7002_NRF7002_DRIVER_H
#define __DRIVERS_WIRELESS_IEEE80211_NRF7002_NRF7002_DRIVER_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>
#include <nuttx/net/netdev.h>
#include <nuttx/mutex.h>
#include <nuttx/semaphore.h>
#include <nuttx/wqueue.h>
#include <nuttx/irq.h>
#include <syslog.h>

#include "fmac_structs.h"
#include "nrf7002_bus_qspi.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/* Maximum number of scan results to cache */

#define NRF7002_MAX_SCAN_RESULTS  32

/* Maximum SSID length (802.11 spec) */

#define NRF7002_MAX_SSID_LEN      32

/* Maximum passphrase length (WPA2) */

#define NRF7002_MAX_PASSPHRASE_LEN 64

/* VIF (virtual interface) index used for the STA */

#define NRF7002_VIF_IDX           0

/* MAC address length */

#define NRF7002_MAC_ADDR_LEN      6

/* Security type flags */

#define NRF7002_SECURITY_OPEN     0
#define NRF7002_SECURITY_WPA2     1

/* Number of concurrent TX tokens (limits inflight TX to the RPU) */

#define NRF7002_TX_TOKENS         10

/****************************************************************************
 * Public Types
 ****************************************************************************/

/* Driver state machine */

enum nrf7002_state
{
  NRF7002_STATE_UNINIT = 0,   /* Not initialized */
  NRF7002_STATE_IDLE,         /* Initialized, interface down */
  NRF7002_STATE_SCANNING,     /* Scan in progress */
  NRF7002_STATE_AUTHENTICATING, /* 802.11 auth in progress */
  NRF7002_STATE_ASSOCIATING,  /* 802.11 assoc in progress */
  NRF7002_STATE_ASSOCIATED,   /* Carrier up */
};

/* One cached scan result entry */

struct nrf7002_scan_result
{
  char     ssid[NRF7002_MAX_SSID_LEN + 1];   /* NUL-terminated SSID */
  uint8_t  ssid_len;                           /* SSID byte length */
  uint8_t  bssid[NRF7002_MAC_ADDR_LEN];       /* BSSID */
  int16_t  rssi;                               /* Signal strength (dBm) */
  int32_t  rssi_mbm;                           /* Signal strength (mBm = dBm*100) */
  uint32_t frequency;                          /* Channel frequency (MHz) */
  int      security;                           /* NRF7002_SECURITY_* */
  uint16_t capability;                         /* 802.11 capability field */
  uint16_t beacon_interval;                    /* Beacon interval (TU) */
  uint64_t tsf;                                /* BSS TSF from scan event */
};

/* Per-driver private state */

struct nrf7002_priv
{
  /* NuttX network device — must be first (cast between priv and dev) */

  struct net_driver_s        netdev;

  /* NCS FMAC handles */

  struct nrf_wifi_fmac_priv *fmac_priv;     /* FMAC layer context */
  void                      *fmac_dev_ctx;  /* RPU device context */
  unsigned char              vif_idx;       /* VIF index (0 = STA) */

  /* QSPI bus context shared with nrf7002_bus_qspi.c */

  struct nrf7002_qspi_ctx    qspi_ctx;

  /* Driver state */

  enum nrf7002_state         state;

  /* Phase 3: TX token semaphore — limits concurrent in-flight TX frames */

  sem_t                      tx_tokens;

  /* Phase 3: RX work item for LPWORK delivery */

  struct work_s              rx_work;

  /* EAPOL work item + queue.  EAPOL frames must NOT be processed inline in
   * rx_frm_cb: that callback runs inside the NCS HAL lock_rx critical section
   * with the RX descriptor not yet returned, and calling start_xmit (to send
   * M2/M4) from there makes the FMAC TX path fail transiently (start_xmit
   * returns -1), so the AP never gets M2/M4 and disconnects.  Instead EAPOL
   * frames are queued here and processed by nrf7002_eapol_worker on LPWORK
   * after rx_frm_cb returns and lock_rx is released.  This keeps control-port
   * start_xmit off HPWORK so RPU event/TX_DONE processing can unmap TX buffers
   * before retransmitted M1/M3 frames cause another M2/M4 send.
   */

  struct work_s              eapol_work;
  FAR struct nrf7002_nbuf   *eapol_queue_head;
  FAR struct nrf7002_nbuf   *eapol_queue_tail;

  /* TX poll work item.  d_txavail (nrf7002_txnotify) schedules this on the
   * SAME LPWORK queue as rx_work so TX devif_poll and RX delivery run
   * serially on one thread — both touch dev->d_buf, and the socket TX path
   * (psock_tcp_send) does NOT hold net_lock, so calling devif_poll inline
   * from the caller's thread races RX delivery and corrupts d_buf.
   */

  struct work_s              tx_work;

  /* Reentrancy guard for nrf7002_txavail_work (devif_poll TX path). */

  bool                       tx_poll_busy;

  /* Set when a txnotify arrives while txavail_work is running.  Ensures a
   * notification delivered inside the work_queue debounce window (work already
   * dequeued and executing) is not lost — the worker re-arms itself on exit.
   */

  bool                       tx_pending;

  /* RX frame queue: frames enqueued by rx_frm_cb, drained by rx_worker.
   * Protected by rx_queue_lock (spinlock via enter/leave_critical_section).
   * Uses the nrf7002_nbuf.next field to chain frames.
   */

  FAR struct nrf7002_nbuf   *rx_queue_head;
  FAR struct nrf7002_nbuf   *rx_queue_tail;

  /* Async connect work item — runs nrf7002_ioctl_connect in LPWORK so
   * the IOCTL caller (NSH task) is not blocked during auth/assoc waits.
   */

  struct work_s              connect_work;

  /* Scan state */

  sem_t                      scan_sem;      /* Posted when scan completes */
  bool                       scan_done;     /* Scan complete flag */
  int                        scan_reason;   /* SCAN_DISPLAY or SCAN_CONNECT */
  struct nrf7002_scan_result scan_results[NRF7002_MAX_SCAN_RESULTS];
  int                        scan_count;    /* Number of valid results */

  /* Auth state */

  sem_t                      auth_sem;      /* Posted on auth result or CMD_STATUS */
  bool                       auth_failed;   /* Set when auth CMD_STATUS indicates error */

  /* Assoc state */

  sem_t                      assoc_sem;     /* Posted on assoc result */
  bool                       assoc_failed;  /* Set when assoc is rejected */

  /* Connection target parameters (set via IOCTL before connect) */

  char    target_ssid[NRF7002_MAX_SSID_LEN + 1];
  int     target_ssid_len;
  uint8_t target_bssid[NRF7002_MAC_ADDR_LEN];
  uint32_t ap_freq;        /* frequency (MHz) of the target AP, set at connect time */
  uint32_t target_freq;    /* user-set frequency via SIOCSIWFREQ (0 = not set) */
  int     security_type;                        /* NRF7002_SECURITY_* */
  char    passphrase[NRF7002_MAX_PASSPHRASE_LEN];

  /* Link state */

  bool                       carrier_up;

  /* Flat TX packet buffer — assigned to netdev.d_buf at init.
   * Must always be restored to dev->d_buf after RX so devif_poll
   * continues to use flat-buffer mode.
   */

  uint8_t                   *pktbuf;

  /* MAC address */

  uint8_t                    mac_addr[NRF7002_MAC_ADDR_LEN];

  /* Last RSSI from scan (for SIOCGIWSTATS) */

  int16_t                    last_rssi;

  /* WPA2-PSK 4-way handshake state */

  uint8_t  pmk[32];        /* Pairwise Master Key (PBKDF2-SHA1 of passphrase) */
  uint8_t  pmk_valid;      /* 1 when pmk[] is populated */
  uint8_t  snonce[32];     /* STA nonce generated for M2 */
  uint8_t  anonce[32];     /* AP nonce from M1 */
  uint8_t  ap_replay[8];   /* replay counter from last AP message */
  uint8_t  ptk[64];        /* Pairwise Transient Key (PRF-512 output) */
  uint8_t  ptk_valid;      /* 1 when ptk[] is populated */
  uint8_t  keys_installed; /* 1 after PTK/GTK installed + port authorized */

  /* Serialise control-path operations */

  mutex_t                    lock;
};

/****************************************************************************
 * Public Data
 ****************************************************************************/

/* Single global driver instance (one nRF7002 per board) */

extern struct nrf7002_priv g_nrf7002_priv;

/****************************************************************************
 * Public Function Prototypes
 ****************************************************************************/

/****************************************************************************
 * Name: nrf7002_initialize
 *
 * Description:
 *   Initialize the nRF7002 WiFi driver.  Must be called after the QSPI
 *   bus has been configured and the GPIO power-up sequence completed.
 *
 * Returned Value:
 *   OK on success; a negated errno on failure.
 *
 ****************************************************************************/

int nrf7002_initialize(void);

/****************************************************************************
 * Name: nrf7002_netdev_register
 *
 * Description:
 *   Register the net_driver_s with the NuttX network layer.
 *
 * Returned Value:
 *   OK on success; a negated errno on failure.
 *
 ****************************************************************************/

int nrf7002_netdev_register(FAR struct nrf7002_priv *priv);

/****************************************************************************
 * Name: nrf7002_txpoll
 *
 * Description:
 *   Transmit one pending frame from d_buf.  Called from nrf7002_driver.c
 *   when arp_input/ipv4_input/ipv6_input produces a reply in d_buf.
 *
 * Returned Value:
 *   0 on success; negated errno on failure.
 *
 ****************************************************************************/

int nrf7002_txpoll(FAR struct net_driver_s *dev);

#endif /* __DRIVERS_WIRELESS_IEEE80211_NRF7002_NRF7002_DRIVER_H */
