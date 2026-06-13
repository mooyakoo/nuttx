/****************************************************************************
 * drivers/wireless/ieee80211/nrf7002/nrf7002_driver.c
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

/****************************************************************************
 * nRF7002 core driver: initialization sequence and FMAC event callbacks.
 *
 * Phase 3 additions:
 *   - rx_frm_callbk_fn: queues frames outside the FMAC callback
 *   - nrf7002_rx_worker: delivers received data frames from LPWORK
 *   - EAPOL worker: handles control-port frames from LPWORK so HPWORK can
 *     continue draining RPU events/TX_DONE
 *
 * Reference: NCS/modules/lib/nrf_wifi/fw_if/umac_if/
 *            drivers/wireless/ieee80211/bcm43xxx/bcmf_netdev.c
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <errno.h>
#include <string.h>
#include <syslog.h>

#include <net/if.h>
#include <netinet/in.h>
#include <nuttx/net/net.h>
#include <nuttx/net/netdev.h>
#include <nuttx/mutex.h>
#include <nuttx/semaphore.h>
#include <nuttx/wqueue.h>
#include <nuttx/kmalloc.h>
#include <nuttx/irq.h>
#include <nuttx/spinlock.h>

#include "osal_api.h"
#include "fmac_api.h"
#include "fmac_structs.h"
#include "host_rpu_umac_if.h"
#include "common/rpu_if.h"
#include "common/fmac_api_common.h"
#include "common/fmac_util.h"
#include "system/fmac_peer.h"

#include "nrf7002_osal.h"
#include "nrf7002_bus_qspi.h"
#include "nrf7002_driver.h"
#include "phy_rf_params_common.h"
#include "nrf7002_wpa.h"

/****************************************************************************
 * RPU Firmware Blob
 *
 * The nRF7002 RPU requires a firmware patch blob (nrf70.bin) to be
 * downloaded before nrf_wifi_sys_fmac_dev_init() can succeed.
 *
 * The blob is Nordic-proprietary (LicenseRef-Nordic-5-Clause) and is NOT
 * distributed in this repository.  It is supplied at build time from the
 * user's nRF Connect SDK installation: the driver references the firmware
 * via the symbols below, which are defined in a generated file
 * (nrf7002_fw_blob.c, produced by tools/gen_fw_blob.sh from nrf70.bin) that
 * is git-ignored.  See ncs/README.md for the generation step.
 ****************************************************************************/

extern const char g_nrf70_fw_patch[];
extern const unsigned int g_nrf70_fw_patch_len;

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/* Minimum RX buffer pool sizes - keep the count small to fit in 512 KB RAM.
 * NCS always expects MAX_NUM_OF_RX_QUEUES pools, and the packet-RAM layout
 * reserves NRF70_RX_NUM_BUFS * NRF70_RX_MAX_DATA_SIZE bytes for RX.
 */

#define NRF7002_RX_POOL0_COUNT              2
#define NRF7002_RX_POOL1_COUNT              1
#define NRF7002_RX_POOL2_COUNT              1
#define NRF7002_RX_BUF_SIZE                 NRF70_RX_MAX_DATA_SIZE

#define NRF7002_MAX_TX_AGGREGATION          9
#define NRF7002_MAX_TX_AGG_SESSIONS         4
#define NRF7002_MAX_RX_AGG_SESSIONS         8
#define NRF7002_MAX_PKT_RAM_TX_ALIGN_OVERHEAD 6
#define NRF7002_RX_REORDER_BUF_SIZE \
  (NRF70_RX_NUM_BUFS / MAX_NUM_OF_RX_QUEUES)

/****************************************************************************
 * Private Data
 ****************************************************************************/

/* Single global driver instance */

struct nrf7002_priv g_nrf7002_priv;

/* RX buffer pool configuration */

static struct rx_buf_pool_params g_rx_buf_pools[MAX_NUM_OF_RX_QUEUES] =
{
  {
    .num_bufs = NRF7002_RX_POOL0_COUNT,
    .buf_sz   = NRF7002_RX_BUF_SIZE,
  },
  {
    .num_bufs = NRF7002_RX_POOL1_COUNT,
    .buf_sz   = NRF7002_RX_BUF_SIZE,
  },
  {
    .num_bufs = NRF7002_RX_POOL2_COUNT,
    .buf_sz   = NRF7002_RX_BUF_SIZE,
  },
};

/* Data configuration: minimal TX/RX parameters */

static struct nrf_wifi_data_config_params g_data_config;

/****************************************************************************
 * Private Functions — RX LPWORK delivery
 ****************************************************************************/

/****************************************************************************
 * Name: nrf7002_rx_worker
 *
 * Description:
 *   Deliver one received frame to the NuttX network stack, then free the nbuf.
 *
 *   The nbuf pointer is passed directly as the work arg.
 *
 ****************************************************************************/

/****************************************************************************
 * Name: nrf7002_rx_deliver_one
 *
 * Description:
 *   Deliver a single received frame to the NuttX network stack.
 *   Called with net_lock held; frees the nbuf before returning.
 *
 ****************************************************************************/

/* Called with net_lock held and with EAPOL already filtered out. */

static void nrf7002_rx_deliver_one(struct nrf7002_priv *priv,
                                   struct nrf7002_nbuf *nbuf)
{
  struct net_driver_s *dev = &priv->netdev;
  unsigned int         frame_len;
  uint16_t             ethertype;

  frame_len = (unsigned int)nbuf->len;

  if (frame_len == 0 || frame_len > CONFIG_NET_ETH_PKTSIZE)
    {
      syslog(LOG_WARNING,
             "nrf7002: rx: frame length %u out of range\n", frame_len);
      goto out_free;
    }

  if (!priv->carrier_up)
    {
      goto out_free;
    }

  dev->d_buf = nbuf->data;
  dev->d_len = frame_len;

#ifdef CONFIG_NET_PKT
  pkt_input(dev);
#endif

  if (frame_len >= 14)
    {
      ethertype = ((uint16_t)nbuf->data[12] << 8)
                | (uint16_t)nbuf->data[13];

#ifdef CONFIG_NET_IPv4
      if (ethertype == 0x0800)
        {
          NETDEV_RXIPV4(dev);
          ipv4_input(dev);
          if (dev->d_len > 0)
            {
              nrf7002_txpoll(dev);
            }
        }
      else
#endif
#ifdef CONFIG_NET_IPv6
      if (ethertype == 0x86dd)
        {
          NETDEV_RXIPV6(dev);
          ipv6_input(dev);
          if (dev->d_len > 0)
            {
              nrf7002_txpoll(dev);
            }
        }
      else
#endif
#ifdef CONFIG_NET_ARP
      if (ethertype == 0x0806)
        {
          NETDEV_RXARP(dev);
          arp_input(dev);
          if (dev->d_len > 0)
            {
              nrf7002_txpoll(dev);
            }
        }
      else
#endif
        {
          NETDEV_RXDROPPED(dev);
        }
    }

  dev->d_buf = priv->pktbuf;
  dev->d_len = 0;

out_free:
  nrf_wifi_osal_nbuf_free(nbuf);
}

/****************************************************************************
 * Name: nrf7002_rx_worker
 *
 * Description:
 *   LPWORK handler: drain the entire rx_queue, delivering each frame to
 *   the NuttX network stack.  Frames are chained via nbuf->next.
 *
 *   Using a queue instead of a single work-item argument prevents frame
 *   loss under high RX rates (e.g. TCP iperf) where rx_frm_cb fires faster
 *   than LPWORK can drain a single frame.
 *
 ****************************************************************************/

static void nrf7002_rx_worker(FAR void *arg)
{
  struct nrf7002_priv *priv = &g_nrf7002_priv;
  struct nrf7002_nbuf *nbuf;
  struct nrf7002_nbuf *next;
  irqstate_t           flags;

  (void)arg;

  /* Atomically steal the entire queue */

  flags = enter_critical_section();
  nbuf                 = priv->rx_queue_head;
  priv->rx_queue_head  = NULL;
  priv->rx_queue_tail  = NULL;
  leave_critical_section(flags);

  if (nbuf == NULL)
    {
      return;
    }

  while (nbuf != NULL)
    {
      next = (struct nrf7002_nbuf *)nbuf->next;
      nbuf->next = NULL;

      /* EAPOL frames are handled outside net_lock because WPA processing
       * may block (ADD_KEY semaphore waits).
       */

      if (nbuf->len >= 14 && priv->carrier_up &&
          nbuf->data[12] == 0x88 && nbuf->data[13] == 0x8e)
        {
          nrf7002_wpa_process_eapol(priv, nbuf->data, nbuf->len);
          nrf_wifi_osal_nbuf_free(nbuf);
        }
      else
        {
          net_lock();
          nrf7002_rx_deliver_one(priv, nbuf);
          net_unlock();
        }

      nbuf = next;
    }
}

/****************************************************************************
 * Name: nrf7002_eapol_worker
 *
 * Description:
 *   LPWORK handler that processes queued EAPOL (4-way handshake) frames.
 *   Runs after rx_frm_cb has returned and the NCS HAL lock_rx critical
 *   section has been released, so M2/M4 sent from process_eapol via
 *   start_xmit go out with the RPU TX path ready (no transient -1 failure).
 *
 ****************************************************************************/

static void nrf7002_eapol_worker(FAR void *arg)
{
  struct nrf7002_priv *priv = &g_nrf7002_priv;
  struct nrf7002_nbuf *nbuf;
  struct nrf7002_nbuf *next;
  irqstate_t           flags;
  bool                 resched;

  (void)arg;

  flags = enter_critical_section();
  nbuf                   = priv->eapol_queue_head;
  priv->eapol_queue_head = NULL;
  priv->eapol_queue_tail = NULL;
  leave_critical_section(flags);

  while (nbuf != NULL)
    {
      next       = (struct nrf7002_nbuf *)nbuf->next;
      nbuf->next = NULL;

      if (priv->carrier_up)
        {
          nrf7002_wpa_process_eapol(priv, nbuf->data, nbuf->len);
        }

      nrf_wifi_osal_nbuf_free(nbuf);
      nbuf = next;
    }

  flags = enter_critical_section();
  resched = priv->eapol_queue_head != NULL;
  leave_critical_section(flags);

  if (resched)
    {
      work_queue(LPWORK, &priv->eapol_work, nrf7002_eapol_worker, NULL, 0);
    }
}

/****************************************************************************
 * Private Functions — FMAC callbacks
 *
 * These are called by the NCS FMAC layer on WiFi events.
 ****************************************************************************/

/****************************************************************************
 * Name: nrf7002_scan_done_cb
 *
 * Description:
 *   Called when an RPU scan has completed.  Posts g_nrf7002_priv.scan_sem
 *   so nrf7002_ioctl can return the result to the caller.
 ****************************************************************************/

static void nrf7002_scan_done_cb(
  void *os_vif_ctx,
  struct nrf_wifi_umac_event_trigger_scan *scan_done_event,
  unsigned int event_len)
{
  struct nrf7002_priv    *priv = os_vif_ctx;
  enum nrf_wifi_status    status;

  (void)scan_done_event;
  (void)event_len;

  syslog(LOG_ERR, "nrf7002: SCAN_DONE from RPU, requesting display results\n");

  if (priv == NULL)
    {
      return;
    }

  /* The RPU has finished scanning.  Now send GET_SCAN_RESULTS with
   * SCAN_DISPLAY so the RPU will send NRF_WIFI_UMAC_EVENT_SCAN_DISPLAY_RESULT
   * events (one batch per AP found).  The semaphore is posted by
   * nrf7002_disp_scan_res_cb when it receives the last batch (more_res=false).
   *
   * If there are zero APs, the RPU sends a single SCAN_DISPLAY_RESULT with
   * event_bss_count=0 and seq=0 (more_res=false), which still triggers the
   * semaphore post.
   */

  /* For SCAN_CONNECT: the RPU has already populated its internal BSS
   * database during the active probe scan.  Calling GET_SCAN_RESULTS with
   * SCAN_CONNECT reason causes the RPU to flush those entries before auth,
   * resulting in cmd_status=-2 (ENOENT) when auth is sent.
   * Skip GET_SCAN_RESULTS for SCAN_CONNECT and post the semaphore directly
   * so nrf7002_ioctl_connect can proceed to auth immediately.
   *
   * For SCAN_DISPLAY: call GET_SCAN_RESULTS with SCAN_DISPLAY so the RPU
   * sends NRF_WIFI_UMAC_EVENT_SCAN_DISPLAY_RESULT events (one batch per AP).
   * The semaphore is posted by nrf7002_disp_scan_res_cb (more_res=false).
   */

  if (priv->scan_reason == SCAN_CONNECT)
    {
      /* scan_done_event == NULL: CMD_STATUS EBUSY from the RPU */

      if (scan_done_event == NULL)
        {
          syslog(LOG_INFO, "nrf7002: SCAN_CONNECT EBUSY — retry queued\n");
          priv->scan_done = false;
          priv->state     = NRF7002_STATE_IDLE;
          nxsem_post(&priv->scan_sem);
          return;
        }
    }

  /* Zephyr's nrf_wifi_wpa_supp_scan_results_get() always calls
   * GET_SCAN_RESULTS with SCAN_CONNECT reason — even after a SCAN_DISPLAY
   * trigger scan.  This returns NRF_WIFI_UMAC_EVENT_SCAN_RESULT events
   * with full BSS data (capability, beacon_interval, tsf, signal, IEs)
   * via scan_res_cb.  These BSS entries remain in the RPU's internal
   * database and are used by CMD_AUTHENTICATE.
   * Using SCAN_DISPLAY for GET_SCAN_RESULTS returns only summarized
   * display data without tsf and with potentially missing fields.
   */

  /* Use the same scan_reason that triggered this scan so that
   * SCAN_DISPLAY uses SCAN_DISPLAY (returns display results via
   * disp_scan_res_cb) and SCAN_CONNECT uses SCAN_CONNECT (returns
   * full BSS entries via scan_res_cb without consuming the database).
   */

  syslog(LOG_INFO, "nrf7002: SCAN_DONE — calling GET_SCAN_RESULTS(reason=%d)\n",
         priv->scan_reason);

  status = nrf_wifi_sys_fmac_scan_res_get(priv->fmac_dev_ctx,
                                           priv->vif_idx,
                                           priv->scan_reason);
  if (status != NRF_WIFI_STATUS_SUCCESS)
    {
      syslog(LOG_ERR, "nrf7002: fmac_scan_res_get failed: %d\n", status);

      /* Fall back: post semaphore so scan doesn't hang */

      priv->scan_done = true;
      priv->state     = NRF7002_STATE_IDLE;
      nxsem_post(&priv->scan_sem);
    }
  else
    {
      syslog(LOG_ERR, "nrf7002: GET_SCAN_RESULTS sent (reason=%d), waiting\n",
             priv->scan_reason);
    }
}

/****************************************************************************
 * Name: nrf7002_scan_res_cb
 *
 * Description:
 *   Called once per scan result by the FMAC.
 *   Extracts SSID, BSSID, RSSI and frequency and caches the result in
 *   priv->scan_results[].
 ****************************************************************************/

static void nrf7002_scan_res_cb(
  void *os_vif_ctx,
  struct nrf_wifi_umac_event_new_scan_results *scan_res,
  unsigned int event_len,
  bool more_res)
{
  struct nrf7002_priv       *priv = os_vif_ctx;
  struct nrf7002_scan_result *entry;
  const unsigned char        *ies;
  unsigned int                ies_len;
  unsigned int                ie_off;
  unsigned char               ie_id;
  unsigned char               ie_len;

  (void)event_len;

  if (priv == NULL || scan_res == NULL)
    {
      return;
    }

  if (priv->scan_count >= NRF7002_MAX_SCAN_RESULTS)
    {
      syslog(LOG_WARNING, "nrf7002: scan result table full, dropping\n");
      return;
    }

  syslog(LOG_ERR, "nrf7002: scan_res_cb valid_fields=0x%08x mac=%02x:%02x:%02x:%02x:%02x:%02x "
         "freq=%u rssi=%d ies_len=%u\n",
         scan_res->valid_fields,
         scan_res->mac_addr[0], scan_res->mac_addr[1], scan_res->mac_addr[2],
         scan_res->mac_addr[3], scan_res->mac_addr[4], scan_res->mac_addr[5],
         scan_res->frequency,
         (int)(scan_res->signal.signal.mbm_signal / 100),
         scan_res->ies_len);

  entry = &priv->scan_results[priv->scan_count];
  memset(entry, 0, sizeof(*entry));

  /* BSSID */

  memcpy(entry->bssid, scan_res->mac_addr, NRF7002_MAC_ADDR_LEN);

  /* Frequency */

  entry->frequency = scan_res->frequency;

  /* 802.11 capability, beacon interval and TSF — needed for auth command */

  if (scan_res->valid_fields &
      NRF_WIFI_EVENT_NEW_SCAN_RESULTS_BEACON_INTERVAL_VALID)
    {
      entry->beacon_interval = scan_res->beacon_interval;
    }

  entry->capability = scan_res->capability;
  entry->tsf        = scan_res->ies_tsf; /* TSF from probe response */

  /* RSSI: signal.mbm_signal is in mBm (100 * dBm); convert to dBm */

  if (scan_res->valid_fields &
      NRF_WIFI_EVENT_NEW_SCAN_RESULTS_SIGNAL_VALID)
    {
      entry->rssi     = (int16_t)(scan_res->signal.signal.mbm_signal / 100);
      entry->rssi_mbm = (int32_t)scan_res->signal.signal.mbm_signal;
    }
  else
    {
      entry->rssi     = -127; /* Unknown */
      entry->rssi_mbm = -12700; /* Unknown (-127 dBm in mBm) */
    }

  /* SSID: parse from Information Elements (tag 0 = SSID) */

  ies     = scan_res->ies;
  ies_len = scan_res->ies_len;
  ie_off  = 0;

  while (ie_off + 2 <= ies_len)
    {
      ie_id  = ies[ie_off];
      ie_len = ies[ie_off + 1];

      if (ie_off + 2 + ie_len > ies_len)
        {
          break;
        }

      if (ie_id == 0) /* SSID IE */
        {
          unsigned char ssid_len = ie_len > NRF7002_MAX_SSID_LEN
                                   ? NRF7002_MAX_SSID_LEN : ie_len;
          memcpy(entry->ssid, &ies[ie_off + 2], ssid_len);
          entry->ssid[ssid_len] = '\0';
          entry->ssid_len       = ssid_len;
          break;
        }

      ie_off += 2 + ie_len;
    }

  /* Minimal security classification based on capability (WPA/RSN IE)
   * A full parser would look for IE tag 48 (RSN) or tag 221 (WPA1).
   * For now mark as WPA2 if RSN IE (tag 48) is present.
   */

  entry->security = NRF7002_SECURITY_OPEN;
  ie_off          = 0;
  while (ie_off + 2 <= ies_len)
    {
      ie_id  = ies[ie_off];
      ie_len = ies[ie_off + 1];

      if (ie_off + 2 + ie_len > ies_len)
        {
          break;
        }

      if (ie_id == 48) /* RSN — WPA2 */
        {
          entry->security = NRF7002_SECURITY_WPA2;
          break;
        }

      ie_off += 2 + ie_len;
    }

  syslog(LOG_DEBUG, "nrf7002: scan[%d] ssid='%s' bssid=%02x:%02x:%02x:%02x:%02x:%02x "
         "rssi=%d freq=%lu sec=%d more=%d\n",
         priv->scan_count,
         entry->ssid,
         entry->bssid[0], entry->bssid[1], entry->bssid[2],
         entry->bssid[3], entry->bssid[4], entry->bssid[5],
         entry->rssi, entry->frequency, entry->security, (int)more_res);

  priv->scan_count++;

  /* For SCAN_CONNECT scans, the RPU delivers results via 0x101 events.
   * When more_res=false this is the last result — post scan_sem so that
   * nrf7002_ioctl_connect (which is waiting) can proceed to send auth.
   */

  if (!more_res)
    {
      syslog(LOG_INFO, "nrf7002: scan_res_cb complete: %d BSS entries\n",
             priv->scan_count);
      priv->scan_done = true;
      priv->state     = NRF7002_STATE_IDLE;
      nxsem_post(&priv->scan_sem);
    }
}

/****************************************************************************
 * Name: nrf7002_disp_scan_res_cb
 *
 * Description:
 *   Called for each AP found during a SCAN_DISPLAY scan.
 *   The RPU sends batches of up to DISPLAY_BSS_TOHOST_PEREVNT (8) results.
 *   Extract SSID, BSSID, channel and RSSI and cache in scan_results[].
 ****************************************************************************/

static void nrf7002_disp_scan_res_cb(
  void *os_vif_ctx,
  struct nrf_wifi_umac_event_new_scan_display_results *scan_res,
  unsigned int event_len,
  bool more_res)
{
  struct nrf7002_priv *priv = os_vif_ctx;
  struct nrf7002_scan_result *entry;
  unsigned char               count;
  unsigned char               i;

  (void)event_len;

  syslog(LOG_ERR, "nrf7002: disp_scan_res_cb more_res=%d\n", (int)more_res);

  if (priv == NULL || scan_res == NULL)
    {
      return;
    }

  count = scan_res->event_bss_count;
  syslog(LOG_ERR, "nrf7002: disp_scan_res_cb bss_count=%d\n", (int)count);
  if (count > 8)
    {
      count = 8;  /* DISPLAY_BSS_TOHOST_PEREVNT */
    }

  for (i = 0; i < count; i++)
    {
      struct umac_display_results *r = &scan_res->display_results[i];

      if (priv->scan_count >= NRF7002_MAX_SCAN_RESULTS)
        {
          syslog(LOG_WARNING, "nrf7002: scan result table full, dropping\n");
          break;
        }

      entry = &priv->scan_results[priv->scan_count];
      memset(entry, 0, sizeof(*entry));

      /* BSSID */

      memcpy(entry->bssid, r->mac_addr, NRF7002_MAC_ADDR_LEN);

      /* SSID */

      if (r->ssid.nrf_wifi_ssid_len > 0 &&
          r->ssid.nrf_wifi_ssid_len <= NRF7002_MAX_SSID_LEN)
        {
          memcpy(entry->ssid, r->ssid.nrf_wifi_ssid,
                 r->ssid.nrf_wifi_ssid_len);
          entry->ssid[r->ssid.nrf_wifi_ssid_len] = '\0';
          entry->ssid_len = r->ssid.nrf_wifi_ssid_len;
        }

      /* Frequency from channel number (2.4 GHz: ch1=2412, ch13=2472) */

      if (r->nwk_channel >= 1 && r->nwk_channel <= 13)
        {
          entry->frequency = 2412 + (r->nwk_channel - 1) * 5;
        }
      else if (r->nwk_channel == 14)
        {
          entry->frequency = 2484;
        }
      else if (r->nwk_channel >= 36)
        {
          /* 5 GHz: channel to MHz */

          entry->frequency = 5180 + (r->nwk_channel - 36) * 5;
        }

      /* RSSI: signal_type=2 (MBM) → mbm_signal/100 gives dBm
       *       signal_type=3 (UNSPEC) → unspec_signal is raw dBm (uint8)
       */

      if (r->signal.signal_type == NRF_WIFI_SIGNAL_TYPE_MBM)
        {
          entry->rssi = (int16_t)((int)r->signal.signal.mbm_signal / 100);
        }
      else if (r->signal.signal_type == NRF_WIFI_SIGNAL_TYPE_UNSPEC)
        {
          entry->rssi = (int16_t)r->signal.signal.unspec_signal;
        }
      else
        {
          entry->rssi = 0;
        }

      /* Security: 0=OPEN, anything else=WPA/WPA2 */

      entry->security = (r->security_type == 0) ? NRF7002_SECURITY_OPEN
                                                 : NRF7002_SECURITY_WPA2;

      /* 802.11 capability field and beacon interval (for auth command) */

      entry->capability      = r->capability;
      entry->beacon_interval = r->beacon_interval;

      syslog(LOG_ERR, "nrf7002: disp_scan[%d] ssid='%s' "
             "bssid=%02x:%02x:%02x:%02x:%02x:%02x "
             "ch=%u rssi=%d sigtype=%u sig_raw=%u sec=%d cap=0x%04x bi=%u\n",
             priv->scan_count,
             entry->ssid,
             entry->bssid[0], entry->bssid[1], entry->bssid[2],
             entry->bssid[3], entry->bssid[4], entry->bssid[5],
             r->nwk_channel, entry->rssi,
             r->signal.signal_type, r->signal.signal.mbm_signal,
             entry->security,
             entry->capability, entry->beacon_interval);

      priv->scan_count++;
    }

  /* If this is the last batch (more_res=false), scan is complete */

  if (!more_res)
    {
      syslog(LOG_ERR, "nrf7002: scan complete: %d APs found\n",
             priv->scan_count);
      priv->scan_done = true;
      priv->state     = NRF7002_STATE_IDLE;
      nxsem_post(&priv->scan_sem);
    }
}

/****************************************************************************
 * Name: nrf7002_process_rssi_cb
 *
 * Description:
 *   Called by the FMAC for every received data frame to update the RSSI.
 *   The FMAC always calls this — it does not NULL-check the pointer.
 ****************************************************************************/

static void nrf7002_process_rssi_cb(void *os_vif_ctx, signed short signal)
{
  struct nrf7002_priv *priv = os_vif_ctx;

  if (priv != NULL)
    {
      priv->last_rssi = signal;
    }
}

/****************************************************************************
 * Name: nrf7002_if_carr_state_chg_cb
 *
 * Description:
 *   Called when the link state changes (carrier on/off).
 *   Translates to netdev_carrier_on() / netdev_carrier_off().
 ****************************************************************************/

static enum nrf_wifi_status nrf7002_if_carr_state_chg_cb(
  void *os_vif_ctx,
  enum nrf_wifi_fmac_if_carr_state cs)
{
  struct nrf7002_priv *priv = os_vif_ctx;

  if (priv == NULL)
    {
      return NRF_WIFI_STATUS_FAIL;
    }

  if (cs == NRF_WIFI_FMAC_IF_CARR_STATE_ON)
    {
      syslog(LOG_INFO, "nrf7002: carrier ON\n");
      priv->carrier_up = true;
      priv->state      = NRF7002_STATE_ASSOCIATED;
      netdev_carrier_on(&priv->netdev);
    }
  else
    {
      /* Suppress carrier OFF while already associated.
       * PTK/GTK key refresh (second 4-way handshake) causes the RPU to
       * fire a transient carrier-OFF event during key installation.
       * If we forward it, arp_cleanup() wipes the ARP table and IFF_RUNNING
       * is cleared — the next frame fails with ENETUNREACH even though the
       * AP link is still up.  Real disconnects are handled by deauth_cb /
       * disassoc_cb which explicitly call netdev_carrier_off().
       */
      if (priv->state == NRF7002_STATE_ASSOCIATED)
        {
          syslog(LOG_INFO, "nrf7002: carrier OFF suppressed (key refresh)\n");
        }
      else
        {
          syslog(LOG_INFO, "nrf7002: carrier OFF\n");
          priv->carrier_up = false;
          priv->keys_installed = 0;
          priv->state      = NRF7002_STATE_IDLE;
          netdev_carrier_off(&priv->netdev);
        }
    }

  return NRF_WIFI_STATUS_SUCCESS;
}

/****************************************************************************
 * Name: nrf7002_auth_resp_cb
 *
 * Description:
 *   Called by FMAC when an authentication response frame is received from
 *   the AP.  The 802.11 auth frame body starts at byte 24 (after the fixed
 *   management header):
 *     [0-1] Algorithm
 *     [2-3] Sequence number
 *     [4-5] Status code  (0 = success)
 *
 *   We only log the result; the actual carrier-up happens in assoc_resp_cb.
 *
 ****************************************************************************/

static void nrf7002_auth_resp_cb(FAR void *os_vif_ctx,
                                 FAR struct nrf_wifi_umac_event_mlme *event,
                                 unsigned int event_len)
{
  FAR struct nrf7002_priv *priv = os_vif_ctx;
  uint16_t status = 0xffff;

  (void)event_len;

  /* 802.11 management header = 24 bytes; auth body byte offsets 4-5 = status */

  if (event && event->frame.frame_len >= 24 + 6)
    {
      const unsigned char *body =
        (const unsigned char *)event->frame.frame + 24;
      status = (uint16_t)body[4] | ((uint16_t)body[5] << 8);
    }

  if (status != 0)
    {
      syslog(LOG_WARNING, "nrf7002: auth FAILED status=%u\n", status);
      if (priv)
        {
          priv->state       = NRF7002_STATE_IDLE;
          priv->auth_failed = true;
          nxsem_post(&priv->auth_sem);
        }
      return;
    }

  syslog(LOG_INFO, "nrf7002: auth OK - sending assoc\n");

  if (priv == NULL || priv->state != NRF7002_STATE_AUTHENTICATING)
    {
      syslog(LOG_WARNING, "nrf7002: auth_resp_cb: unexpected state\n");
      return;
    }

  /* Post auth_sem to wake the LPWORK connect thread.  That thread will
   * build and send fmac_assoc from its own stack, avoiding the ~500-byte
   * stack-allocated assoc_info in a shallow HPWORK callback.
   */

  priv->auth_failed = false;
  priv->state       = NRF7002_STATE_AUTHENTICATING; /* keep; thread advances */
  nxsem_post(&priv->auth_sem);
}

/****************************************************************************
 * Name: nrf7002_assoc_resp_cb
 *
 * Description:
 *   Called by FMAC when an association response frame is received.  The
 *   802.11 assoc-resp body starts at byte 24:
 *     [0-1] Capabilities
 *     [2-3] Status code  (0 = success)
 *     [4-5] Association ID
 *
 *   On success (status == 0) we signal carrier-on, which completes the
 *   connection and wakes up any waiting ifup/DHCP.
 *
 ****************************************************************************/

static void nrf7002_assoc_resp_cb(FAR void *os_vif_ctx,
                                  FAR struct nrf_wifi_umac_event_mlme *event,
                                  unsigned int event_len)
{
  FAR struct nrf7002_priv *priv = os_vif_ctx;
  uint16_t status = 0xffff;

  (void)event_len;

  if (priv == NULL)
    {
      return;
    }

  /* 802.11 management header = 24 bytes; assoc-resp body byte offsets 2-3 = status */

  if (event && event->frame.frame_len >= 24 + 6)
    {
      const unsigned char *body =
        (const unsigned char *)event->frame.frame + 24;
      status = (uint16_t)body[2] | ((uint16_t)body[3] << 8);
    }

  if (status == 0)
    {
      int peer_id;
      struct nrf_wifi_sys_fmac_dev_ctx *sys_dev_ctx;

      syslog(LOG_INFO, "nrf7002: assoc OK - carrier ON\n");
      priv->keys_installed =
        (priv->security_type == NRF7002_SECURITY_WPA2) ? 0 : 1;

      /* Register the AP as a host-side FMAC TX peer. */

      peer_id = nrf_wifi_fmac_peer_get_id(priv->fmac_dev_ctx,
                                           priv->target_bssid);
      if (peer_id == -1)
        {
          peer_id = nrf_wifi_fmac_peer_add(priv->fmac_dev_ctx,
                                            priv->vif_idx,
                                            priv->target_bssid,
                                            0 /* is_legacy */,
                                            0 /* qos_supported */);
          if (peer_id >= 0)
            {
              syslog(LOG_INFO, "nrf7002: AP registered as peer %d\n",
                     peer_id);
            }
          else
            {
              syslog(LOG_ERR, "nrf7002: peer_add failed!\n");
            }
        }
      else
        {
          syslog(LOG_INFO, "nrf7002: AP already registered as peer %d\n",
                 peer_id);
        }

      /* NOTE: We previously sent SET_STATION(ASSOCIATED) here to mark the RPU
       * station associated before M2.  The RPU REJECTED it with
       * cmd_status=-22 (EINVAL) — for a STA VIF the association state is owned
       * by the AUTHENTICATE/ASSOCIATE flow, and an extra host SET_STATION is
       * invalid and appears to corrupt the RPU TX state (TX descriptors get
       * mapped but never produce TX_BUFF_DONE).  Removed.
       */

      sys_dev_ctx = wifi_dev_priv(priv->fmac_dev_ctx);
      if (sys_dev_ctx != NULL && peer_id >= 0 && peer_id < MAX_PEERS)
        {
          bool authorized = priv->security_type != NRF7002_SECURITY_WPA2;

          sys_dev_ctx->tx_config.peers[peer_id].authorized = authorized;
          priv->keys_installed = authorized ? 1 : 0;
        }

      priv->carrier_up   = true;
      priv->state        = NRF7002_STATE_ASSOCIATED;
      priv->assoc_failed = false;
      netdev_carrier_on(&priv->netdev);
      nxsem_post(&priv->assoc_sem);
    }
  else
    {
      syslog(LOG_WARNING, "nrf7002: assoc FAILED status=%u\n", status);
      priv->state        = NRF7002_STATE_IDLE;
      priv->assoc_failed = true;
      nxsem_post(&priv->assoc_sem);
    }
}

/****************************************************************************
 * Name: nrf7002_rx_frm_cb
 *
 * Description:
 *   Called by the FMAC when a received Ethernet frame is ready.
 *
 *   Phase 3 optimization: instead of delivering inline (which runs in
 *   whatever context the FMAC interrupt handler uses), we schedule
 *   nrf7002_rx_worker on HPWORK to deliver the frame asynchronously at
 *   high priority.  This reduces interrupt latency in the FMAC path.
 *
 *   The nbuf ownership is transferred to the work item; it will be freed
 *   by nrf7002_rx_worker after delivery.
 *
 ****************************************************************************/

static void nrf7002_rx_frm_cb(void *os_vif_ctx, void *frm)
{
  struct nrf7002_priv *priv = os_vif_ctx;
  struct nrf7002_nbuf *nbuf = (struct nrf7002_nbuf *)frm;
  irqstate_t           flags;

  if (priv == NULL || nbuf == NULL)
    {
      if (nbuf != NULL)
        {
          nrf_wifi_osal_nbuf_free(nbuf);
        }

      return;
    }

  /* EAPOL (4-way handshake) frames: queue + defer to nrf7002_eapol_worker.
   *
   * rx_frm_cb runs inside the NCS HAL lock_rx critical section (see
   * nrf_wifi_fmac_rx_event_process), with the RX descriptor not yet returned.
   * Sending M2/M4 from here (process_eapol -> start_xmit) makes the FMAC TX
   * path fail transiently (start_xmit returns -1), so the AP never receives
   * M2/M4 and disconnects right after EAPOL-4WAY-HS-COMPLETED.  Defer EAPOL
   * processing to a dedicated LPWORK item that runs once lock_rx is released.
   * Keeping EAPOL start_xmit off HPWORK leaves the RPU event bottom half free
   * to deliver TX_DONE and unmap TX descriptors before M1/M3 retries reuse
   * the same BE descriptor slot.
   */

  if (nbuf->len >= 14 && priv->carrier_up &&
      nbuf->data[12] == 0x88 && nbuf->data[13] == 0x8e)
    {
      nbuf->next = NULL;

      flags = enter_critical_section();
      if (priv->eapol_queue_tail != NULL)
        {
          priv->eapol_queue_tail->next = nbuf;
        }
      else
        {
          priv->eapol_queue_head = nbuf;
        }

      priv->eapol_queue_tail = nbuf;
      leave_critical_section(flags);

      work_queue(LPWORK, &priv->eapol_work, nrf7002_eapol_worker, NULL, 0);
      return;
    }

  /* Enqueue the frame onto the RX queue.
   *
   * The queue is protected by a critical section (interrupt disable) so
   * this is safe to call from any context the FMAC uses (including from
   * within the QSPI interrupt handler).
   *
   * We then (re-)schedule rx_worker on HPWORK.  If a work item is already
   * pending, work_queue returns -EALREADY / -EBUSY and we ignore it — the
   * already-queued rx_worker will drain the frame we just enqueued.
   */

  nbuf->next = NULL;

  flags = enter_critical_section();
  if (priv->rx_queue_tail != NULL)
    {
      priv->rx_queue_tail->next = nbuf;
    }
  else
    {
      priv->rx_queue_head = nbuf;
    }

  priv->rx_queue_tail = nbuf;
  leave_critical_section(flags);

  /* Schedule the data-frame worker on LPWORK.
   *
   * RX delivery (deep ipv4_input→TCP→txpoll chain) and TX poll both run on
   * LPWORK, separate from HPWORK which services the RPU HOSTIRQ bottom-half
   * and NCS HAL event/TX-done tasklets.  Keeping the FMAC-touching TX path
   * off HPWORK prevents the "start_xmit waits for an RPU response that only
   * HPWORK can deliver" deadlock.  Both share the LPWORK thread so dev->d_buf
   * has one owner.  The NCS tx_lock mutex is taken from both LPWORK (txpoll)
   * and HPWORK (TX-done in the event tasklet); CONFIG_PRIORITY_INHERITANCE
   * must be enabled so the LPWORK holder is boosted and HPWORK does not
   * block indefinitely (priority inversion).
   */

  work_queue(LPWORK, &priv->rx_work, nrf7002_rx_worker, NULL, 0);
}

/****************************************************************************
 * Name: g_nrf7002_callbk_fns
 *
 * Description:
 *   Minimum callback set required by nrf_wifi_sys_fmac_init.
 *   Callbacks not needed are left NULL.
 ****************************************************************************/

/****************************************************************************
 * Name: nrf7002_deauth_cb / nrf7002_disassoc_cb
 *
 * Description:
 *   Called when the AP sends a Deauthentication or Disassociation frame.
 *   Update local state so the driver knows the link is down.
 *
 ****************************************************************************/

static void nrf7002_deauth_cb(void *os_vif_ctx,
                               struct nrf_wifi_umac_event_mlme *event,
                               unsigned int event_len)
{
  struct nrf7002_priv *priv = os_vif_ctx;

  (void)event;
  (void)event_len;

  if (priv == NULL)
    {
      return;
    }

  syslog(LOG_WARNING, "nrf7002: deauth from AP — carrier OFF\n");

  priv->carrier_up = false;
  priv->keys_installed = 0;
  priv->state      = NRF7002_STATE_IDLE;
  netdev_carrier_off(&priv->netdev);
}

static void nrf7002_disassoc_cb(void *os_vif_ctx,
                                 struct nrf_wifi_umac_event_mlme *event,
                                 unsigned int event_len)
{
  struct nrf7002_priv *priv = os_vif_ctx;

  (void)event;
  (void)event_len;

  if (priv == NULL)
    {
      return;
    }

  syslog(LOG_WARNING, "nrf7002: disassoc from AP — carrier OFF\n");

  priv->carrier_up = false;
  priv->keys_installed = 0;
  priv->state      = NRF7002_STATE_IDLE;
  netdev_carrier_off(&priv->netdev);
}

static struct nrf_wifi_fmac_callbk_fns g_nrf7002_callbk_fns =
{
  .scan_done_callbk_fn         = nrf7002_scan_done_cb,
  .scan_res_callbk_fn          = nrf7002_scan_res_cb,
  .disp_scan_res_callbk_fn     = nrf7002_disp_scan_res_cb,
  .if_carr_state_chg_callbk_fn = nrf7002_if_carr_state_chg_cb,
  .rx_frm_callbk_fn            = nrf7002_rx_frm_cb,
  .auth_resp_callbk_fn         = nrf7002_auth_resp_cb,
  .assoc_resp_callbk_fn        = nrf7002_assoc_resp_cb,
  .deauth_callbk_fn            = nrf7002_deauth_cb,
  .disassoc_callbk_fn          = nrf7002_disassoc_cb,
  .process_rssi_from_rx        = nrf7002_process_rssi_cb,
};

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: nrf7002_initialize
 *
 * Description:
 *   Full driver initialization sequence:
 *
 *   1. Register NuttX OSAL ops with the NCS firmware stack
 *   2. Initialize FMAC layer (HAL + BAL + OSAL internal state)
 *   3. Power-up the RPU and add the QSPI device
 *   4. Download RPU firmware and bring up the interface
 *   5. Add a STA VIF
 *   6. Register the NuttX network device
 *
 * Returned Value:
 *   OK on success; negated errno on failure.
 *
 ****************************************************************************/

int nrf7002_initialize(void)
{
  struct nrf7002_priv    *priv = &g_nrf7002_priv;
  FAR struct qspi_dev_s  *saved_qspi_dev;
  int                     ret;

  /* Save the QSPI bus handle set by the board-level code (nrf53_nrf7002.c)
   * before clearing the struct.  The board code sets qspi_ctx.qspi_dev via
   *   g_nrf7002_priv.qspi_ctx.qspi_dev = nrf53_qspi_initialize(0);
   * before calling nrf7002_initialize().  The memset below would clear it,
   * causing all subsequent QSPI accesses to see a NULL pointer.
   */

  saved_qspi_dev = priv->qspi_ctx.qspi_dev;

  memset(priv, 0, sizeof(*priv));

  /* Restore the QSPI handle so nrf7002_qspi_bus_init (called back by the
   * FMAC during nrf_wifi_sys_fmac_init) finds a valid bus pointer.
   */

  priv->qspi_ctx.qspi_dev = saved_qspi_dev;

  nxmutex_init(&priv->lock);
  nxsem_init(&priv->scan_sem, 0, 0);
  nxsem_init(&priv->auth_sem,  0, 0);
  nxsem_init(&priv->assoc_sem, 0, 0);
  priv->auth_failed   = false;
  priv->rx_queue_head = NULL;
  priv->rx_queue_tail = NULL;

  /* Phase 3: Initialize TX tokens semaphore.
   * NRF7002_TX_TOKENS = 2 means at most 2 frames can be in-flight
   * simultaneously toward the RPU.
   */

  nxsem_init(&priv->tx_tokens, 0, NRF7002_TX_TOKENS);

  priv->state     = NRF7002_STATE_UNINIT;
  priv->last_rssi = -127;

  /* Step 1: Register OSAL ops.
   * This must happen before any other nrf_wifi_* call.
   */

  nrf_wifi_osal_init(&nrf7002_osal_ops);
  syslog(LOG_INFO, "nrf7002: OSAL registered\n");

  /* Step 2: Initialize FMAC.
   * Mirror the Zephyr nrf_wifi data configuration.  Leaving these fields at
   * zero lets host TX commands queue locally, but the RPU data/TX side is not
   * configured the same way as the reference driver and never completes TX.
   */

  memset(&g_data_config, 0, sizeof(g_data_config));
  g_data_config.rate_protection_type     = 0;
  g_data_config.aggregation              = NRF_WIFI_FEATURE_ENABLE;
  g_data_config.wmm                      = NRF_WIFI_FEATURE_ENABLE;
  g_data_config.max_num_tx_agg_sessions  = NRF7002_MAX_TX_AGG_SESSIONS;
  g_data_config.max_num_rx_agg_sessions  = NRF7002_MAX_RX_AGG_SESSIONS;
  g_data_config.max_tx_aggregation       = NRF7002_MAX_TX_AGGREGATION;
  g_data_config.reorder_buf_size         = NRF7002_RX_REORDER_BUF_SIZE;
  g_data_config.max_rxampdu_size         = MAX_RX_AMPDU_SIZE_64KB;

  priv->fmac_priv = nrf_wifi_sys_fmac_init(&g_data_config,
                                             g_rx_buf_pools,
                                             &g_nrf7002_callbk_fns);
  if (priv->fmac_priv == NULL)
    {
      syslog(LOG_ERR, "nrf7002: nrf_wifi_sys_fmac_init failed\n");
      ret = -ENOMEM;
      goto err_osal;
    }

  syslog(LOG_INFO, "nrf7002: FMAC initialized\n");

#ifdef NRF70_DATA_TX
  {
    struct nrf_wifi_sys_fmac_priv *sys_fpriv;

    sys_fpriv = wifi_fmac_priv(priv->fmac_priv);
    sys_fpriv->max_ampdu_len_per_token =
      (RPU_PKTRAM_SIZE - (NRF70_RX_NUM_BUFS * NRF70_RX_MAX_DATA_SIZE)) /
      NRF70_MAX_TX_TOKENS;
    sys_fpriv->max_ampdu_len_per_token &= ~0x3u;
    sys_fpriv->avail_ampdu_len_per_token =
      sys_fpriv->max_ampdu_len_per_token -
      (NRF7002_MAX_PKT_RAM_TX_ALIGN_OVERHEAD *
       g_data_config.max_tx_aggregation);

    syslog(LOG_INFO,
           "nrf7002: TX PKTRAM token=%u avail=%u agg=%u\n",
           sys_fpriv->max_ampdu_len_per_token,
           sys_fpriv->avail_ampdu_len_per_token,
           g_data_config.max_tx_aggregation);
  }
#endif

  /* Step 3: Add RPU device.
   * The FMAC will call bus_qspi_dev_add which binds the QSPI handle.
   * The qspi_dev pointer must be set in priv->qspi_ctx before this call
   * by the board-level bringup code (nrf53_nrf7002.c).
   */

  priv->fmac_dev_ctx = nrf_wifi_sys_fmac_dev_add(priv->fmac_priv, priv);
  if (priv->fmac_dev_ctx == NULL)
    {
      syslog(LOG_ERR, "nrf7002: nrf_wifi_fmac_dev_add failed\n");
      ret = -ENODEV;
      goto err_fmac;
    }

  syslog(LOG_INFO, "nrf7002: RPU device added\n");

  /* Step 3b: Parse and download the RPU firmware patch blob.
   *
   * The nRF7002 RPU contains a base ROM firmware; the blob loaded here
   * patches the LMAC and UMAC.  Without this step fmac_dev_init fails
   * because the RPU cannot respond to commands.
   *
   * This matches the Zephyr flow in:
   *   zephyr/drivers/wifi/nrf_wifi/src/fmac_main.c (nrf_wifi_fw_load)
   */

  {
    struct nrf_wifi_fmac_fw_info fw_info;

    memset(&fw_info, 0, sizeof(fw_info));

    ret = nrf_wifi_fmac_fw_parse(priv->fmac_dev_ctx,
                                  g_nrf70_fw_patch,
                                  g_nrf70_fw_patch_len,
                                  &fw_info);
    if (ret != NRF_WIFI_STATUS_SUCCESS)
      {
        syslog(LOG_ERR, "nrf7002: nrf_wifi_fmac_fw_parse failed: %d\n", ret);
        /* Continue — let dev_init report the error rather than aborting */
      }
    else
      {
        ret = nrf_wifi_fmac_fw_load(priv->fmac_dev_ctx, &fw_info);
        if (ret != NRF_WIFI_STATUS_SUCCESS)
          {
            syslog(LOG_ERR,
                   "nrf7002: nrf_wifi_fmac_fw_load failed: %d\n", ret);
          }
        else
          {
            syslog(LOG_INFO, "nrf7002: RPU firmware blob loaded (%u bytes)\n",
                   g_nrf70_fw_patch_len);
          }
      }
  }

  /* Step 4: Initialize RPU (brings up UMAC/LMAC using the loaded firmware).
   *
   * All fields in these structs are 0 (all-bands backoff disabled, all
   * gains 0 dBi, all PCB losses 0 dB) — correct for the nRF7002-DK
   * reference design.  Passing NRF_WIFI_DEF_PHY_CALIB enables the full
   * RF calibration sequence including 2.4 GHz RX/TX DC and IQ.
   */

  struct nrf_wifi_tx_pwr_ctrl_params tx_pwr_ctrl;
  struct nrf_wifi_tx_pwr_ceil_params tx_pwr_ceil;
  struct nrf_wifi_board_params       board_params;

  memset(&tx_pwr_ctrl,  0, sizeof(tx_pwr_ctrl));
  memset(&tx_pwr_ceil,  0, sizeof(tx_pwr_ceil));
  memset(&board_params, 0, sizeof(board_params));

  ret = nrf_wifi_sys_fmac_dev_init(priv->fmac_dev_ctx,
#if defined(NRF_WIFI_LOW_POWER)
                                  0,    /* sleep_type: disabled */
#endif
                                  NRF_WIFI_DEF_PHY_CALIB, /* full RF calib incl 2.4GHz */
                                  BAND_ALL, /* op_band: both 2.4/5GHz */
                                  false, /* beamforming: disabled */
                                  &tx_pwr_ctrl,
                                  &tx_pwr_ceil,
                                  &board_params,
                                  (unsigned char *)"CN"  /* country_code */);
  if (ret != NRF_WIFI_STATUS_SUCCESS)
    {
      syslog(LOG_WARNING,
             "nrf7002: nrf_wifi_sys_fmac_dev_init failed: %d "
             "(QSPI/RPU not responding — CS pin conflict or hardware issue; "
             "continuing so NSH remains usable)\n", ret);
      /* Continue: register the netdev stub so ifconfig/iwlist don't crash.
       * WiFi operations will fail until the QSPI CS pin conflict is resolved.
       */
    }
  else
    {
      syslog(LOG_INFO, "nrf7002: RPU firmware initialized\n");
    }

  /* Step 5: Add a STA VIF */

  {
    struct nrf_wifi_umac_add_vif_info vif_info;

    memset(&vif_info, 0, sizeof(vif_info));
    vif_info.iftype = NRF_WIFI_IFTYPE_STATION;

    priv->vif_idx = nrf_wifi_sys_fmac_add_vif(priv->fmac_dev_ctx,
                                               priv,
                                               &vif_info);
    if (priv->vif_idx == 0xff)
      {
        syslog(LOG_WARNING, "nrf7002: nrf_wifi_sys_fmac_add_vif failed "
               "(continuing without VIF)\n");
      }
    else
      {
        syslog(LOG_INFO, "nrf7002: VIF %u added\n", priv->vif_idx);
      }
  }

  /* Step 5b: Read hardware MAC from OTP and update netdev d_mac.
   * The nRF7002 chip has its own OTP-programmed MAC.  NuttX must
   * use that same MAC for Ethernet frames so the AP accepts data.
   */

  {
    unsigned char otp_mac[NRF7002_MAC_ADDR_LEN];
    enum nrf_wifi_status mac_status;

    memset(otp_mac, 0, sizeof(otp_mac));
    mac_status = nrf_wifi_fmac_otp_mac_addr_get(priv->fmac_dev_ctx,
                                                 priv->vif_idx,
                                                 otp_mac);
    if (mac_status == NRF_WIFI_STATUS_SUCCESS &&
        (otp_mac[0] | otp_mac[1] | otp_mac[2] |
         otp_mac[3] | otp_mac[4] | otp_mac[5]) != 0)
      {
        memcpy(priv->mac_addr, otp_mac, NRF7002_MAC_ADDR_LEN);
        syslog(LOG_INFO,
               "nrf7002: OTP MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
               otp_mac[0], otp_mac[1], otp_mac[2],
               otp_mac[3], otp_mac[4], otp_mac[5]);

        /* Program the OTP MAC into the RPU VIF so the firmware uses it
         * for OTA 802.11 frames.  Must match what NuttX puts in d_mac.
         */

        mac_status = nrf_wifi_sys_fmac_set_vif_macaddr(priv->fmac_dev_ctx,
                                                        priv->vif_idx,
                                                        otp_mac);
        if (mac_status != NRF_WIFI_STATUS_SUCCESS)
          {
            syslog(LOG_WARNING,
                   "nrf7002: set_vif_macaddr failed (%d)\n",
                   (int)mac_status);
          }
      }
    else
      {
        syslog(LOG_WARNING,
               "nrf7002: OTP MAC read failed (%d), using default\n",
               (int)mac_status);
      }
  }

  /* Step 6: Register NuttX network device */

  ret = nrf7002_netdev_register(priv);
  if (ret < 0)
    {
      syslog(LOG_ERR, "nrf7002: netdev_register failed: %d\n", ret);
      goto err_vif;
    }

  priv->state = NRF7002_STATE_IDLE;
  syslog(LOG_INFO, "nrf7002: driver initialized\n");

  return OK;

err_vif:
  nrf_wifi_sys_fmac_dev_deinit(priv->fmac_dev_ctx);
  nrf_wifi_fmac_dev_rem(priv->fmac_dev_ctx);

err_fmac:
  nrf_wifi_fmac_deinit(priv->fmac_priv);

err_osal:
  nxsem_destroy(&priv->tx_tokens);
  nxmutex_destroy(&priv->lock);
  nxsem_destroy(&priv->scan_sem);
  nxsem_destroy(&priv->auth_sem);
  nxsem_destroy(&priv->assoc_sem);

  return ret;
}
