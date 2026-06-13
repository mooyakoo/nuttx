/****************************************************************************
 * drivers/wireless/ieee80211/nrf7002/nrf7002_netdev.c
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
 * net_driver_s operations for the nRF7002 WiFi driver.
 *
 * Phase 3 additions:
 *   - txpoll: token-based TX path via nrf_wifi_fmac_start_xmit
 *   - netdev_txnotify: invokes txpoll if carrier is up
 *   - ifup/ifdown: power management via nrf_wifi_sys_fmac_set_power_save
 *   - SIOCSIWMODE: AP mode stub (CONFIG_IEEE80211_NRF7002_AP_MODE)
 *   - SIOCGIWSTATS: return RSSI from last scan result
 *
 * Reference: drivers/wireless/ieee80211/bcm43xxx/bcmf_netdev.c
 *            include/nuttx/wireless/wireless.h
 *            NCS/modules/lib/nrf_wifi/fw_if/umac_if/inc/
 *              system/fmac_api.h
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <stdint.h>

#include <nuttx/kmalloc.h>
#include <nuttx/signal.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <nuttx/net/net.h>
#include <nuttx/net/netdev.h>
#include <nuttx/wireless/wireless.h>

#include "fmac_api.h"
#include "host_rpu_umac_if.h"
#include "nrf7002_driver.h"
#include "nrf7002_wpa.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/* Maximum time (ms) to wait for scan to complete */

/* Packet buffer size: max Ethernet frame + guard bytes */

#ifndef MAX_NETDEV_PKTSIZE
#  define MAX_NETDEV_PKTSIZE CONFIG_NET_ETH_PKTSIZE
#endif

#define NRF7002_PKTBUF_SIZE  ((MAX_NETDEV_PKTSIZE + CONFIG_NET_GUARDSIZE + 1) & ~1u)

#define NRF7002_SCAN_TIMEOUT_MS  15000

#define NRF7002_EAPOL_ETHERTYPE      0x888e
#define NRF7002_TX_NBUF_HEADROOM     100

/****************************************************************************
 * Private Data
 ****************************************************************************/

/* Static flat packet buffer used by devif_poll.
 * devif_poll uses dev->d_buf as the output buffer when it is non-NULL
 * (flat-buffer mode).  Without a pre-allocated d_buf the poll falls
 * into IOB mode which the nrf7002 TX path does not support.
 */

static uint16_t g_nrf7002_pktbuf[NRF7002_PKTBUF_SIZE / 2];

/****************************************************************************
 * Private Function Prototypes
 ****************************************************************************/

static int nrf7002_ifup(FAR struct net_driver_s *dev);
static int nrf7002_ifdown(FAR struct net_driver_s *dev);
int nrf7002_txpoll(FAR struct net_driver_s *dev);
static int nrf7002_txnotify(FAR struct net_driver_s *dev);
#ifdef CONFIG_NETDEV_IOCTL
static int nrf7002_ioctl(FAR struct net_driver_s *dev,
                          int cmd, unsigned long arg);
#endif

static bool nrf7002_is_eapol_frame(FAR const uint8_t *frame, size_t len);

/****************************************************************************
 * Private Functions
 ****************************************************************************/

static bool nrf7002_is_eapol_frame(FAR const uint8_t *frame, size_t len)
{
  uint16_t ethertype;

  if (frame == NULL || len < 14)
    {
      return false;
    }

  ethertype = ((uint16_t)frame[12] << 8) | frame[13];

  return ethertype == NRF7002_EAPOL_ETHERTYPE;
}

/****************************************************************************
 * Name: nrf7002_txpoll
 *
 * Description:
 *   Phase 3 TX path: token-based frame submission.
 *
 *   1. Try to acquire a TX token (non-blocking).  If none available, the
 *      RPU is busy — return -EAGAIN to throttle the stack.
 *   2. Copy d_buf/d_len into an nbuf via nrf_wifi_osal_nbuf_alloc.
 *   3. Submit via nrf_wifi_fmac_start_xmit.
 *      On failure, FMAC has freed the nbuf; return the token.
 *   4. Clear d_buf so the stack does not attempt a second send.
 *
 *   The TX token is local backpressure only and is returned immediately
 *   after nrf_wifi_fmac_start_xmit accepts or rejects the frame.
 *
 ****************************************************************************/

int nrf7002_txpoll(FAR struct net_driver_s *dev)
{
  FAR struct nrf7002_priv   *priv =
    (FAR struct nrf7002_priv *)dev->d_private;
  enum nrf_wifi_status       status;
  void                      *nbuf;
  int                        ret;

  /* Must have a frame to send */

  if (dev->d_buf == NULL || dev->d_len == 0)
    {
      return OK;
    }


  if (!priv->carrier_up || priv->fmac_dev_ctx == NULL)
    {
      return -ENETDOWN;
    }

  if (priv->security_type == NRF7002_SECURITY_WPA2 &&
      priv->keys_installed == 0 &&
      !nrf7002_is_eapol_frame((FAR const uint8_t *)dev->d_buf,
                              dev->d_len))
    {
      return -EAGAIN;
    }

  /* Acquire a TX token — non-blocking.
   * If the semaphore count is 0 all tokens are in-flight; bail.
   */

  ret = nxsem_trywait(&priv->tx_tokens);
  if (ret < 0)
    {
      /* No token available — backpressure the stack */

      return -EAGAIN;
    }

  /* Allocate a network buffer and copy the frame data.
   * The OSAL nbuf abstraction provides the buffer management that the
   * FMAC layer expects.
   */

  nbuf = nrf_wifi_osal_nbuf_alloc(dev->d_len + NRF7002_TX_NBUF_HEADROOM);
  if (nbuf == NULL)
    {
      syslog(LOG_WARNING, "nrf7002: txpoll: nbuf alloc failed\n");
      nxsem_post(&priv->tx_tokens);
      return -ENOMEM;
    }

  /* Use data_put to extend the tail and set len, then copy frame data */

  nrf_wifi_osal_nbuf_headroom_res(nbuf, NRF7002_TX_NBUF_HEADROOM);
  nrf_wifi_osal_nbuf_data_put(nbuf, dev->d_len);
  memcpy(nrf_wifi_osal_nbuf_data_get(nbuf), dev->d_buf, dev->d_len);

  NETDEV_TXPACKETS(dev);

  /* Submit to the FMAC layer.
   * nrf_wifi_fmac_start_xmit internally queues the frame and sends it to
   * the RPU when tokens are available in the NCS layer.
   */

  status = nrf_wifi_fmac_start_xmit(priv->fmac_dev_ctx,
                                     priv->vif_idx,
                                     nbuf);
  if (status != NRF_WIFI_STATUS_SUCCESS)
    {
      /* TX failed — most likely the NCS TX token/descriptor pool is
       * momentarily exhausted under high TX rate (TX-done not yet processed).
       * FMAC has freed the nbuf; return the local token and apply
       * backpressure with -EAGAIN so the network stack retries this frame
       * later instead of dropping it.  Rate-limit the log.
       */

      static uint32_t fail_cnt = 0;
      if ((++fail_cnt % 64) == 1)
        {
          syslog(LOG_WARNING, "nrf7002: txpoll start_xmit busy (%d) #%lu\n",
                 status, (unsigned long)fail_cnt);
        }

      /* nrf_wifi_fmac_start_xmit() frees nbuf on failure. */

      nxsem_post(&priv->tx_tokens);
      return -EAGAIN;
    }

  /* Frame ownership transferred to FMAC.
   * Return the driver-level TX token immediately — the FMAC manages its
   * own internal token pool.  The driver token is purely for local
   * backpressure (limiting concurrent start_xmit calls).
   */

  nxsem_post(&priv->tx_tokens);

  /* Reset d_len to indicate we consumed the frame.
   * Do NOT set d_buf = NULL — devif_poll manages d_buf; clearing it
   * would break the devif_poll flat-buffer mode loop.
   */

  dev->d_len = 0;

  NETDEV_TXDONE(dev);

  return OK;
}

/****************************************************************************
 * Name: nrf7002_txnotify
 *
 * Description:
 *   Callback from the network layer when a new TX frame is available.
 *   Calls txpoll directly when the carrier is up.
 *
 ****************************************************************************/

/****************************************************************************
 * Name: nrf7002_txavail_work
 *
 * Description:
 *   LPWORK handler that runs the TX poll under net_lock.  Scheduled by
 *   nrf7002_txnotify.  Runs on the SAME LPWORK queue as nrf7002_rx_worker so
 *   TX poll and RX delivery serialize on one thread (single dev->d_buf owner).
 *   Kept off HPWORK so start_xmit never blocks the thread that delivers RPU
 *   responses.  net_lock matches the RX path's locking.
 *
 ****************************************************************************/

static void nrf7002_txavail_work(FAR void *arg)
{
  FAR struct nrf7002_priv *priv = (FAR struct nrf7002_priv *)arg;
  FAR struct net_driver_s *dev  = &priv->netdev;

  net_lock();

  /* Guard against reentrancy: rx_deliver_one and txpoll both run devif
   * output under net_lock on the same LPWORK thread.  If a TX poll re-enters
   * devif_poll (e.g. tcpsend_eventhandler queuing more output that loops back
   * here) the recursion blows the work-queue stack.  A simple in-progress
   * flag breaks the loop; the still-pending work item will retry later.
   */

  if (priv->tx_poll_busy)
    {
      /* Reentrant call on the same thread (recursive devif output) — bail to
       * break the recursion, but re-arm the worker (1-tick delay to avoid a
       * busy loop) so the pending TX is serviced after the current poll
       * completes instead of being dropped (which would stall the stream).
       */

      net_unlock();
      work_queue(LPWORK, &priv->tx_work, nrf7002_txavail_work, priv, 1);
      return;
    }

  priv->tx_poll_busy = true;

  /* Clear the pending flag before polling so any notification that arrives
   * during devif_poll is observed at the end and triggers a re-poll.
   */

  priv->tx_pending = false;

  if (priv->carrier_up)
    {
      devif_poll(dev, nrf7002_txpoll);
    }

  priv->tx_poll_busy = false;

  /* A txnotify arrived while we were polling — re-arm to drain it.  This
   * closes the work_queue debounce window (notifications coalesced while the
   * work item was already executing would otherwise be lost).
   */

  if (priv->tx_pending)
    {
      priv->tx_pending = false;
      work_queue(LPWORK, &priv->tx_work, nrf7002_txavail_work, priv, 0);
    }

  net_unlock();
}

/****************************************************************************
 * Name: nrf7002_txnotify
 *
 * Description:
 *   d_txavail callback.  The socket TX path (e.g. psock_tcp_send) calls this
 *   WITHOUT holding net_lock and from an arbitrary task context.  Calling
 *   devif_poll inline here would race nrf7002_rx_worker (LPWORK) over
 *   dev->d_buf and corrupt it under bidirectional load (iperf).  Defer to
 *   LPWORK so the poll runs serially with RX delivery under net_lock.
 *
 ****************************************************************************/

static int nrf7002_txnotify(FAR struct net_driver_s *dev)
{
  FAR struct nrf7002_priv *priv =
    (FAR struct nrf7002_priv *)dev->d_private;


  if (priv->carrier_up)
    {
      /* Mark a pending notification so a txnotify that lands while the worker
       * is already running (work_queue debounce window) is not lost.  Ignore
       * EBUSY from work_queue — an already-queued tx_work covers it.
       */

      priv->tx_pending = true;
      work_queue(LPWORK, &priv->tx_work, nrf7002_txavail_work, priv, 0);
    }

  return OK;
}

/****************************************************************************
 * Name: nrf7002_ifup
 *
 * Description:
 *   Bring the WiFi interface up.
 *
 *   Phase 3: disable power save (PS_DISABLED) when the interface comes up
 *   so the RPU is ready for active TX/RX.
 *
 ****************************************************************************/

static int nrf7002_ifup(FAR struct net_driver_s *dev)
{
  FAR struct nrf7002_priv *priv =
    (FAR struct nrf7002_priv *)dev->d_private;
  struct nrf_wifi_umac_chg_vif_state_info vif_state;
  enum nrf_wifi_status status;

  syslog(LOG_INFO, "nrf7002: ifup\n");

  priv->state = NRF7002_STATE_IDLE;

  if (priv->fmac_dev_ctx != NULL && priv->carrier_up == false)
    {
      /* Disable power save so the RPU stays active */

      nrf_wifi_sys_fmac_set_power_save(priv->fmac_dev_ctx,
                                        priv->vif_idx,
                                        false /* PS disabled */);

      /* Set VIF state to UP in the UMAC firmware.
       *
       * The RPU UMAC requires the VIF to be set UP (state=1) via
       * NRF_WIFI_UMAC_CMD_SET_IFFLAGS before it will process scan
       * or connect requests.  Without this, fmac_scan silently
       * accepts the command but the RPU never starts scanning.
       */

      memset(&vif_state, 0, sizeof(vif_state));
      vif_state.state    = 1;            /* UP */
      vif_state.if_index = priv->vif_idx;

      syslog(LOG_ERR, "nrf7002: calling chg_vif_state(UP) vif=%d\n",
             priv->vif_idx);
      status = nrf_wifi_sys_fmac_chg_vif_state(priv->fmac_dev_ctx,
                                                priv->vif_idx,
                                                &vif_state);
      syslog(LOG_ERR, "nrf7002: chg_vif_state returned %d\n", status);
      if (status != NRF_WIFI_STATUS_SUCCESS)
        {
          syslog(LOG_ERR,
                 "nrf7002: chg_vif_state(UP) FAILED: %d\n", status);
        }
      else
        {
          syslog(LOG_ERR, "nrf7002: VIF set UP in UMAC OK\n");
        }
    }

  return OK;
}

/****************************************************************************
 * Name: nrf7002_ifdown
 *
 * Description:
 *   Take the WiFi interface down.
 *
 *   Phase 3: enable power save (PS_ENABLED) when the interface goes down
 *   to reduce current draw while idle.
 *
 ****************************************************************************/

static int nrf7002_ifdown(FAR struct net_driver_s *dev)
{
  FAR struct nrf7002_priv *priv =
    (FAR struct nrf7002_priv *)dev->d_private;

  syslog(LOG_INFO, "nrf7002: ifdown\n");

  priv->state      = NRF7002_STATE_IDLE;
  priv->carrier_up = false;

  /* Enable power save on ifdown to reduce idle current */

  if (priv->fmac_dev_ctx != NULL)
    {
      nrf_wifi_sys_fmac_set_power_save(priv->fmac_dev_ctx,
                                        priv->vif_idx,
                                        true /* PS enabled */);
    }

  return OK;
}

#ifdef CONFIG_NETDEV_IOCTL

/****************************************************************************
 * Name: nrf7002_ioctl_scan
 *
 * Description:
 *   SIOCSIWSCAN — trigger a background scan.
 *   Clears the cached result table, issues nrf_wifi_sys_fmac_scan, then
 *   issues nrf_wifi_sys_fmac_scan_res_get to ask the RPU to send the
 *   results via scan_res_callbk_fn / scan_done_callbk_fn.
 *
 *   The caller (typically wapi or a scan daemon) should call SIOCGIWSCAN
 *   after the scan completes.  We do a blocking wait with timeout here so
 *   that a simple "wapi scan wlan0" works.
 *
 ****************************************************************************/

static int nrf7002_ioctl_scan(FAR struct nrf7002_priv *priv)
{
  struct nrf_wifi_umac_scan_info scan_info;
  enum nrf_wifi_status           status;
  struct timespec                ts;
  int                            ret;

  if (priv->fmac_dev_ctx == NULL)
    {
      return -ENODEV;
    }

  /* Reset scan state */

  priv->scan_count  = 0;
  priv->scan_done   = false;
  priv->scan_reason = SCAN_DISPLAY;
  priv->state       = NRF7002_STATE_SCANNING;

  memset(&scan_info, 0, sizeof(scan_info));
  scan_info.scan_reason = SCAN_DISPLAY;

  /* Scan all bands (bands=0 means both 2.4 GHz and 5 GHz).
   * This is the default: let the RPU scan everything based on the
   * regulatory domain set during firmware initialization.
   */
  scan_info.scan_params.bands = 0;  /* 0 = all bands */

  /* Trigger the scan */

  syslog(LOG_ERR, "nrf7002: calling fmac_scan vif=%d\n", priv->vif_idx);
  status = nrf_wifi_sys_fmac_scan(priv->fmac_dev_ctx,
                                   priv->vif_idx,
                                   &scan_info);
  syslog(LOG_ERR, "nrf7002: fmac_scan returned %d\n", status);
  if (status != NRF_WIFI_STATUS_SUCCESS)
    {
      syslog(LOG_ERR, "nrf7002: fmac_scan failed (%d)\n", status);
      priv->state = NRF7002_STATE_IDLE;
      return -EIO;
    }

  /* Wait for the scan to complete.
   *
   * Flow:
   *   1. fmac_scan sends TRIGGER_SCAN to RPU
   *   2. RPU sends SCAN_DONE event → scan_done_cb fires
   *   3. scan_done_cb calls fmac_scan_res_get(SCAN_DISPLAY)
   *   4. RPU sends SCAN_DISPLAY_RESULT events → disp_scan_res_cb fires per AP
   *   5. disp_scan_res_cb posts scan_sem when more_res=false (last batch)
   */

  clock_gettime(CLOCK_REALTIME, &ts);
  ts.tv_sec += NRF7002_SCAN_TIMEOUT_MS / 1000;

  ret = nxsem_timedwait(&priv->scan_sem, &ts);
  if (ret == -ETIMEDOUT)
    {
      syslog(LOG_WARNING, "nrf7002: scan timeout\n");
      priv->state = NRF7002_STATE_IDLE;
      return -ETIMEDOUT;
    }

  syslog(LOG_INFO, "nrf7002: scan complete: %d APs found\n",
         priv->scan_count);

  return OK;
}

/****************************************************************************
 * Name: nrf7002_ioctl_get_scan
 *
 * Description:
 *   SIOCGIWSCAN — return cached scan results as iw_event list.
 *
 *   Each AP is serialized as a sequence of iw_event structures written
 *   into the caller's buffer (wrq->u.data.pointer, length wrq->u.data.length).
 *
 *   iw_event layout (simplified):
 *     SIOCGIWAP    : BSSID (struct sockaddr)
 *     SIOCGIWESSID : SSID  (char array, length in u.essid.length)
 *     SIOCGIWFREQ  : frequency (struct iw_freq)
 *
 *   If the buffer is too small we return -E2BIG (caller re-allocates).
 *
 ****************************************************************************/

static int nrf7002_ioctl_get_scan(FAR struct nrf7002_priv *priv,
                                   FAR struct iwreq *wrq)
{
  FAR char                         *buf;
  FAR struct iw_event              *iwe;
  size_t                            buf_len;
  size_t                            written;
  size_t                            ssid_padded;
  int                               i;

  if (wrq == NULL)
    {
      return -EINVAL;
    }

  buf     = wrq->u.data.pointer;
  buf_len = wrq->u.data.length;

  if (buf == NULL || buf_len == 0)
    {
      /* Compute required buffer size (worst-case: all SSIDs at max length) */

      wrq->u.data.length = priv->scan_count *
                           (IW_EV_LEN(ap_addr) + IW_EV_LEN(qual) +
                            IW_EV_LEN(freq)    + IW_EV_LEN(data) +
                            IW_EV_LEN(essid)   + IW_ESSID_MAX_SIZE);
      return -E2BIG;
    }

  written = 0;

  for (i = 0; i < priv->scan_count; i++)
    {
      const struct nrf7002_scan_result *res = &priv->scan_results[i];

      /* ssid_padded: SSID data length rounded up to 4-byte boundary */

      ssid_padded = ((res->ssid_len + 3) & ~3u);

      /* --- SIOCGIWAP: BSSID --- */

      if (written + IW_EV_LEN(ap_addr) > buf_len)
        {
          return -E2BIG;
        }

      iwe = (FAR struct iw_event *)(buf + written);
      memset(iwe, 0, IW_EV_LEN(ap_addr));
      iwe->cmd = SIOCGIWAP;
      iwe->len = (uint16_t)IW_EV_LEN(ap_addr);
      iwe->u.ap_addr.sa_family = ARPHRD_ETHER;
      memcpy(iwe->u.ap_addr.sa_data, res->bssid, NRF7002_MAC_ADDR_LEN);
      written += IW_EV_LEN(ap_addr);

      /* --- SIOCGIWESSID: SSID (variable length, 4-byte aligned) ---
       *
       * Layout in stream: [iw_event header + essid union][SSID bytes...]
       * essid.pointer must be set to sizeof(iwe->u.essid) so the consumer
       * can locate the inline data (offset from start of iwe->u.essid).
       * iwe->len covers the fixed header plus the padded SSID payload.
       */

      if (written + IW_EV_LEN(essid) + ssid_padded > buf_len)
        {
          return -E2BIG;
        }

      iwe = (FAR struct iw_event *)(buf + written);
      memset(iwe, 0, IW_EV_LEN(essid) + ssid_padded);
      iwe->cmd              = SIOCGIWESSID;
      iwe->len              = (uint16_t)(IW_EV_LEN(essid) + ssid_padded);
      iwe->u.essid.flags    = 1;
      iwe->u.essid.length   = (uint16_t)res->ssid_len;
      iwe->u.essid.pointer  = (FAR void *)sizeof(iwe->u.essid);
      memcpy(&iwe->u.essid + 1, res->ssid, res->ssid_len);
      written += IW_EV_LEN(essid) + ssid_padded;

      /* --- IWEVQUAL: Signal quality --- */

      if (written + IW_EV_LEN(qual) > buf_len)
        {
          return -E2BIG;
        }

      iwe = (FAR struct iw_event *)(buf + written);
      memset(iwe, 0, IW_EV_LEN(qual));
      iwe->cmd                = IWEVQUAL;
      iwe->len                = (uint16_t)IW_EV_LEN(qual);
      iwe->u.qual.level       = (uint8_t)(res->rssi & 0xff);
      iwe->u.qual.updated     = IW_QUAL_DBM | IW_QUAL_ALL_UPDATED;
      written += IW_EV_LEN(qual);

      /* --- SIOCGIWFREQ: Channel frequency --- */

      if (written + IW_EV_LEN(freq) > buf_len)
        {
          return -E2BIG;
        }

      iwe = (FAR struct iw_event *)(buf + written);
      memset(iwe, 0, IW_EV_LEN(freq));
      iwe->cmd      = SIOCGIWFREQ;
      iwe->len      = (uint16_t)IW_EV_LEN(freq);
      iwe->u.freq.m = (int32_t)res->frequency;
      iwe->u.freq.e = 6; /* MHz: value * 10^6 → Hz */
      written += IW_EV_LEN(freq);

      /* --- SIOCGIWENCODE: Security / encryption mode --- */

      if (written + IW_EV_LEN(data) > buf_len)
        {
          return -E2BIG;
        }

      iwe = (FAR struct iw_event *)(buf + written);
      memset(iwe, 0, IW_EV_LEN(data));
      iwe->cmd          = SIOCGIWENCODE;
      iwe->len          = (uint16_t)IW_EV_LEN(data);
      iwe->u.data.flags = (res->security == NRF7002_SECURITY_OPEN)
                          ? IW_ENCODE_DISABLED
                          : (IW_ENCODE_ENABLED | IW_ENCODE_NOKEY);
      iwe->u.data.length = 0;
      written += IW_EV_LEN(data);
    }

  wrq->u.data.length = (uint16_t)written;
  return OK;
}

/****************************************************************************
 * Name: nrf7002_ioctl_connect
 *
 * Description:
 *   SIOCSIWAP — trigger a connection using the stored SSID and auth params.
 *
 *   802.11 connection sequence via NCS FMAC:
 *     1. nrf_wifi_sys_fmac_auth   (authentication request)
 *     2. nrf_wifi_sys_fmac_assoc  (association request)
 *
 *   The FMAC will call if_carr_state_chg_callbk_fn on success.
 *
 ****************************************************************************/

static void nrf7002_ioctl_connect(FAR void *arg)
{
  FAR struct nrf7002_priv        *priv = (FAR struct nrf7002_priv *)arg;
  struct nrf_wifi_umac_auth_info  auth_info;
  enum nrf_wifi_status            status;
  uint32_t                        ap_freq = 0;
  int                             i;
  bool                            bssid_zero;

  if (priv->fmac_dev_ctx == NULL)
    {
      syslog(LOG_ERR, "nrf7002: connect: no FMAC context\n");
      return;
    }

  if (priv->target_ssid_len == 0)
    {
      syslog(LOG_ERR, "nrf7002: connect: no SSID set\n");
      return;
    }

  /* Look up the target AP in the cached scan results to get the channel
   * frequency.  The RPU requires the frequency to be set in the auth
   * command; without it the auth frame is not transmitted on air.
   */

  bssid_zero = true;
  for (i = 0; i < NRF7002_MAC_ADDR_LEN; i++)
    {
      if (priv->target_bssid[i] != 0)
        {
          bssid_zero = false;
          break;
        }
    }

  /* First pass: exact BSSID match (when a specific AP was requested) */

  for (i = 0; i < priv->scan_count; i++)
    {
      const struct nrf7002_scan_result *r = &priv->scan_results[i];

      if (!bssid_zero &&
          memcmp(r->bssid, priv->target_bssid, NRF7002_MAC_ADDR_LEN) == 0)
        {
          ap_freq = r->frequency;
          break;
        }
    }

  /* Second pass: SSID match — used when:
   *  - target_bssid is all-zero (wapi ap wlan0 any), or
   *  - target_bssid is non-zero garbage (sscanf("any") failed) and did
   *    not match any cached BSSID.  Fall back to SSID lookup.
   */

  if (ap_freq == 0 && priv->target_ssid_len > 0)
    {
      for (i = 0; i < priv->scan_count; i++)
        {
          const struct nrf7002_scan_result *r = &priv->scan_results[i];

          if (strncmp(r->ssid, priv->target_ssid, NRF7002_MAX_SSID_LEN) == 0)
            {
              ap_freq = r->frequency;
              /* Store the real BSSID so the RPU targets this specific AP */
              memcpy(priv->target_bssid, r->bssid, NRF7002_MAC_ADDR_LEN);
              syslog(LOG_INFO, "nrf7002: SSID match: bssid=%02x:%02x:%02x:%02x:%02x:%02x\n",
                     r->bssid[0], r->bssid[1], r->bssid[2],
                     r->bssid[3], r->bssid[4], r->bssid[5]);
              break;
            }
        }
    }

  if (ap_freq == 0 && priv->target_freq != 0)
    {
      ap_freq = priv->target_freq;
      syslog(LOG_INFO, "nrf7002: connect: using user-set freq=%lu MHz\n",
             (unsigned long)ap_freq);
    }

  if (ap_freq == 0)
    {
      syslog(LOG_WARNING, "nrf7002: connect: AP '%s' not in scan cache,"
             " will do all-channel SCAN_CONNECT\n", priv->target_ssid);
    }
  else
    {
      syslog(LOG_INFO, "nrf7002: connect: AP '%s' freq=%lu MHz\n",
             priv->target_ssid, (unsigned long)ap_freq);
    }

  syslog(LOG_INFO, "nrf7002: connecting to '%s' freq=%lu MHz\n",
         priv->target_ssid, (unsigned long)ap_freq);

  uint16_t saved_capability      = 0;
  uint16_t saved_beacon_interval = 0;
  int32_t  saved_signal          = 0;
  uint64_t saved_tsf             = 0;

  /* Skip local deauth before first connect attempt.
   * The local-state-change deauth may clear the RPU's BSS database for the
   * target BSSID, causing CMD_AUTHENTICATE to return ENOENT.
   * Only deauth after a failed assoc (handled in auth retry loop).
   */

  /* --- SCAN_CONNECT + Auth + Assoc flow ---
   *
   * The nRF7002 UMAC firmware maintains an internal BSS database populated by
   * probe responses captured during SCAN_CONNECT (active probe scan).
   * CMD_AUTHENTICATE requires the target BSSID to be in this BSS database;
   * without it the firmware returns ENOENT (-2).
   *
   * CRITICAL: after SCAN_DONE for SCAN_CONNECT, do NOT call GET_SCAN_RESULTS.
   * GET_SCAN_RESULTS(SCAN_CONNECT) consumes the BSS database entries, causing
   * the subsequent auth to fail with ENOENT.  scan_done_cb returns immediately
   * for SCAN_CONNECT without calling GET_SCAN_RESULTS.
   */

#define NRF7002_AUTH_RETRIES   3
#define NRF7002_AUTH_TIMEOUT_S 8
#define NRF7002_ASSOC_TIMEOUT_S 10

  /* --- SCAN_CONNECT: active probe to populate RPU BSS database --- */

  {
    struct nrf_wifi_umac_scan_info *connect_scan;
    size_t alloc_sz = sizeof(*connect_scan) + sizeof(uint32_t);
    struct timespec sc_ts;
    int sc_ret;

    /* Drain stale scan_sem */

    while (nxsem_trywait(&priv->scan_sem) == OK)
      {
        /* drained */
      }

    connect_scan = kmm_zalloc(alloc_sz);
    if (connect_scan)
      {
        enum nrf_wifi_status sc_status;

        connect_scan->scan_reason = SCAN_CONNECT;
        connect_scan->scan_params.num_scan_ssids = 1;
        connect_scan->scan_params.scan_ssids[0].nrf_wifi_ssid_len =
            (unsigned char)priv->target_ssid_len;
        memcpy(connect_scan->scan_params.scan_ssids[0].nrf_wifi_ssid,
               priv->target_ssid, priv->target_ssid_len);

        if (ap_freq != 0)
          {
            connect_scan->scan_params.center_frequency[0] = ap_freq;
            connect_scan->scan_params.num_scan_channels   = 1;
          }

        priv->scan_count  = 0;
        priv->scan_done   = false;
        priv->scan_reason = SCAN_CONNECT;
        priv->state       = NRF7002_STATE_SCANNING;

        syslog(LOG_INFO, "nrf7002: SCAN_CONNECT for '%s' freq=%lu MHz\n",
               priv->target_ssid, (unsigned long)ap_freq);

        sc_status = nrf_wifi_sys_fmac_scan(priv->fmac_dev_ctx,
                                           priv->vif_idx,
                                           connect_scan);
        if (sc_status != NRF_WIFI_STATUS_SUCCESS)
          {
            syslog(LOG_WARNING, "nrf7002: SCAN_CONNECT failed (%d)\n",
                   (int)sc_status);
            priv->state = NRF7002_STATE_IDLE;
          }
        else
          {
            clock_gettime(CLOCK_REALTIME, &sc_ts);
            sc_ts.tv_sec += NRF7002_SCAN_TIMEOUT_MS / 1000;
            sc_ret = nxsem_timedwait(&priv->scan_sem, &sc_ts);
            if (sc_ret == -ETIMEDOUT || !priv->scan_done)
              {
                syslog(LOG_WARNING, "nrf7002: SCAN_CONNECT timeout/fail\n");
              }
            else
              {
                syslog(LOG_INFO, "nrf7002: SCAN_CONNECT done\n");
              }
          }

        kmm_free(connect_scan);
      }
    else
      {
        syslog(LOG_ERR, "nrf7002: SCAN_CONNECT alloc failed\n");
      }
  }

  /* After SCAN_CONNECT, re-do BSS lookup from the updated scan cache.
   * SCAN_CONNECT may overwrite scan_results[] with full BSS data.
   * If SCAN_CONNECT returned empty results, ap_freq from the pre-scan
   * display cache is still valid — keep it.
   */

  if (priv->scan_count > 1 ||
      (priv->scan_count == 1 && priv->scan_results[0].frequency != 0))
    {
      /* SCAN_CONNECT returned real results — re-lookup */

      uint32_t sc_freq = 0;

      bssid_zero = true;
      for (i = 0; i < NRF7002_MAC_ADDR_LEN; i++)
        {
          if (priv->target_bssid[i] != 0)
            {
              bssid_zero = false;
              break;
            }
        }

      for (i = 0; i < priv->scan_count; i++)
        {
          const struct nrf7002_scan_result *r = &priv->scan_results[i];

          if (!bssid_zero &&
              memcmp(r->bssid, priv->target_bssid, NRF7002_MAC_ADDR_LEN) == 0)
            {
              sc_freq = r->frequency;
              break;
            }
        }

      if (sc_freq == 0 && priv->target_ssid_len > 0)
        {
          for (i = 0; i < priv->scan_count; i++)
            {
              const struct nrf7002_scan_result *r = &priv->scan_results[i];

              if (strncmp(r->ssid, priv->target_ssid, NRF7002_MAX_SSID_LEN) == 0)
                {
                  sc_freq = r->frequency;
                  memcpy(priv->target_bssid, r->bssid, NRF7002_MAC_ADDR_LEN);
                  syslog(LOG_INFO,
                         "nrf7002: post-SCAN_CONNECT BSS:"
                         " bssid=%02x:%02x:%02x:%02x:%02x:%02x"
                         " freq=%lu\n",
                         r->bssid[0], r->bssid[1], r->bssid[2],
                         r->bssid[3], r->bssid[4], r->bssid[5],
                         (unsigned long)sc_freq);
                  break;
                }
            }
        }

      if (sc_freq != 0)
        {
          ap_freq = sc_freq;
        }
    }
  else
    {
      /* SCAN_CONNECT returned empty — keep ap_freq from display scan cache */

      syslog(LOG_INFO, "nrf7002: SCAN_CONNECT empty, using cached freq=%lu\n",
             (unsigned long)ap_freq);
    }

  /* Re-populate saved BSS context from updated scan cache */

  saved_capability      = 0;
  saved_beacon_interval = 0;
  saved_signal          = 0;
  saved_tsf             = 0;

  for (i = 0; i < priv->scan_count; i++)
    {
      const struct nrf7002_scan_result *r = &priv->scan_results[i];
      if (memcmp(r->bssid, priv->target_bssid, NRF7002_MAC_ADDR_LEN) == 0)
        {
          saved_capability      = r->capability;
          saved_beacon_interval = r->beacon_interval;
          saved_signal          = (int32_t)r->rssi;
          saved_tsf             = r->tsf;
          syslog(LOG_INFO,
                 "nrf7002: BSS context: cap=0x%04x bi=%u signal=%d tsf=%llu\n",
                 saved_capability, saved_beacon_interval,
                 (int)saved_signal, (unsigned long long)saved_tsf);
          break;
        }
    }

  if (ap_freq == 0)
    {
      syslog(LOG_ERR, "nrf7002: target AP '%s' not found after SCAN_CONNECT\n",
             priv->target_ssid);
      priv->state = NRF7002_STATE_IDLE;
      return;
    }

  priv->ap_freq = ap_freq;

  {
    int  auth_attempt;
    bool auth_ok = false;

    /* Drain leftover semaphore counts from any previous attempt */

    while (nxsem_trywait(&priv->auth_sem) == OK)
      {
        /* drained */
      }

    while (nxsem_trywait(&priv->assoc_sem) == OK)
      {
        /* drained */
      }

    for (auth_attempt = 0;
         auth_attempt < NRF7002_AUTH_RETRIES && !auth_ok;
         auth_attempt++)
      {
        struct timespec ts;
        int             ret;

        if (auth_attempt > 0)
          {
            syslog(LOG_INFO, "nrf7002: auth retry %d/%d\n",
                   auth_attempt + 1, NRF7002_AUTH_RETRIES);
            nxsig_usleep(500000); /* 500 ms back-off */
          }

        /* Build auth_info from SCAN_CONNECT cache */

        priv->ap_freq = ap_freq;
        priv->state   = NRF7002_STATE_AUTHENTICATING;

        memset(&auth_info, 0, sizeof(auth_info));

        auth_info.auth_type = NRF_WIFI_AUTHTYPE_OPEN_SYSTEM;

        memcpy(auth_info.nrf_wifi_bssid, priv->target_bssid,
               NRF7002_MAC_ADDR_LEN);

        auth_info.frequency = ap_freq;

        auth_info.ssid.nrf_wifi_ssid_len = (unsigned char)priv->target_ssid_len;
        memcpy(auth_info.ssid.nrf_wifi_ssid, priv->target_ssid,
               priv->target_ssid_len);

        /* For WPA2 networks, include a minimal RSN IE in the auth command.
         * This mirrors Zephyr/wpa_supplicant behaviour: when params->ie is
         * non-NULL the firmware uses the IE to populate its BSS database
         * (security context) instead of the cap/signal/tsf fields.
         * Without an IE, the firmware returns ENOENT for OPEN_SYSTEM auth
         * against WPA2 APs because it cannot identify the security context.
         *
         * RSN IE: WPA2-PSK (AES-CCMP) minimal form, 22 bytes:
         *   30 14 01 00 00 0f ac 04  01 00 00 0f ac 04  01 00 00 0f ac 02  00 00
         */

        /* Fill BSS context from display-scan cache.
         * Zephyr fills these fields from curr_bss (wpa_bss) which is
         * populated from GET_SCAN_RESULTS(SCAN_DISPLAY).  The from_beacon
         * field is hard-coded to 0 in Zephyr's wpa_supp_if.c.
         * No IE is included for standard WPA2-PSK OPEN_SYSTEM auth
         * (IE is only used for FT/SAE in wpa_supplicant).
         */

        auth_info.capability      = saved_capability;
        auth_info.beacon_interval = saved_beacon_interval;
        auth_info.nrf_wifi_signal = saved_signal;
        auth_info.tsf             = saved_tsf;
        auth_info.scan_width      = 0;
        auth_info.from_beacon     = 0; /* hardcoded 0 per Zephyr wpa_supp_if.c */

        syslog(LOG_INFO, "nrf7002: auth attempt %d:"
               " bssid=%02x:%02x:%02x:%02x:%02x:%02x"
               " freq=%lu cap=0x%04x bi=%u signal=%d tsf=%llu\n",
               auth_attempt + 1,
               auth_info.nrf_wifi_bssid[0], auth_info.nrf_wifi_bssid[1],
               auth_info.nrf_wifi_bssid[2], auth_info.nrf_wifi_bssid[3],
               auth_info.nrf_wifi_bssid[4], auth_info.nrf_wifi_bssid[5],
               (unsigned long)auth_info.frequency,
               (unsigned)auth_info.capability,
               (unsigned)auth_info.beacon_interval,
               (int)auth_info.nrf_wifi_signal,
               (unsigned long long)auth_info.tsf);

        /* Drain auth_sem before sending auth */

        while (nxsem_trywait(&priv->auth_sem) == OK)
          {
            /* drained */
          }

        priv->auth_failed = false;

        status = nrf_wifi_sys_fmac_auth(priv->fmac_dev_ctx,
                                        priv->vif_idx,
                                        &auth_info);
        if (status != NRF_WIFI_STATUS_SUCCESS)
          {
            syslog(LOG_ERR, "nrf7002: fmac_auth submit failed (%d),"
                   " retrying\n", (int)status);
            priv->state = NRF7002_STATE_IDLE;
            nxsig_usleep(200000);
            continue;
          }

        syslog(LOG_INFO, "nrf7002: auth request sent, waiting %ds\n",
               NRF7002_AUTH_TIMEOUT_S);

        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += NRF7002_AUTH_TIMEOUT_S;
        ret = nxsem_timedwait(&priv->auth_sem, &ts);

        if (ret == -ETIMEDOUT)
          {
            syslog(LOG_WARNING, "nrf7002: auth timeout attempt %d\n",
                   auth_attempt + 1);
            priv->state = NRF7002_STATE_IDLE;
          }
        else if (priv->auth_failed)
          {
            syslog(LOG_WARNING, "nrf7002: auth rejected attempt %d\n",
                   auth_attempt + 1);
            priv->state = NRF7002_STATE_IDLE;
          }
        else
          {
            /* Auth accepted.  Send association request from this LPWORK
             * thread so the large assoc_info struct lives here rather than
             * in the shallow HPWORK auth_resp_cb stack.
             */

            {
              struct nrf_wifi_umac_assoc_info assoc_info;
              enum nrf_wifi_status            fmac_st;

              memset(&assoc_info, 0, sizeof(assoc_info));

              assoc_info.ssid.nrf_wifi_ssid_len =
                (unsigned char)priv->target_ssid_len;
              memcpy(assoc_info.ssid.nrf_wifi_ssid, priv->target_ssid,
                     priv->target_ssid_len);

              memcpy(assoc_info.nrf_wifi_bssid, priv->target_bssid,
                     NRF7002_MAC_ADDR_LEN);

              assoc_info.center_frequency = priv->ap_freq;

              if (priv->security_type == NRF7002_SECURITY_WPA2)
                {
                  assoc_info.conn_type = NRF_WIFI_CONN_TYPE_SECURE;

                  /* RSN IE for WPA2-Personal CCMP/PSK, no PMF */

                  static const unsigned char rsn_ie[] =
                    {
                      0x30, 0x14,
                      0x01, 0x00,
                      0x00, 0x0f, 0xac, 0x04,
                      0x01, 0x00,
                      0x00, 0x0f, 0xac, 0x04,
                      0x01, 0x00,
                      0x00, 0x0f, 0xac, 0x02,
                      0x00, 0x00
                    };
                  assoc_info.wpa_ie.ie_len = (signed int)sizeof(rsn_ie);
                  memcpy(assoc_info.wpa_ie.ie, rsn_ie, sizeof(rsn_ie));
                  assoc_info.control_port = 1;
                }
              else
                {
                  assoc_info.conn_type    = NRF_WIFI_CONN_TYPE_OPEN;
                  assoc_info.control_port = 0;
                }

              priv->state = NRF7002_STATE_ASSOCIATING;

              /* Drain assoc_sem before sending */

              while (nxsem_trywait(&priv->assoc_sem) == OK)
                {
                  /* drained */
                }

              priv->assoc_failed = false;

              fmac_st = nrf_wifi_sys_fmac_assoc(priv->fmac_dev_ctx,
                                                 priv->vif_idx,
                                                 &assoc_info);
              if (fmac_st != NRF_WIFI_STATUS_SUCCESS)
                {
                  syslog(LOG_ERR,
                         "nrf7002: fmac_assoc failed (%d), attempt %d\n",
                         (int)fmac_st, auth_attempt + 1);
                  priv->state = NRF7002_STATE_IDLE;
                  continue;
                }

              syslog(LOG_INFO, "nrf7002: assoc request sent attempt %d,"
                     " waiting %ds\n",
                     auth_attempt + 1, NRF7002_ASSOC_TIMEOUT_S);
            }

            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += NRF7002_ASSOC_TIMEOUT_S;
            ret = nxsem_timedwait(&priv->assoc_sem, &ts);

            if (ret == -ETIMEDOUT)
              {
                syslog(LOG_WARNING, "nrf7002: assoc timeout attempt %d\n",
                       auth_attempt + 1);
                priv->state = NRF7002_STATE_IDLE;
              }
            else if (priv->assoc_failed)
              {
                syslog(LOG_WARNING, "nrf7002: assoc rejected attempt %d\n",
                       auth_attempt + 1);
                priv->state = NRF7002_STATE_IDLE;
              }
            else
              {
                syslog(LOG_INFO, "nrf7002: assoc OK attempt %d,"
                       " carrier UP\n", auth_attempt + 1);
                auth_ok = true;
              }
          }
      }

    if (!auth_ok)
      {
        syslog(LOG_ERR, "nrf7002: connect failed after %d attempts\n",
               NRF7002_AUTH_RETRIES);
        priv->state = NRF7002_STATE_IDLE;
        return;
      }
  }

  syslog(LOG_INFO, "nrf7002: connect_work completed OK\n");
}

#ifdef CONFIG_IEEE80211_NRF7002_AP_MODE

/****************************************************************************
 * Name: nrf7002_ap_start
 *
 * Description:
 *   Stub: start the SoftAP.
 *
 *   Calls nrf_wifi_sys_fmac_start_ap with a minimal AP configuration.
 *   This requires NRF70_SYSTEM_WITH_RAW_MODES (or similar) to be defined
 *   in the NCS build to enable the AP mode FMAC path.
 *
 ****************************************************************************/

static int nrf7002_ap_start(FAR struct nrf7002_priv *priv)
{
  struct nrf_wifi_umac_start_ap_info ap_info;
  enum nrf_wifi_status               status;

  if (priv->fmac_dev_ctx == NULL)
    {
      return -ENODEV;
    }

  memset(&ap_info, 0, sizeof(ap_info));

  /* Minimal SoftAP config using stored SSID.
   * Caller is expected to set SSID via SIOCSIWESSID before SIOCSIWMODE.
   */

  if (priv->target_ssid_len > 0)
    {
      ap_info.ssid.nrf_wifi_ssid_len = (unsigned char)priv->target_ssid_len;
      memcpy(ap_info.ssid.nrf_wifi_ssid, priv->target_ssid,
             priv->target_ssid_len);
    }

  status = nrf_wifi_sys_fmac_start_ap(priv->fmac_dev_ctx,
                                       priv->vif_idx,
                                       &ap_info);
  if (status != NRF_WIFI_STATUS_SUCCESS)
    {
      syslog(LOG_ERR, "nrf7002: start_ap failed (%d)\n", status);
      return -EIO;
    }

  syslog(LOG_INFO, "nrf7002: SoftAP started\n");
  return OK;
}

#endif /* CONFIG_IEEE80211_NRF7002_AP_MODE */

/****************************************************************************
 * Name: nrf7002_ioctl
 *
 * Description:
 *   Handle wireless extension IOCTLs.
 *
 *   SIOCSIWSCAN   — trigger RPU scan (blocks until done or timeout)
 *   SIOCGIWSCAN   — return cached scan results as iw_event stream
 *   SIOCSIWESSID  — store target SSID
 *   SIOCSIWAUTH   — store security parameters
 *   SIOCSIWAP     — trigger connection using stored SSID + auth
 *   SIOCSIWENCODE — store passphrase (WEP legacy — reused for WPA2 PSK)
 *   SIOCGIWSTATS  — return RSSI from last scan (Phase 3)
 *   SIOCSIWMODE   — set operation mode; IW_MODE_MASTER starts AP (Phase 3)
 *
 *   All other commands return -ENOTTY.
 *
 ****************************************************************************/

static int nrf7002_ioctl(FAR struct net_driver_s *dev,
                          int cmd, unsigned long arg)
{
  FAR struct nrf7002_priv *priv =
    (FAR struct nrf7002_priv *)dev->d_private;
  FAR struct iwreq        *wrq  = (FAR struct iwreq *)(uintptr_t)arg;
  int                      ret  = -ENOTTY;

  syslog(LOG_ERR, "nrf7002: ioctl cmd=0x%04x\n", cmd);

  switch (cmd)
    {
      /* ------------------------------------------------------------------ */
      /* Initiate a scan                                                       */
      /* ------------------------------------------------------------------ */

      case SIOCSIWSCAN:
        syslog(LOG_INFO, "nrf7002: SIOCSIWSCAN\n");
        ret = nrf7002_ioctl_scan(priv);
        break;

      /* ------------------------------------------------------------------ */
      /* SIOCSIWFREQ — store user-specified channel frequency                 */
      /* ------------------------------------------------------------------ */

      case SIOCSIWFREQ:
        if (wrq != NULL)
          {
            uint32_t freq_mhz = 0;

            syslog(LOG_INFO, "nrf7002: SIOCSIWFREQ m=%ld e=%d\n",
                   (long)wrq->u.freq.m, (int)wrq->u.freq.e);

            if (wrq->u.freq.e == 6)
              {
                freq_mhz = (uint32_t)(wrq->u.freq.m);       /* already MHz */
              }
            else if (wrq->u.freq.e == 0 && wrq->u.freq.m >= 1 &&
                     wrq->u.freq.m <= 200)
              {
                /* channel number — convert to MHz */
                if (wrq->u.freq.m <= 13)
                  freq_mhz = 2412 + (wrq->u.freq.m - 1) * 5;
                else if (wrq->u.freq.m == 14)
                  freq_mhz = 2484;
                else if (wrq->u.freq.m >= 36)
                  freq_mhz = 5000 + wrq->u.freq.m * 5;
              }
            else if (wrq->u.freq.e == 0 && wrq->u.freq.m > 200)
              {
                /* wapi passes MHz directly with e=0 when value > 200 */
                freq_mhz = (uint32_t)wrq->u.freq.m;
              }
            else if (wrq->u.freq.e >= 1)
              {
                /* value in Hz * 10^e — convert to MHz */
                uint64_t hz = (uint64_t)wrq->u.freq.m;
                int      e  = (int)wrq->u.freq.e;
                while (e-- > 0) hz *= 10;
                freq_mhz = (uint32_t)(hz / 1000000);
              }

            if (freq_mhz != 0)
              {
                priv->target_freq = freq_mhz;
                syslog(LOG_INFO, "nrf7002: SIOCSIWFREQ -> %lu MHz\n",
                       (unsigned long)freq_mhz);
              }
          }

        ret = OK;
        break;

      /* ------------------------------------------------------------------ */
      /* Retrieve cached scan results                                          */
      /* ------------------------------------------------------------------ */

      case SIOCGIWSCAN:
        syslog(LOG_INFO, "nrf7002: SIOCGIWSCAN (count=%d)\n",
               priv->scan_count);
        ret = nrf7002_ioctl_get_scan(priv, wrq);
        break;

      /* ------------------------------------------------------------------ */
      /* Store target SSID                                                     */
      /* ------------------------------------------------------------------ */

      case SIOCSIWESSID:
        if (wrq == NULL || wrq->u.essid.pointer == NULL)
          {
            ret = -EINVAL;
            break;
          }

        {
          size_t len = wrq->u.essid.length;

          if (len > NRF7002_MAX_SSID_LEN)
            {
              len = NRF7002_MAX_SSID_LEN;
            }

          memcpy(priv->target_ssid, wrq->u.essid.pointer, len);
          priv->target_ssid[len] = '\0';
          priv->target_ssid_len  = (int)len;

          syslog(LOG_INFO, "nrf7002: ESSID set to '%s'\n",
                 priv->target_ssid);

          /* Re-derive PMK if passphrase is already stored. */

          if (priv->pmk_valid && len > 0)
            {
              nrf7002_wpa_derive_pmk(priv->passphrase,
                                      (const uint8_t *)priv->target_ssid,
                                      (uint32_t)len,
                                      priv->pmk);
              priv->ptk_valid = 0;
              syslog(LOG_INFO, "nrf7002: PMK re-derived for new SSID\n");
            }

          ret = OK;
        }
        break;

      /* ------------------------------------------------------------------ */
      /* Store security type (open vs WPA2)                                   */
      /* ------------------------------------------------------------------ */

      case SIOCSIWAUTH:
        if (wrq == NULL)
          {
            ret = -EINVAL;
            break;
          }

        /* IW_AUTH_80211_AUTH_ALG: 0x1 = open, 0x2 = shared key */
        /* IW_AUTH_WPA_VERSION    : 0x0 = disabled, 0x2 = WPA2  */

        if (wrq->u.param.flags == IW_AUTH_WPA_VERSION)
          {
            priv->security_type =
              (wrq->u.param.value == IW_AUTH_WPA_VERSION_WPA2)
              ? NRF7002_SECURITY_WPA2
              : NRF7002_SECURITY_OPEN;

            syslog(LOG_INFO, "nrf7002: auth WPA version -> security=%d\n",
                   priv->security_type);
          }

        ret = OK;
        break;

      /* ------------------------------------------------------------------ */
      /* Store passphrase (reusing SIOCSIWENCODE for WPA PSK)                 */
      /* ------------------------------------------------------------------ */

      case SIOCSIWENCODE:
        if (wrq == NULL)
          {
            ret = -EINVAL;
            break;
          }

        if (wrq->u.encoding.pointer != NULL &&
            wrq->u.encoding.length > 0)
          {
            size_t psk_len = wrq->u.encoding.length;

            if (psk_len >= NRF7002_MAX_PASSPHRASE_LEN)
              {
                psk_len = NRF7002_MAX_PASSPHRASE_LEN - 1;
              }

            memcpy(priv->passphrase, wrq->u.encoding.pointer, psk_len);
            priv->passphrase[psk_len] = '\0';

            syslog(LOG_INFO, "nrf7002: passphrase stored (%zu bytes)\n",
                   psk_len);

            /* Pre-derive PMK if SSID is already known.
             * PBKDF2-SHA1(4096) is ~500ms on Cortex-M33; run it once here
             * during configuration rather than at handshake time.
             */

            if (priv->target_ssid_len > 0)
              {
                nrf7002_wpa_derive_pmk(priv->passphrase,
                                        (const uint8_t *)priv->target_ssid,
                                        (uint32_t)priv->target_ssid_len,
                                        priv->pmk);
                priv->pmk_valid  = 1;
                priv->ptk_valid  = 0;
                syslog(LOG_INFO, "nrf7002: PMK derived (ssid=%s)\n",
                       priv->target_ssid);
              }
          }

        ret = OK;
        break;

      /* ------------------------------------------------------------------ */
      /* SIOCSIWENCODEEXT — WPA2-PSK passphrase from wapi psk command        */
      /* ------------------------------------------------------------------ */

      case SIOCSIWENCODEEXT:
        if (wrq != NULL && wrq->u.encoding.pointer != NULL &&
            wrq->u.encoding.length >= (int)sizeof(struct iw_encode_ext))
          {
            const struct iw_encode_ext *ext =
              (const struct iw_encode_ext *)wrq->u.encoding.pointer;

            if (ext->key_len > 0)
              {
                size_t psk_len = ext->key_len;

                if (psk_len >= NRF7002_MAX_PASSPHRASE_LEN)
                  {
                    psk_len = NRF7002_MAX_PASSPHRASE_LEN - 1;
                  }

                memcpy(priv->passphrase, ext->key, psk_len);
                priv->passphrase[psk_len] = '\0';

                syslog(LOG_INFO,
                       "nrf7002: ENCODEEXT passphrase stored (%zu bytes)\n",
                       psk_len);

                if (priv->target_ssid_len > 0)
                  {
                    nrf7002_wpa_derive_pmk(priv->passphrase,
                                            (const uint8_t *)priv->target_ssid,
                                            (uint32_t)priv->target_ssid_len,
                                            priv->pmk);
                    priv->pmk_valid = 1;
                    priv->ptk_valid = 0;
                    syslog(LOG_INFO, "nrf7002: PMK derived (ssid=%s)\n",
                           priv->target_ssid);
                  }
              }
          }

        ret = OK;
        break;

      /* ------------------------------------------------------------------ */
      /* Connect (auth + assoc) using stored SSID/auth/passphrase             */
      /* ------------------------------------------------------------------ */

      case SIOCSIWAP:
        syslog(LOG_INFO, "nrf7002: SIOCSIWAP (connect async)\n");

        /* If a specific BSSID was given, store it */

        if (wrq != NULL &&
            wrq->u.ap_addr.sa_family == ARPHRD_ETHER)
          {
            memcpy(priv->target_bssid, wrq->u.ap_addr.sa_data,
                   NRF7002_MAC_ADDR_LEN);
          }

        /* Run connect in LPWORK so the IOCTL caller (NSH) is not blocked
         * during auth/assoc semaphore waits (which can take up to 15s).
         * nrf7002_ioctl_connect posts carrier-on via if_carr_state_chg_cb
         * when association succeeds.
         */

        work_cancel(LPWORK, &priv->connect_work);
        ret = work_queue(LPWORK, &priv->connect_work,
                         (worker_t)nrf7002_ioctl_connect, priv, 0);
        if (ret < 0)
          {
            syslog(LOG_ERR, "nrf7002: work_queue connect failed: %d\n", ret);
          }
        else
          {
            ret = OK;
          }

        break;

      /* ------------------------------------------------------------------ */
      /* Phase 3: Return link statistics (RSSI from last scan)                */
      /* ------------------------------------------------------------------ */

      case SIOCGIWSTATS:
        {
          FAR struct iw_statistics *stats;
          int                       i;

          if (wrq == NULL)
            {
              ret = -EINVAL;
              break;
            }

          stats = (FAR struct iw_statistics *)wrq->u.data.pointer;
          if (stats == NULL)
            {
              ret = -EINVAL;
              break;
            }

          memset(stats, 0, sizeof(*stats));

          /* Populate RSSI from last scan result matching the connected BSSID.
           * If not associated, return the stored last_rssi value.
           */

          if (priv->state == NRF7002_STATE_ASSOCIATED)
            {
              for (i = 0; i < priv->scan_count; i++)
                {
                  if (memcmp(priv->scan_results[i].bssid,
                             priv->target_bssid,
                             NRF7002_MAC_ADDR_LEN) == 0)
                    {
                      priv->last_rssi = priv->scan_results[i].rssi;
                      break;
                    }
                }
            }

          /* level field is uint8_t in iw_quality; map dBm to 0-255 range.
           * Convention: level = (uint8_t)(rssi + 256) for negative dBm.
           */

          stats->qual.level   = (uint8_t)((int)priv->last_rssi & 0xff);
          stats->qual.updated = IW_QUAL_LEVEL_UPDATED | IW_QUAL_DBM;

          syslog(LOG_DEBUG, "nrf7002: SIOCGIWSTATS rssi=%d\n",
                 priv->last_rssi);
          ret = OK;
        }
        break;

      /* ------------------------------------------------------------------ */
      /* Phase 3: Set operation mode (AP mode stub)                           */
      /* ------------------------------------------------------------------ */

      case SIOCSIWMODE:
        {
          if (wrq == NULL)
            {
              ret = -EINVAL;
              break;
            }

#ifdef CONFIG_IEEE80211_NRF7002_AP_MODE
          if (wrq->u.mode == IW_MODE_MASTER)
            {
              syslog(LOG_INFO, "nrf7002: SIOCSIWMODE -> AP mode\n");
              ret = nrf7002_ap_start(priv);
            }
          else
#endif
            {
              /* STA mode — always the default */

              syslog(LOG_INFO, "nrf7002: SIOCSIWMODE -> STA mode\n");
              ret = OK;
            }
        }
        break;

      default:
        break;
    }

  return ret;
}

#endif /* CONFIG_NETDEV_IOCTL */

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: nrf7002_netdev_register
 *
 * Description:
 *   Configure and register the NuttX net_driver_s for the nRF7002.
 *
 * Returned Value:
 *   OK on success; negated errno on failure.
 *
 ****************************************************************************/

int nrf7002_netdev_register(FAR struct nrf7002_priv *priv)
{
  FAR struct net_driver_s *dev = &priv->netdev;

  /* Populate net_driver_s */

  dev->d_private = priv;

  /* MAC address: use the OTP MAC read from the nRF7002 chip (set by
   * nrf7002_initialize before registering the netdev).  Fall back to a
   * locally-administered placeholder if OTP read failed (all zeros).
   */

  if (priv->mac_addr[0] | priv->mac_addr[1] | priv->mac_addr[2] |
      priv->mac_addr[3] | priv->mac_addr[4] | priv->mac_addr[5])
    {
      memcpy(dev->d_mac.ether.ether_addr_octet, priv->mac_addr,
             NRF7002_MAC_ADDR_LEN);
    }
  else
    {
      /* OTP MAC not available: use locally-administered placeholder */

      dev->d_mac.ether.ether_addr_octet[0] = 0x02;
      dev->d_mac.ether.ether_addr_octet[1] = 0x00;
      dev->d_mac.ether.ether_addr_octet[2] = 0x00;
      dev->d_mac.ether.ether_addr_octet[3] = 0x7a;  /* '7' */
      dev->d_mac.ether.ether_addr_octet[4] = 0x00;
      dev->d_mac.ether.ether_addr_octet[5] = 0x02;  /* '2' → "nrf7002" */
    }

  /* Pre-allocate the flat TX packet buffer.
   * devif_poll uses flat-buffer mode when dev->d_buf is non-NULL;
   * without this it falls into IOB mode which our TX path cannot handle.
   */

  priv->pktbuf = (FAR uint8_t *)g_nrf7002_pktbuf;
  dev->d_buf   = priv->pktbuf;

  /* MTU for 802.11 data frames */

  dev->d_pktsize = CONFIG_NET_ETH_PKTSIZE;

  /* Ops */

  dev->d_ifup    = nrf7002_ifup;
  dev->d_ifdown  = nrf7002_ifdown;
  dev->d_txavail = nrf7002_txnotify; /* Phase 3: TX notification callback */
#ifdef CONFIG_NETDEV_IOCTL
  dev->d_ioctl   = nrf7002_ioctl;
#endif

  /* Register with the network layer as a WLAN device */

  return netdev_register(dev, NET_LL_IEEE80211);
}
