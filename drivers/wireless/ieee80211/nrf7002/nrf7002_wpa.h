/****************************************************************************
 * drivers/wireless/ieee80211/nrf7002/nrf7002_wpa.h
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Minimal WPA2-PSK 4-way handshake for the nRF7002 driver.
 *
 ****************************************************************************/

#ifndef __DRIVERS_WIRELESS_IEEE80211_NRF7002_NRF7002_WPA_H
#define __DRIVERS_WIRELESS_IEEE80211_NRF7002_NRF7002_WPA_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <stdint.h>
#include <stdbool.h>

/****************************************************************************
 * Forward Declarations
 ****************************************************************************/

struct nrf7002_priv;

/****************************************************************************
 * Public Function Prototypes
 ****************************************************************************/

/****************************************************************************
 * Name: nrf7002_wpa_derive_pmk
 *
 * Description:
 *   Derive the 32-byte PMK from a passphrase and SSID using PBKDF2-SHA1
 *   (4096 iterations).  Result is stored in pmk[32].
 *
 ****************************************************************************/

void nrf7002_wpa_derive_pmk(const char *passphrase,
                             const uint8_t *ssid, uint32_t ssid_len,
                             uint8_t pmk[32]);

/****************************************************************************
 * Name: nrf7002_wpa_process_eapol
 *
 * Description:
 *   Parse and handle an incoming EAPOL frame for the WPA2-PSK 4-way
 *   handshake.  Called from nrf7002_rx_worker for ethertype 0x888E.
 *
 * Returns:
 *   true  if the frame was an EAPOL-Key frame (consumed)
 *   false if the frame should be passed to the network stack
 *
 ****************************************************************************/

bool nrf7002_wpa_process_eapol(struct nrf7002_priv *priv,
                                const uint8_t *frame, uint32_t len);

/****************************************************************************
 * Name: nrf7002_wpa_send_m2
 *
 * Description:
 *   Build and transmit EAPOL M2 (STA response to AP M1).
 *   Requires priv->ptk_valid == 1.
 *
 ****************************************************************************/

void nrf7002_wpa_send_m2(struct nrf7002_priv *priv);

/****************************************************************************
 * Name: nrf7002_wpa_send_m4
 *
 * Description:
 *   Build and transmit EAPOL M4 (confirms PTK/GTK installation).
 *
 ****************************************************************************/

void nrf7002_wpa_send_m4(struct nrf7002_priv *priv,
                          const uint8_t replay_cnt[8]);

#endif /* __DRIVERS_WIRELESS_IEEE80211_NRF7002_NRF7002_WPA_H */
