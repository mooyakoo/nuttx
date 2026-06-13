# ##############################################################################
# drivers/wireless/ieee80211/nrf7002/CMakeLists.txt
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements. See the NOTICE file distributed with this
# work for additional information regarding copyright ownership. The ASF
# licenses this file to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.
#
# ##############################################################################

if(CONFIG_IEEE80211_NRF7002)

  # NuttX OSAL shim and driver source files

  set(SRCS
      nrf7002_osal.c
      nrf7002_bus_qspi.c
      nrf7002_driver.c
      nrf7002_netdev.c
      nrf7002_wpa.c)

  # Vendored NCS nrf_wifi firmware-stack sources (OS-agnostic, BSD-3-Clause).
  # ncs_fmac_promisc.c is intentionally omitted (needs NRF70_PROMISC_DATA_RX).

  list(
    APPEND
    SRCS
    ncs_osal.c
    ncs_bal.c
    ncs_qspi.c
    ncs_hal_api_common.c
    ncs_hal_api.c
    ncs_hal_fw_patch_loader.c
    ncs_hal_interrupt.c
    ncs_hal_mem.c
    ncs_hal_reg.c
    ncs_hpqm.c
    ncs_pal.c
    ncs_fmac_api.c
    ncs_fmac_api_common.c
    ncs_fmac_cmd.c
    ncs_fmac_cmd_common.c
    ncs_fmac_event.c
    ncs_fmac_util.c
    ncs_fmac_peer.c
    ncs_fmac_vif.c
    ncs_fmac_ap.c
    ncs_rx.c
    ncs_tx.c
    ncs_list.c
    ncs_queue.c
    ncs_util.c)

  target_sources(drivers PRIVATE ${SRCS})

  set(NCS_WIFI ${CMAKE_CURRENT_SOURCE_DIR}/ncs)

  target_include_directories(
    drivers
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${NCS_WIFI}/os_if/inc
            ${NCS_WIFI}/fw_if/umac_if/inc
            ${NCS_WIFI}/fw_if/umac_if/inc/system
            ${NCS_WIFI}/fw_if/umac_if/inc/common
            ${NCS_WIFI}/fw_if/umac_if/inc/fw
            ${NCS_WIFI}/hw_if/hal/inc
            ${NCS_WIFI}/hw_if/hal/inc/common
            ${NCS_WIFI}/bus_if/bal/inc
            ${NCS_WIFI}/bus_if/bus/qspi/inc
            ${NCS_WIFI}/utils/inc)

  # NCS feature flags (must match the firmware stack's compile-time
  # expectations; kept in sync with Make.defs).

  target_compile_definitions(
    drivers
    PRIVATE NRF70_SYSTEM_MODE
            NRF70_STA_MODE
            NRF70_DATA_TX
            NRF70_UTIL
            NRF70_TCP_IP_CHECKSUM_OFFLOAD
            NRF70_RPU_EXTEND_TWT_SP
            NRF_WIFI_MGMT_BUFF_OFFLOAD
            NRF_WIFI_FEAT_KEEPALIVE
            NRF_WIFI_KEEPALIVE_PERIOD_S=60
            NRF_WIFI_AP_DEAD_DETECT_TIMEOUT=20
            NRF_WIFI_IFACE_MTU=1500
            NRF_WIFI_PS_INT_PS=0
            NRF_WIFI_RPU_RECOVERY
            NRF_WIFI_RPU_RECOVERY_PS_ACTIVE_TIMEOUT_MS=50000
            NRF_WIFI_DISPLAY_SCAN_BSS_LIMIT=150
            NRF_WIFI_RPU_MIN_TIME_TO_ENTER_SLEEP_MS=1000
            WIFI_NRF70_LOG_LEVEL=1
            NRF_WIFI_MAX_PS_POLL_FAIL_CNT=10
            NRF70_RPU_PS_IDLE_TIMEOUT_MS=10
            NRF70_RX_NUM_BUFS=4
            NRF70_MAX_TX_TOKENS=12
            NRF70_RX_MAX_DATA_SIZE=1600
            NRF70_MAX_TX_PENDING_QLEN=18
            NRF70_BAND_2G_LOWER_EDGE_BACKOFF_DSSS=0
            NRF70_BAND_2G_LOWER_EDGE_BACKOFF_HT=0
            NRF70_BAND_2G_LOWER_EDGE_BACKOFF_HE=0
            NRF70_BAND_2G_UPPER_EDGE_BACKOFF_DSSS=0
            NRF70_BAND_2G_UPPER_EDGE_BACKOFF_HT=0
            NRF70_BAND_2G_UPPER_EDGE_BACKOFF_HE=0
            NRF70_BAND_UNII_1_LOWER_EDGE_BACKOFF_HT=0
            NRF70_BAND_UNII_1_LOWER_EDGE_BACKOFF_HE=0
            NRF70_BAND_UNII_1_UPPER_EDGE_BACKOFF_HT=0
            NRF70_BAND_UNII_1_UPPER_EDGE_BACKOFF_HE=0
            NRF70_BAND_UNII_2A_LOWER_EDGE_BACKOFF_HT=0
            NRF70_BAND_UNII_2A_LOWER_EDGE_BACKOFF_HE=0
            NRF70_BAND_UNII_2A_UPPER_EDGE_BACKOFF_HT=0
            NRF70_BAND_UNII_2A_UPPER_EDGE_BACKOFF_HE=0
            NRF70_BAND_UNII_2C_LOWER_EDGE_BACKOFF_HT=0
            NRF70_BAND_UNII_2C_LOWER_EDGE_BACKOFF_HE=0
            NRF70_BAND_UNII_2C_UPPER_EDGE_BACKOFF_HT=0
            NRF70_BAND_UNII_2C_UPPER_EDGE_BACKOFF_HE=0
            NRF70_BAND_UNII_3_LOWER_EDGE_BACKOFF_HT=0
            NRF70_BAND_UNII_3_LOWER_EDGE_BACKOFF_HE=0
            NRF70_BAND_UNII_3_UPPER_EDGE_BACKOFF_HT=0
            NRF70_BAND_UNII_3_UPPER_EDGE_BACKOFF_HE=0
            NRF70_BAND_UNII_4_LOWER_EDGE_BACKOFF_HT=0
            NRF70_BAND_UNII_4_LOWER_EDGE_BACKOFF_HE=0
            NRF70_BAND_UNII_4_UPPER_EDGE_BACKOFF_HT=0
            NRF70_BAND_UNII_4_UPPER_EDGE_BACKOFF_HE=0
            NRF70_PCB_LOSS_2G=0
            NRF70_PCB_LOSS_5G_BAND1=0
            NRF70_PCB_LOSS_5G_BAND2=0
            NRF70_PCB_LOSS_5G_BAND3=0
            NRF70_ANT_GAIN_2G=0
            NRF70_ANT_GAIN_5G_BAND1=0
            NRF70_ANT_GAIN_5G_BAND2=0
            NRF70_ANT_GAIN_5G_BAND3=0)

endif() # CONFIG_IEEE80211_NRF7002
