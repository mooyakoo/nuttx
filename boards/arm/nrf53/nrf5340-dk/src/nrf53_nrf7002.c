/****************************************************************************
 * boards/arm/nrf53/nrf5340-dk/src/nrf53_nrf7002.c
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
 * Board-level bringup for the nRF7002 WiFi companion chip on the
 * nRF5340-DK / nRF7002-DK (PCA10143).
 *
 * GPIO assignments (from PCA10143 schematic):
 *   BUCKEN   — P0.12  output low→high: enable nRF7002 DCDC buck regulator
 *   IOVDD    — P0.31  output low→high: enable nRF7002 IO voltage rail
 *   HOSTIRQ  — P0.23  input:           nRF7002 interrupt to nRF5340
 *
 * Power-up sequence (from nRF7002 PS §4.2):
 *   1. Assert BUCKEN (P0.12 = 1) — wait ≥1 ms
 *   2. Assert IOVDD  (P0.31 = 1) — wait ≥1 ms
 *   3. Configure HOSTIRQ as input with interrupt
 *   4. Initialize QSPI, bind to nrf7002_priv.qspi_ctx.qspi_dev
 *   5. Call nrf7002_initialize()
 *
 * NOTE: P0.31 is shared with LED4 on the standard nRF5340-DK.
 *       The wifi_cpuapp/defconfig disables CONFIG_ARCH_LEDS to avoid
 *       the conflict.
 *
 * NOTE: CS pin conflict — nrf53_qspi.c defaults CSN to P0.18 which is the
 *       MX25 NOR Flash on the nRF5340-DK.  On the nRF7002-DK the nRF7002
 *       uses a separate CS pin.  Override NRF53_QSPI0_CSN_PIN in
 *       wifi_cpuapp/defconfig or patch nrf53_qspi.c to switch PSEL.CSN.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <errno.h>
#include <string.h>
#include <syslog.h>

#include <nuttx/arch.h>
#include <nuttx/spi/qspi.h>

#include "arm_internal.h"
#include "nrf53_gpio.h"
#include "nrf53_gpiote.h"
#include "nrf53_qspi.h"
#include "hardware/nrf53_qspi.h"
#include "hardware/nrf53_memorymap_cpuapp.h"

#include <arch/board/board.h>
#include "nrf5340-dk.h"

#include "nrf7002_driver.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/* Power-up timing delays (milliseconds).
 *
 * Per the nRF7002 Product Specification §4.2:
 *   - After asserting BUCKEN, wait at least 1 ms for the DCDC to stabilize.
 *   - After asserting IOVDD (IO voltage), wait at least 10 ms for the RPU
 *     internal ROM boot to complete before accessing the QSPI interface.
 *
 * Using conservatively larger values for robustness.
 */

#define NRF7002_BUCKEN_DELAY_MS   2   /* DCDC stabilization: 1 ms min */
#define NRF7002_IOVDD_DELAY_MS   15   /* RPU internal ROM boot: 10 ms min */

/****************************************************************************
 * Private Data
 ****************************************************************************/

/* HOSTIRQ work queue item for deferred interrupt processing.
 *
 * NOTE: the NuttX work queue (delay 0) is backed by a watchdog timer that
 * fires on a 10 ms system-tick boundary (non-tickless), so HOSTIRQ servicing
 * is batched at ~100/s.  A dedicated semaphore-woken thread was tried to
 * service every HOSTIRQ immediately; it removed the tick-gating (handler rate
 * tracked the ~280/s ISR rate and start_xmit busy went to 0) but did NOT
 * raise throughput — the ceiling is the RPU's single-frame TX completion rate
 * (~280/s), and the work queue's incidental batching actually let the RPU
 * accumulate slightly more completions per service.  Kept the simpler work
 * queue.  Breaking past ~3.3 Mbps needs true A-MPDU aggregation, not faster
 * event servicing.
 */

static struct work_s g_hostirq_work;

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name: nrf7002_hostirq_work
 *
 * Description:
 *   HPWORK item that calls the FMAC interrupt callback.
 *   Scheduled by nrf7002_hostirq_isr().
 *
 ****************************************************************************/

static void nrf7002_hostirq_work(FAR void *arg)
{
  FAR struct nrf7002_qspi_ctx *ctx = arg;

  /* No syslog here: this gates the entire RX/event path.  A 115200-baud
   * syslog write (~3 ms/line) would stall EAPOL M4 past the AP's 100 ms
   * M3-retransmit window.
   */

  if (ctx != NULL && ctx->intr_callbk_fn != NULL)
    {
      ctx->intr_callbk_fn(ctx->intr_callbk_data);
    }
}

/****************************************************************************
 * Name: nrf7002_hostirq_isr
 *
 * Description:
 *   GPIO interrupt handler for HOSTIRQ (P0.23, rising edge).
 *   Defers processing to HPWORK to keep the ISR short.
 *
 ****************************************************************************/

static int nrf7002_hostirq_isr(int irq, FAR void *context, FAR void *arg)
{
  FAR struct nrf7002_qspi_ctx *ctx = &g_nrf7002_priv.qspi_ctx;

  work_queue(HPWORK, &g_hostirq_work, nrf7002_hostirq_work, ctx, 0);

  return OK;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: nrf53_nrf7002_initialize
 *
 * Description:
 *   Board-level initialization for the nRF7002 WiFi chip:
 *   power-up GPIO sequence, QSPI init, driver init.
 *
 * Returned Value:
 *   OK on success; negated errno on failure.
 *
 ****************************************************************************/

int nrf53_nrf7002_initialize(void)
{
  int ret;

  syslog(LOG_INFO, "nrf7002: board init start\n");

  /* Step 1: Configure BUCKEN (P0.12) as output, initially low */

  nrf53_gpio_config(NRF7002_BUCKEN_PIN);

  /* Step 2: Assert BUCKEN — enable nRF7002 DCDC buck converter */

  nrf53_gpio_write(NRF7002_BUCKEN_PIN, true);
  up_mdelay(NRF7002_BUCKEN_DELAY_MS);
  syslog(LOG_DEBUG, "nrf7002: BUCKEN asserted\n");

  /* Step 3: Configure IOVDD (P0.31) as output, initially low */

  nrf53_gpio_config(NRF7002_IOVDD_PIN);

  /* Step 4: Assert IOVDD — enable nRF7002 IO voltage domain */

  nrf53_gpio_write(NRF7002_IOVDD_PIN, true);
  up_mdelay(NRF7002_IOVDD_DELAY_MS);
  syslog(LOG_DEBUG, "nrf7002: IOVDD asserted\n");

  /* Step 5: Configure HOSTIRQ (P0.23) as input and attach ISR.
   *
   * Note: GPIOTE must be enabled (CONFIG_NRF53_GPIOTE=y).
   * The interrupt fires on rising edge; the nRF7002 drives HOSTIRQ
   * high when a message is available in the RPU GRAM.
   */

  nrf53_gpio_config(NRF7002_HOSTIRQ_PIN);

  nrf53_gpiote_set_pin_event(NRF7002_HOSTIRQ_PIN,
                              nrf7002_hostirq_isr,
                              NULL);
  ret = OK;

  syslog(LOG_DEBUG, "nrf7002: HOSTIRQ registered\n");

  /* Step 6: Initialize the QSPI peripheral and obtain the bus handle.
   *
   * nrf53_qspi_initialize(0) returns the struct qspi_dev_s * for QSPI0.
   * Store it in the driver's qspi_ctx so that nrf7002_qspi_dev_add (called
   * by the FMAC inside nrf7002_initialize) can find it.
   *
   * TODO CS pin: On the nRF7002-DK the nRF7002 CS is separate from the
   * MX25 CS (P0.18).  Ensure NRF53_QSPI0_CSN_PIN is overridden in
   * wifi_cpuapp/defconfig to point to the nRF7002 CS pin.
   */

  g_nrf7002_priv.qspi_ctx.qspi_dev = nrf53_qspi_initialize(0);
  if (g_nrf7002_priv.qspi_ctx.qspi_dev == NULL)
    {
      syslog(LOG_ERR, "nrf7002: nrf53_qspi_initialize failed\n");
      ret = -ENODEV;
      goto err_irq;
    }

  /* Set QSPI clock to 24 MHz as required by the nRF7002 RPU.
   *
   * The nRF5340 QSPI defaults to 96 MHz (SCKFREQ=0) after nrf53_qspi_initialize.
   * The nRF7002 product specification requires ≤ 24 MHz for reliable register
   * access.  Running at 96 MHz causes the RPU SYSBUS reads to return garbage
   * values (the LMAC ready poll at 0xA4000018 never sees bit 0 set, so
   * nrf_wifi_hal_proc_reset fails with timeout → fw_load failure).
   *
   * Per NCS DTS: qspi-frequency = <24000000>.
   */

  {
    uint32_t actual = QSPI_SETFREQUENCY(g_nrf7002_priv.qspi_ctx.qspi_dev,
                                        24000000);
    syslog(LOG_INFO, "nrf7002: QSPI clock set to %lu Hz\n",
           (unsigned long)actual);
  }

  /* Set RDC4IO = 0xA0 in the nRF5340 QSPI IFTIMING register.
   *
   * RDC4IO configures the number of dummy cycles inserted by the nRF5340 QSPI
   * hardware when issuing READ4IO transactions.  Setting 0xA0 (bits 7:4 = 0xA
   * = 10 dummy cycles) matches the Zephyr nrf_wifi QSPI config in
   * ncs/zephyr/modules/nrf_wifi/bus/qspi_if.c (qspi_cfg->RDC4IO = 0xA0):
   *
   *   NRF_QSPI->IFTIMING |= qspi_cfg->RDC4IO;  // "10 Dummy Cycles for READ4"
   *
   * Without this, the nRF5340 QSPI hardware doesn't align its read window
   * correctly to the nRF7002 slave latency, causing reads of SYSBUS registers
   * to return 0x00000000 instead of the actual register values.
   *
   * NRF53_QSPI_BASE + NRF53_QSPI_IFTIMING_OFFSET = 0x5002B000 + 0x0640
   */

  {
    uint32_t iftiming = getreg32(NRF53_QSPI_BASE + NRF53_QSPI_IFTIMING_OFFSET);
    iftiming |= 0xA0;
    putreg32(iftiming, NRF53_QSPI_BASE + NRF53_QSPI_IFTIMING_OFFSET);
    syslog(LOG_INFO, "nrf7002: QSPI IFTIMING set to 0x%08lx (RDC4IO=0xA0)\n",
           (unsigned long)iftiming);
  }

  /* Enable Quad Enable (QE) bit in the nRF7002 RPU QSPI status register.
   *
   * The nRF7002 RPU powers up with its QSPI interface in single-line mode
   * (QE=0).  The nRF5340 QSPI controller is configured for Quad-I/O
   * (READ4IO / PP4IO).  Without QE set, Quad reads return garbage on the
   * data lines (observed value 0xaaaa8088 on all register reads).
   *
   * This mirrors the Zephyr qspi_nrfx_configure() flow in
   *   ncs/zephyr/modules/nrf_wifi/bus/qspi_if.c which:
   *   1. Reads SR via RDSR (opcode 0x05) — single-line CINSTR
   *   2. Sets bit 6 (QE) via WRSR (opcode 0x01) — single-line CINSTR
   *
   * After QE is set, READ4IO (0xEB) and PP4IO (0x38) work correctly.
   */

  {
    struct qspi_cmdinfo_s cmdinfo;
    uint8_t               sr = 0;

    /* Read SR via RDSR */

    memset(&cmdinfo, 0, sizeof(cmdinfo));
    cmdinfo.flags  = QSPICMD_READDATA;
    cmdinfo.cmd    = 0x05;          /* RDSR opcode */
    cmdinfo.buffer = &sr;
    cmdinfo.buflen = 1;

    ret = QSPI_COMMAND(g_nrf7002_priv.qspi_ctx.qspi_dev, &cmdinfo);
    if (ret < 0)
      {
        syslog(LOG_WARNING, "nrf7002: RDSR failed: %d, assuming QE=0\n",
               ret);
        sr = 0;
      }
    else
      {
        syslog(LOG_INFO, "nrf7002: RDSR = 0x%02x\n", sr);
      }

    /* Set bit 6 (QE) if not already set */

    if ((sr & (1 << 6)) == 0)
      {
        sr |= (1 << 6);

        memset(&cmdinfo, 0, sizeof(cmdinfo));
        cmdinfo.flags  = QSPICMD_WRITEDATA;
        cmdinfo.cmd    = 0x01;       /* WRSR opcode */
        cmdinfo.buffer = &sr;
        cmdinfo.buflen = 1;

        ret = QSPI_COMMAND(g_nrf7002_priv.qspi_ctx.qspi_dev, &cmdinfo);
        if (ret < 0)
          {
            syslog(LOG_WARNING, "nrf7002: WRSR (QE) failed: %d\n", ret);
          }
        else
          {
            syslog(LOG_INFO, "nrf7002: WRSR QE bit set (SR=0x%02x)\n", sr);
          }
      }
    else
      {
        syslog(LOG_INFO, "nrf7002: QE already set (SR=0x%02x)\n", sr);
      }
  }

  syslog(LOG_DEBUG, "nrf7002: QSPI initialized\n");

  /* Step 7: Initialize the nRF7002 driver (OSAL + FMAC + netdev) */

  ret = nrf7002_initialize();
  if (ret < 0)
    {
      syslog(LOG_ERR, "nrf7002: nrf7002_initialize failed: %d\n", ret);
      goto err_irq;
    }

  syslog(LOG_INFO, "nrf7002: board init done\n");
  return OK;

err_irq:
  nrf53_gpiote_set_pin_event(NRF7002_HOSTIRQ_PIN, NULL, NULL);

err_gpio:
  /* De-assert power rails on failure */

  nrf53_gpio_write(NRF7002_IOVDD_PIN, false);
  nrf53_gpio_write(NRF7002_BUCKEN_PIN, false);

  return ret;
}
