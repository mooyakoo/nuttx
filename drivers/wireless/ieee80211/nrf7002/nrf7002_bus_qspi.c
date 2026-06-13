/****************************************************************************
 * drivers/wireless/ieee80211/nrf7002/nrf7002_bus_qspi.c
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
 * QSPI bus adaptation layer for the nRF7002 WiFi chip.
 *
 * The nRF7002 is accessed over a Quad-SPI interface.  The NCS firmware
 * stack calls the qspi_* ops in nrf_wifi_osal_ops to transfer data; this
 * file implements those ops on top of NuttX's struct qspi_dev_s.
 *
 * Two address regions are distinguished (matching the Zephyr shim):
 *   addr < 0x0C0000  — RPU gram (high-latency read; use QSPIMEM_READ)
 *   addr >= 0x0C0000 — RPU peripheral registers (standard read)
 *
 * TODO (CS pin conflict):
 *   nrf53_qspi.c defaults CSN to P0.18, which is the MX25 Flash chip
 *   select on the nRF5340-DK.  On the nRF7002-DK (PCA10143) the nRF7002
 *   has its own CS pin.  Until a dual-CS mechanism is upstreamed, override
 *   NRF53_QSPI0_CSN_PIN in wifi_cpuapp/defconfig, or patch nrf53_qspi.c
 *   to switch PSEL.CSN before calling nrf53_qspi_initialize(0).
 *
 * Reference: NCS/zephyr/modules/nrf_wifi/os/shim.c
 *            NCS/modules/lib/nrf_wifi/bus_if/bus/qspi/
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>

#include <nuttx/arch.h>
#include <nuttx/kmalloc.h>
#include <nuttx/spi/qspi.h>
#include <nuttx/wqueue.h>

#include "osal_structs.h"
#include "host_rpu_common_if.h"
#include "host_rpu_data_if.h"
#include "nrf7002_bus_qspi.h"
#include "nrf7002_driver.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/* QSPI command opcodes used by the nRF7002 RPU.
 * These match the values in the NCS qspi_if implementation.
 */

#define NRF7002_QSPI_READ_CMD    0x0b   /* Fast Read (with dummy cycle) */
#define NRF7002_QSPI_WRITE_CMD   0x02   /* Page Program */

/* Address region boundaries (QSPI offset space after PAL translation).
 *
 * The nRF7002 RPU QSPI slave inserts latency words before the actual read
 * data for certain address regions.  This matches rpu_7002_memmap[] in
 * ncs/zephyr/modules/nrf_wifi/bus/rpu_hw_if.c:
 *
 *  Region        Offset range         Latency words
 *  SysBus        0x000000 - 0x008FFF  1
 *  ExtSysBus     0x009000 - 0x03FFFF  2
 *  PBus          0x040000 - 0x07FFFF  1
 *  PKTRAM        0x0C0000 - 0x0F0FFF  0 (normal read)
 *  GRAM          0x080000 - 0x092000  2
 *  (other ROM/RAM regions also have latency > 0)
 *
 * A "latency word" is a full 4-byte word inserted by the RPU slave before
 * the real data.  We must read (1 + latency) * 4 bytes and use the last 4.
 */

#define NRF7002_SYSBUS_START     0x000000ul
#define NRF7002_SYSBUS_END       0x008FFFul
#define NRF7002_EXTSYSBUS_START  0x009000ul
#define NRF7002_EXTSYSBUS_END    0x03FFFFul
#define NRF7002_PBUS_START       0x040000ul
#define NRF7002_PBUS_END         0x07FFFFul
#define NRF7002_GRAM_START       0x080000ul
#define NRF7002_GRAM_END         0x092000ul
#define NRF7002_PKTRAM_START     0x0C0000ul
#define NRF7002_PKTRAM_END       0x0F0FFFul

/* "hl_read" boundary: below PKTRAM start all reads have latency > 0 */

#define NRF7002_GRAM_BOUNDARY    0x0c0000ul

/* Maximum latency words: 2 (ExtSysBus / GRAM).
 * Read buffer size: (1 + MAX_LATENCY) * 4 = 12 bytes.
 */

#define NRF7002_MAX_LATENCY      2u
#define NRF7002_HL_BUFSZ         ((1u + NRF7002_MAX_LATENCY) * 4u)

/* Bit 23 address mask applied to every QSPI DMA transfer.
 *
 * The nRF7002 RPU QSPI slave requires bit 23 set on all addresses to select
 * "incremental address mode".  Without this bit every DMA read returns
 * 0x000xxxxx garbage (the RPU ignores/misroutes the access).
 *
 * This matches Zephyr's addrmask = 0x800000 in
 * ncs/zephyr/modules/nrf_wifi/bus/device.c qspi_defconfig().
 */

#define NRF7002_QSPI_ADDRMASK    0x800000ul

/* Round up to 4-byte alignment */

#define ALIGN4(x)  (((x) + 3u) & ~3u)

/* RPU power-management CINSTR opcodes (from NCS qspi_if.c / rpu_hw_if.c) */

#define NRF7002_WRSR2_OPCODE  0x3f   /* Write Status Register 2 (wake RPU) */
#define NRF7002_RDSR2_OPCODE  0x2f   /* Read Status Register 2 */
#define NRF7002_RDSR1_OPCODE  0x1f   /* Read Status Register 1 */

#define NRF7002_RPU_WAKEUP_NOW  (1 << 0)  /* WRSR2/RDSR2 bit: assert wake */
#define NRF7002_RPU_AWAKE_BIT   (1 << 1)  /* RDSR1 bit: RPU is awake/ready */

/* RPU clock-enable register offset (from NCS rpu_hw_if.c rpu_clks_on) */

#define NRF7002_RPU_CLKS_ADDR   0x048C20ul
#define NRF7002_RPU_CLKS_ON_VAL 0x00000100ul

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name: qspi_reg_read
 *
 * Description:
 *   Read 'buflen' bytes from 'addr' on the QSPI bus into 'buf'.
 *   The address length is always 3 bytes (24-bit) for nRF7002.
 ****************************************************************************/

static int qspi_reg_read(FAR struct qspi_dev_s *dev, unsigned long addr,
                          FAR void *buf, size_t buflen)
{
  struct qspi_meminfo_s meminfo;

  memset(&meminfo, 0, sizeof(meminfo));
  meminfo.flags   = QSPIMEM_READ | QSPIMEM_QUADIO;
  meminfo.cmd     = NRF7002_QSPI_READ_CMD;
  meminfo.addr    = (uint32_t)(addr | NRF7002_QSPI_ADDRMASK);
  meminfo.addrlen = 3;
  meminfo.buffer  = buf;
  meminfo.buflen  = (uint32_t)buflen;

  return QSPI_MEMORY(dev, &meminfo);
}

/****************************************************************************
 * Name: qspi_reg_write
 *
 * Description:
 *   Write 'buflen' bytes from 'buf' to 'addr' on the QSPI bus.
 ****************************************************************************/

static int qspi_reg_write(FAR struct qspi_dev_s *dev, unsigned long addr,
                           FAR const void *buf, size_t buflen)
{
  struct qspi_meminfo_s meminfo;

  memset(&meminfo, 0, sizeof(meminfo));
  meminfo.flags   = QSPIMEM_WRITE;
  meminfo.cmd     = NRF7002_QSPI_WRITE_CMD;
  meminfo.addr    = (uint32_t)(addr | NRF7002_QSPI_ADDRMASK);
  meminfo.addrlen = 3;
  meminfo.buffer  = (FAR void *)buf; /* cast away const for the vtable */
  meminfo.buflen  = (uint32_t)buflen;

  return QSPI_MEMORY(dev, &meminfo);
}

/****************************************************************************
 * Name: nrf7002_rpu_wakeup
 *
 * Description:
 *   Wake the nRF7002 RPU from sleep and enable its internal clocks.
 *
 *   This must be called once after QSPI is initialised, BEFORE any
 *   SYSBUS/PBUS register access.  Without it every DMA read returns
 *   0xaaaa8088 because the RPU QSPI slave is in sleep mode.
 *
 *   The sequence mirrors Zephyr rpu_enable() in
 *     ncs/zephyr/modules/nrf_wifi/bus/rpu_hw_if.c:
 *     1. WRSR2(0x3f, 0x01) — assert RPU_WAKEUP_NOW  (CINSTR, single-line)
 *     2. RDSR2(0x2f)       — verify RPU_WAKEUP_NOW bit is set
 *     3. RDSR1(0x1f) ×10  — poll RPU_AWAKE_BIT (bit 1)
 *     4. Write 0x100 → 0x048C20 — enable RPU internal clocks
 *
 * Input Parameters:
 *   dev - NuttX QSPI device handle
 *
 * Returned Value:
 *   OK on success; negated errno on failure.
 *
 ****************************************************************************/

static int nrf7002_rpu_wakeup(FAR struct qspi_dev_s *dev)
{
  struct qspi_cmdinfo_s cmdinfo;
  uint8_t               sr;
  int                   ret;
  int                   ii;

  /* Step 1: WRSR2(0x3f, 0x01) — wake RPU.
   * The Zephyr shim does this at 8 MHz (lowest frequency) for reliability.
   * We run at 24 MHz; the CINSTR path should still work.
   */

  sr = NRF7002_RPU_WAKEUP_NOW;

  memset(&cmdinfo, 0, sizeof(cmdinfo));
  cmdinfo.flags  = QSPICMD_WRITEDATA;
  cmdinfo.cmd    = NRF7002_WRSR2_OPCODE;
  cmdinfo.buffer = &sr;
  cmdinfo.buflen = 1;

  ret = QSPI_COMMAND(dev, &cmdinfo);
  if (ret < 0)
    {
      syslog(LOG_ERR, "nrf7002: WRSR2(wake) failed: %d\n", ret);
      return ret;
    }

  syslog(LOG_INFO, "nrf7002: WRSR2(0x3f, 0x01) sent\n");

  /* Step 2: RDSR2(0x2f) — verify RPU_WAKEUP_NOW bit was latched. */

  sr = 0;
  memset(&cmdinfo, 0, sizeof(cmdinfo));
  cmdinfo.flags  = QSPICMD_READDATA;
  cmdinfo.cmd    = NRF7002_RDSR2_OPCODE;
  cmdinfo.buffer = &sr;
  cmdinfo.buflen = 1;

  ret = QSPI_COMMAND(dev, &cmdinfo);
  if (ret < 0)
    {
      syslog(LOG_WARNING, "nrf7002: RDSR2 failed: %d (continuing)\n", ret);
    }
  else
    {
      syslog(LOG_INFO, "nrf7002: RDSR2 = 0x%02x (RPU_WAKEUP_NOW=%d)\n",
             sr, (int)(sr & NRF7002_RPU_WAKEUP_NOW));
    }

  /* Step 3: RDSR1(0x1f) — poll until RPU_AWAKE_BIT (bit 1) is set.
   * Poll up to 10 times with 1 ms delay (matches Zephyr qspi_if.c).
   */

  for (ii = 0; ii < 10; ii++)
    {
      sr = 0;
      memset(&cmdinfo, 0, sizeof(cmdinfo));
      cmdinfo.flags  = QSPICMD_READDATA;
      cmdinfo.cmd    = NRF7002_RDSR1_OPCODE;
      cmdinfo.buffer = &sr;
      cmdinfo.buflen = 1;

      ret = QSPI_COMMAND(dev, &cmdinfo);
      if (ret == 0 && (sr & NRF7002_RPU_AWAKE_BIT))
        {
          syslog(LOG_INFO,
                 "nrf7002: RPU awake after %d ms (RDSR1=0x%02x)\n",
                 ii, sr);
          break;
        }

      up_mdelay(1);
    }

  if (!(sr & NRF7002_RPU_AWAKE_BIT))
    {
      syslog(LOG_ERR,
             "nrf7002: RPU did not wake up (RDSR1=0x%02x after 10ms)\n",
             sr);
      return -ETIMEDOUT;
    }

  /* Step 4: Enable RPU internal clocks.
   * Write 0x100 to QSPI address 0x048C20 (UCCP clock-gate register).
   * Matches rpu_clks_on() in ncs/zephyr/modules/nrf_wifi/bus/rpu_hw_if.c.
   */

  {
    uint32_t clk_val = NRF7002_RPU_CLKS_ON_VAL;

    ret = qspi_reg_write(dev, NRF7002_RPU_CLKS_ADDR, &clk_val,
                         sizeof(clk_val));
    if (ret < 0)
      {
        syslog(LOG_ERR, "nrf7002: rpu_clks_on write failed: %d\n", ret);
        return ret;
      }

    syslog(LOG_INFO, "nrf7002: RPU clocks enabled\n");
  }

  return OK;
}

/****************************************************************************
 * Public Functions — QSPI register / bulk access
 ****************************************************************************/

/****************************************************************************
 * Name: nrf7002_qspi_read_reg32
 *
 * Description:
 *   Read a 32-bit register at RPU address 'addr'.
 ****************************************************************************/

unsigned int nrf7002_qspi_read_reg32(void *priv, unsigned long addr)
{
  struct nrf7002_qspi_ctx *ctx = priv;
  uint32_t                 val = 0;
  int                      ret;
  static int               read_count = 0;

  if (ctx == NULL || ctx->qspi_dev == NULL)
    {
      syslog(LOG_ERR, "nrf7002_qspi_read_reg32: NULL context\n");
      return 0;
    }

  ret = qspi_reg_read(ctx->qspi_dev, addr, &val, sizeof(val));
  if (ret < 0)
    {
      syslog(LOG_ERR, "nrf7002_qspi_read_reg32(0x%lx) failed: %d\n",
             addr, ret);
    }

  return (unsigned int)val;
}

/****************************************************************************
 * Name: nrf7002_qspi_write_reg32
 *
 * Description:
 *   Write a 32-bit value to RPU register at 'addr'.
 ****************************************************************************/

void nrf7002_qspi_write_reg32(void *priv, unsigned long addr,
                               unsigned int val)
{
  struct nrf7002_qspi_ctx *ctx = priv;
  uint32_t                 v   = (uint32_t)val;
  int                      ret;
  static int               write_count = 0;

  if (ctx == NULL || ctx->qspi_dev == NULL)
    {
      syslog(LOG_ERR, "nrf7002_qspi_write_reg32: NULL context\n");
      return;
    }


  ret = qspi_reg_write(ctx->qspi_dev, addr, &v, sizeof(v));
  if (ret < 0)
    {
      syslog(LOG_ERR, "nrf7002_qspi_write_reg32(0x%lx) failed: %d\n",
             addr, ret);
    }
}

/****************************************************************************
 * Name: nrf7002_qspi_cpy_from
 *
 * Description:
 *   Copy 'count' bytes from RPU address 'addr' into host buffer 'dest'.
 *   Transfer length is rounded up to a 4-byte multiple.
 ****************************************************************************/

void nrf7002_qspi_cpy_from(void *priv, void *dest, unsigned long addr,
                             size_t count)
{
  struct nrf7002_qspi_ctx *ctx  = priv;
  size_t                   full = count & ~(size_t)3;
  size_t                   rem  = count & (size_t)3;
  int                      ret;

  if (ctx == NULL || ctx->qspi_dev == NULL)
    {
      syslog(LOG_ERR, "nrf7002_qspi_cpy_from: NULL context\n");
      return;
    }

  /* The QSPI engine transfers in 4-byte units, but the caller buffer is only
   * guaranteed to hold `count` bytes (NCS allocates exact-size event storage,
   * hal_interrupt.c:261).  Reading ALIGN4(count) straight into `dest` writes
   * 1-3 bytes past the heap chunk and corrupts allocator metadata — observed
   * as an mm_free() assert under TCP RX (coalesced events of e.g. 134 bytes).
   * Read the aligned prefix directly, then read the final padded word into a
   * local bounce and copy only the remaining 1-3 bytes.
   */

  if (full > 0)
    {
      ret = qspi_reg_read(ctx->qspi_dev, addr, dest, full);
      if (ret < 0)
        {
          syslog(LOG_ERR, "nrf7002_qspi_cpy_from(0x%lx, %zu) failed: %d\n",
                 addr, count, ret);
          return;
        }
    }

  if (rem > 0)
    {
      uint32_t tail;

      ret = qspi_reg_read(ctx->qspi_dev, addr + full, &tail, sizeof(tail));
      if (ret < 0)
        {
          syslog(LOG_ERR, "nrf7002_qspi_cpy_from(0x%lx, %zu) tail failed: %d\n",
                 addr, count, ret);
          return;
        }

      memcpy((uint8_t *)dest + full, &tail, rem);
    }
}

/****************************************************************************
 * Name: nrf7002_qspi_cpy_to
 *
 * Description:
 *   Copy 'count' bytes from host buffer 'src' to RPU address 'addr'.
 *   Transfer length is rounded up to a 4-byte multiple.
 ****************************************************************************/

void nrf7002_qspi_cpy_to(void *priv, unsigned long addr, const void *src,
                           size_t count)
{
  struct nrf7002_qspi_ctx *ctx  = priv;
  size_t                   full = count & ~(size_t)3;
  size_t                   rem  = count & (size_t)3;
  int                      ret;

  if (ctx == NULL || ctx->qspi_dev == NULL)
    {
      syslog(LOG_ERR, "nrf7002_qspi_cpy_to: NULL context\n");
      return;
    }

  /* Symmetric to cpy_from: the QSPI engine writes in 4-byte units but `src`
   * only holds `count` bytes.  Writing ALIGN4(count) straight from `src`
   * reads 1-3 bytes past the caller buffer and leaks them to the RPU.  Write
   * the aligned prefix directly, then assemble the final word from the
   * remaining 1-3 bytes (zero-padded) via a local bounce.
   */

  if (full > 0)
    {
      ret = qspi_reg_write(ctx->qspi_dev, addr, src, full);
      if (ret < 0)
        {
          syslog(LOG_ERR, "nrf7002_qspi_cpy_to(0x%lx, %zu) failed: %d\n",
                 addr, count, ret);
          return;
        }
    }

  if (rem > 0)
    {
      uint32_t tail = 0;

      memcpy(&tail, (const uint8_t *)src + full, rem);
      ret = qspi_reg_write(ctx->qspi_dev, addr + full, &tail, sizeof(tail));
      if (ret < 0)
        {
          syslog(LOG_ERR, "nrf7002_qspi_cpy_to(0x%lx, %zu) tail failed: %d\n",
                 addr, count, ret);
        }
    }
}

/****************************************************************************
 * Public Functions — QSPI bus lifecycle
 ****************************************************************************/

/****************************************************************************
 * Name: nrf7002_qspi_bus_init
 *
 * Description:
 *   Return the QSPI context that lives inside g_nrf7002_priv.
 *
 *   The board-level code (nrf53_nrf7002.c) sets qspi_ctx.qspi_dev
 *   before calling nrf7002_initialize(), so by the time the FMAC
 *   calls this function the handle is already valid.  Returning the
 *   embedded context (rather than a fresh kmm_zalloc'd one) ensures
 *   that all subsequent QSPI register-access calls see the real bus
 *   handle instead of a NULL pointer.
 *
 *   Fix for Phase-1 bug: "QSPI NULL context" — the previous
 *   implementation allocated a separate struct that was never populated
 *   with qspi_dev, so every read/write silently returned 0 / was
 *   dropped.
 ****************************************************************************/

void *nrf7002_qspi_bus_init(void)
{
  struct nrf7002_qspi_ctx *ctx = &g_nrf7002_priv.qspi_ctx;

  if (ctx->qspi_dev == NULL)
    {
      syslog(LOG_ERR,
             "nrf7002_qspi_bus_init: qspi_dev is NULL — "
             "board init must set g_nrf7002_priv.qspi_ctx.qspi_dev "
             "before calling nrf7002_initialize()\n");
    }
  else
    {
      syslog(LOG_INFO, "nrf7002_qspi_bus_init: using existing qspi_ctx\n");
    }

  return ctx;
}

/****************************************************************************
 * Name: nrf7002_qspi_bus_deinit
 *
 * Description:
 *   The QSPI context is embedded in g_nrf7002_priv; nothing to free.
 ****************************************************************************/

void nrf7002_qspi_bus_deinit(void *os_qspi_priv)
{
  (void)os_qspi_priv;
  /* Context is part of g_nrf7002_priv — not heap-allocated, do not free */
}

/****************************************************************************
 * Name: nrf7002_qspi_dev_add
 *
 * Description:
 *   Bind the NuttX QSPI bus handle obtained from nrf53_qspi_initialize()
 *   to this context.  The caller (board-level nrf53_nrf7002.c) stores the
 *   handle inside nrf7002_priv before calling nrf7002_initialize(), so by
 *   the time FMAC calls bus_qspi_dev_add the handle is already set via
 *   nrf7002_qspi_set_dev().
 *
 * Note:
 *   osal_qspi_dev_ctx is the HAL's opaque device context; we just need to
 *   return a non-NULL pointer so the HAL knows the device was added.
 ****************************************************************************/

void *nrf7002_qspi_dev_add(void *qspi_priv, void *osal_qspi_dev_ctx)
{
  struct nrf7002_qspi_ctx *ctx = qspi_priv;
  int ret;

  (void)osal_qspi_dev_ctx;

  if (ctx == NULL)
    {
      syslog(LOG_ERR, "nrf7002_qspi_dev_add: NULL priv\n");
      return NULL;
    }

  if (ctx->qspi_dev == NULL)
    {
      syslog(LOG_ERR, "nrf7002_qspi_dev_add: qspi_dev not set\n");
      return NULL;
    }

  ctx->dev_added = true;
  syslog(LOG_INFO, "nrf7002: QSPI device added\n");

  /* Wake the RPU and enable its internal clocks.
   *
   * The nRF7002 RPU powers up in sleep mode.  All SYSBUS/PBUS register
   * accesses via DMA (READ4IO) return 0xaaaa8088 garbage until the RPU
   * is explicitly woken via WRSR2(0x3f, 0x01) and the internal UCCP
   * clocks are gated on.  This mirrors Zephyr's rpu_enable() sequence in
   * ncs/zephyr/modules/nrf_wifi/bus/rpu_hw_if.c.
   */

  ret = nrf7002_rpu_wakeup(ctx->qspi_dev);
  if (ret < 0)
    {
      syslog(LOG_ERR, "nrf7002_qspi_dev_add: RPU wakeup failed: %d\n",
             ret);
      ctx->dev_added = false;
      return NULL;
    }

  syslog(LOG_INFO, "nrf7002: RPU wakeup complete\n");
  return ctx;
}

/****************************************************************************
 * Name: nrf7002_qspi_dev_rem
 ****************************************************************************/

void nrf7002_qspi_dev_rem(void *os_qspi_dev_ctx)
{
  struct nrf7002_qspi_ctx *ctx = os_qspi_dev_ctx;

  if (ctx != NULL)
    {
      ctx->dev_added = false;
    }
}

/****************************************************************************
 * Name: nrf7002_qspi_dev_init
 *
 * Description:
 *   The NCS HAL calls this after dev_add.  On NuttX the QSPI peripheral
 *   was already configured by nrf53_qspi_initialize(); nothing extra needed.
 ****************************************************************************/

enum nrf_wifi_status nrf7002_qspi_dev_init(void *os_qspi_dev_ctx)
{
  (void)os_qspi_dev_ctx;
  return NRF_WIFI_STATUS_SUCCESS;
}

/****************************************************************************
 * Name: nrf7002_qspi_dev_deinit
 ****************************************************************************/

void nrf7002_qspi_dev_deinit(void *os_qspi_dev_ctx)
{
  (void)os_qspi_dev_ctx;
}

/****************************************************************************
 * Name: nrf7002_qspi_dev_intr_reg
 *
 * Description:
 *   Register the FMAC interrupt callback.  The actual GPIO interrupt on
 *   HOSTIRQ (P0.23) is set up by the board-level nrf53_nrf7002.c using
 *   nrf53_gpiote_register().  When the GPIO fires, the board code enqueues
 *   a HPWORK item that calls callbk_fn(callbk_data).
 *
 *   We store the callback here so the board ISR wrapper can retrieve it
 *   via nrf7002_qspi_get_intr_cb().
 ****************************************************************************/

enum nrf_wifi_status nrf7002_qspi_dev_intr_reg(void *os_qspi_dev_ctx,
                                                void *callbk_data,
                                                int (*callbk_fn)(
                                                  void *callbk_data))
{
  struct nrf7002_qspi_ctx *ctx = os_qspi_dev_ctx;

  if (ctx == NULL || callbk_fn == NULL)
    {
      return NRF_WIFI_STATUS_FAIL;
    }

  ctx->intr_callbk_data = callbk_data;
  ctx->intr_callbk_fn   = callbk_fn;

  syslog(LOG_INFO, "nrf7002: QSPI interrupt callback registered\n");

  return NRF_WIFI_STATUS_SUCCESS;
}

/****************************************************************************
 * Name: nrf7002_qspi_dev_intr_unreg
 ****************************************************************************/

void nrf7002_qspi_dev_intr_unreg(void *os_qspi_dev_ctx)
{
  struct nrf7002_qspi_ctx *ctx = os_qspi_dev_ctx;

  if (ctx != NULL)
    {
      ctx->intr_callbk_data = NULL;
      ctx->intr_callbk_fn   = NULL;
    }
}

/****************************************************************************
 * Name: nrf7002_qspi_dev_host_map_get
 *
 * Description:
 *   QSPI is not memory-mapped on nRF5340; report address 0.
 ****************************************************************************/

void nrf7002_qspi_dev_host_map_get(void *os_qspi_dev_ctx,
                                    struct nrf_wifi_osal_host_map *host_map)
{
  (void)os_qspi_dev_ctx;

  if (host_map != NULL)
    {
      host_map->addr = 0;
      host_map->size = 0;
    }
}
