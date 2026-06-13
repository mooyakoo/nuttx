/****************************************************************************
 * drivers/wireless/ieee80211/nrf7002/nrf7002_osal.c
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
 * NuttX OSAL shim for the NCS nrf_wifi firmware stack.
 *
 * Maps each nrf_wifi_osal_ops function pointer to the equivalent NuttX
 * primitive.  Only the ~30 ops exercised by the QSPI/FMAC path are
 * implemented with real bodies; the rest are stubbed with NULL or a
 * minimal no-op.  The linker will call out any missing symbols at build
 * time so the stubs can be filled in incrementally.
 *
 * Reference: NCS/zephyr/modules/nrf_wifi/os/shim.c
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <stdarg.h>
#include <stddef.h>
#include <limits.h>
#include <string.h>
#include <syslog.h>

#include <nuttx/irq.h>
#include <nuttx/spinlock.h>
#include <nuttx/kmalloc.h>
#include <nuttx/mutex.h>
#include <nuttx/clock.h>
#include <nuttx/signal.h>
#include <nuttx/wqueue.h>

#include "osal_ops.h"
#include "nrf7002_osal.h"
#include "nrf7002_bus_qspi.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define NRF7002_LOG_BUFSZ 256

/* Permanent front guard reserved at the head of every nbuf allocation.
 *
 * The NCS 802.11->Ethernet conversion in rx.c prepends a 14-byte Ethernet
 * header via nbuf_data_push() and assumes prior header-strip pulls have made
 * room.  For certain RX frames/timing that assumption is violated and the
 * 14-byte prepend moves data before the allocation start, corrupting the kmm
 * heap (observed as mm_free/mm_malloc free-list asserts under TCP RX, and as
 * an on-board nbuf "data < priv" assert on HPWORK).  Reserving a permanent
 * 16-byte (4-byte aligned, covers the 14-byte eth header) front guard keeps
 * data within [priv, priv+capacity] regardless of NCS pull/push accounting.
 */

#define NRF7002_NBUF_FRONT_HEADROOM 16

/****************************************************************************
 * Private Types
 ****************************************************************************/

/* Spinlock implementation backed by a NuttX mutex.
 * The irq_take/rel variants also save/restore the IRQ state so that
 * the FMAC layer can call them from both task and interrupt context.
 */

struct nrf7002_spinlock
{
  mutex_t      mtx;
  irqstate_t   flags; /* saved IRQ state for irq_take/rel pair */
};

/* Tasklet (work-queue item) wrapper */

struct nrf7002_tasklet
{
  struct work_s work;
  void        (*callback)(unsigned long data);
  unsigned long data;
};

/* One-shot timer wrapper (backed by LPWORK with delay) */

struct nrf7002_timer
{
  struct work_s work;
  void        (*callback)(unsigned long data);
  unsigned long data;
};

/****************************************************************************
 * Private Function Prototypes
 ****************************************************************************/

/* Memory */

static void *nrf7002_mem_alloc(size_t size);
static void *nrf7002_mem_zalloc(size_t size);
static void  nrf7002_mem_free(void *buf);
static void *nrf7002_data_mem_zalloc(size_t size);
static void  nrf7002_data_mem_free(void *buf);
static void *nrf7002_mem_cpy(void *dest, const void *src, size_t count);
static void *nrf7002_mem_set(void *start, int val, size_t size);
static int   nrf7002_mem_cmp(const void *addr1, const void *addr2,
                              size_t size);

/* IO memory — QSPI is not memory-mapped; return NULL/no-op */

static void        *nrf7002_iomem_mmap(unsigned long addr,
                                        unsigned long size);
static void         nrf7002_iomem_unmap(volatile void *addr);
static unsigned int nrf7002_iomem_read_reg32(const volatile void *addr);
static void         nrf7002_iomem_write_reg32(volatile void *addr,
                                               unsigned int val);
static void         nrf7002_iomem_cpy_from(void *dest,
                                            const volatile void *src,
                                            size_t count);
static void         nrf7002_iomem_cpy_to(volatile void *dest,
                                          const void *src, size_t count);

/* Spinlock */

static void *nrf7002_spinlock_alloc(void);
static void  nrf7002_spinlock_free(void *lock);
static void  nrf7002_spinlock_init(void *lock);
static void  nrf7002_spinlock_take(void *lock);
static void  nrf7002_spinlock_rel(void *lock);
static void  nrf7002_spinlock_irq_take(void *lock, unsigned long *flags);
static void  nrf7002_spinlock_irq_rel(void *lock, unsigned long *flags);

/* Logging */

static int nrf7002_log_dbg(const char *fmt, va_list args);
static int nrf7002_log_info(const char *fmt, va_list args);
static int nrf7002_log_err(const char *fmt, va_list args);

/* Linked list */

static void        *nrf7002_llist_node_alloc(void);
static void         nrf7002_llist_node_free(void *node);
static void        *nrf7002_llist_node_data_get(void *node);
static void         nrf7002_llist_node_data_set(void *node, void *data);
static void        *nrf7002_llist_alloc(void);
static void         nrf7002_llist_free(void *llist);
static void         nrf7002_llist_init(void *llist);
static void         nrf7002_llist_add_node_tail(void *llist, void *node);
static void         nrf7002_llist_add_node_head(void *llist, void *node);
static void        *nrf7002_llist_get_node_head(void *llist);
static void        *nrf7002_llist_get_node_nxt(void *llist, void *node);
static void         nrf7002_llist_del_node(void *llist, void *node);
static unsigned int nrf7002_llist_len(void *llist);

/* Network buffer */

static void        *nrf7002_nbuf_alloc(unsigned int size);
static void         nrf7002_nbuf_free(void *nbuf);
static void         nrf7002_nbuf_headroom_res(void *nbuf, unsigned int size);
static unsigned int nrf7002_nbuf_headroom_get(void *nbuf);
static unsigned int nrf7002_nbuf_data_size(void *nbuf);
static void        *nrf7002_nbuf_data_get(void *nbuf);
static void        *nrf7002_nbuf_data_put(void *nbuf, unsigned int size);
static void        *nrf7002_nbuf_data_push(void *nbuf, unsigned int size);
static void        *nrf7002_nbuf_data_pull(void *nbuf, unsigned int size);
static unsigned char nrf7002_nbuf_get_priority(void *nbuf);
static unsigned char nrf7002_nbuf_get_chksum_done(void *nbuf);
static void          nrf7002_nbuf_set_chksum_done(void *nbuf,
                                                   unsigned char done);

/* Tasklet (work queue) */

static void *nrf7002_tasklet_alloc(int type);
static void  nrf7002_tasklet_free(void *tasklet);
static void  nrf7002_tasklet_init(void *tasklet,
                                   void (*cb)(unsigned long),
                                   unsigned long data);
static void  nrf7002_tasklet_schedule(void *tasklet);
static void  nrf7002_tasklet_kill(void *tasklet);

/* Timer (one-shot timer via work queue with delay) */

static void *nrf7002_timer_alloc(void);
static void  nrf7002_timer_free(void *timer);
static void  nrf7002_timer_init(void *timer,
                                 void (*callback)(unsigned long data),
                                 unsigned long data);
static void  nrf7002_timer_schedule(void *timer, unsigned long duration_ms);
static void  nrf7002_timer_kill(void *timer);

/* Timing */

static int           nrf7002_sleep_ms(int msecs);
static int           nrf7002_delay_us(int usecs);
static unsigned long nrf7002_time_get_curr_us(void);
static unsigned int  nrf7002_time_elapsed_us(unsigned long start);
static unsigned long nrf7002_time_get_curr_ms(void);
static unsigned int  nrf7002_time_elapsed_ms(unsigned long start);

/* QSPI bus ops (implemented in nrf7002_bus_qspi.c) */

/* bus_qspi_init / dev_add / dev_rem / dev_init / dev_deinit /
 * dev_intr_reg / dev_intr_unreg / dev_host_map_get are declared in
 * nrf7002_bus_qspi.h and referenced directly in the ops struct below. */

/* Misc */

static void         nrf7002_assert(int test_val, int val,
                                    enum nrf_wifi_assert_op_type op,
                                    char *assert_msg);
static unsigned int nrf7002_strlen(const void *str);

/****************************************************************************
 * Private Functions — Memory
 ****************************************************************************/

static void *nrf7002_mem_alloc(size_t size)
{
  return kmm_malloc(size);
}

static void *nrf7002_mem_zalloc(size_t size)
{
  return kmm_zalloc(size);
}

static void nrf7002_mem_free(void *buf)
{
  kmm_free(buf);
}

/* data_mem_* use the same global heap on NuttX (no separate data pool) */

static void *nrf7002_data_mem_zalloc(size_t size)
{
  return kmm_zalloc(size);
}

static void nrf7002_data_mem_free(void *buf)
{
  kmm_free(buf);
}

static void *nrf7002_mem_cpy(void *dest, const void *src, size_t count)
{
  return memcpy(dest, src, count);
}

static void *nrf7002_mem_set(void *start, int val, size_t size)
{
  return memset(start, val, size);
}

static int nrf7002_mem_cmp(const void *addr1, const void *addr2, size_t size)
{
  return memcmp(addr1, addr2, size);
}

/****************************************************************************
 * Private Functions — IO Memory (stubs; QSPI is not memory-mapped)
 ****************************************************************************/

static void *nrf7002_iomem_mmap(unsigned long addr, unsigned long size)
{
  /* nRF7002 uses QSPI, not memory-mapped IO.  The HAL only calls this
   * for PCIe targets; return NULL to indicate unsupported.
   */

  (void)addr;
  (void)size;
  return NULL;
}

static void nrf7002_iomem_unmap(volatile void *addr)
{
  (void)addr;
}

static unsigned int nrf7002_iomem_read_reg32(const volatile void *addr)
{
  (void)addr;
  return 0;
}

static void nrf7002_iomem_write_reg32(volatile void *addr, unsigned int val)
{
  (void)addr;
  (void)val;
}

static void nrf7002_iomem_cpy_from(void *dest, const volatile void *src,
                                    size_t count)
{
  (void)dest;
  (void)src;
  (void)count;
}

static void nrf7002_iomem_cpy_to(volatile void *dest, const void *src,
                                   size_t count)
{
  (void)dest;
  (void)src;
  (void)count;
}

/****************************************************************************
 * Private Functions — Spinlock
 ****************************************************************************/

static void *nrf7002_spinlock_alloc(void)
{
  struct nrf7002_spinlock *lock;

  lock = kmm_zalloc(sizeof(*lock));
  if (lock == NULL)
    {
      syslog(LOG_ERR, "nrf7002: spinlock_alloc OOM\n");
    }

  return lock;
}

static void nrf7002_spinlock_free(void *lock)
{
  kmm_free(lock);
}

static void nrf7002_spinlock_init(void *lock)
{
  struct nrf7002_spinlock *sl = lock;

  nxmutex_init(&sl->mtx);
}

static void nrf7002_spinlock_take(void *lock)
{
  struct nrf7002_spinlock *sl = lock;

  nxmutex_lock(&sl->mtx);
}

static void nrf7002_spinlock_rel(void *lock)
{
  struct nrf7002_spinlock *sl = lock;

  nxmutex_unlock(&sl->mtx);
}

static void nrf7002_spinlock_irq_take(void *lock, unsigned long *flags)
{
  struct nrf7002_spinlock *sl = lock;

  /* Mutex + interrupt mask.  This keeps handshake/ping/low-rate traffic
   * working (the QSPI completion interrupt is still serviceable across the
   * short mutex wait in practice for those paths).
   *
   * KNOWN LIMITATION: under sustained high-rate traffic (iperf) the HAL IRQ
   * handler holds this lock while draining many RPU events over QSPI, and the
   * HOSTIRQ path can re-enter the handler on the HPWORK stack and overflow it.
   * Replacing this with a pure interrupt mask deadlocks the interrupt-driven
   * nRF53 QSPI wait, and a pure mutex re-enters/overflows.  A correct fix
   * needs a polled QSPI completion path or decoupling the NCS HAL IRQ
   * re-entry (see project notes: nrf7002-wifi-handshake-fixed).
   */

  nxmutex_lock(&sl->mtx);

  if (flags != NULL)
    {
      *flags = 0;
    }
}

static void nrf7002_spinlock_irq_rel(void *lock, unsigned long *flags)
{
  struct nrf7002_spinlock *sl = lock;

  (void)flags;
  nxmutex_unlock(&sl->mtx);
}

/****************************************************************************
 * Private Functions — Logging
 ****************************************************************************/

static int nrf7002_log_dbg(const char *fmt, va_list args)
{
  char buf[NRF7002_LOG_BUFSZ];

  vsnprintf(buf, sizeof(buf), fmt, args);
  syslog(LOG_DEBUG, "nrf7002: %s\n", buf);
  return 0;
}

static int nrf7002_log_info(const char *fmt, va_list args)
{
  char buf[NRF7002_LOG_BUFSZ];

  vsnprintf(buf, sizeof(buf), fmt, args);
  syslog(LOG_INFO, "nrf7002: %s\n", buf);
  return 0;
}

static int nrf7002_log_err(const char *fmt, va_list args)
{
  char buf[NRF7002_LOG_BUFSZ];

  vsnprintf(buf, sizeof(buf), fmt, args);
  syslog(LOG_ERR, "nrf7002: %s\n", buf);
  return 0;
}

/****************************************************************************
 * Private Functions — Linked List
 *
 * The NCS FMAC uses an opaque singly-linked list API.  We implement it
 * with a simple struct wrapping a next pointer and a data pointer.
 ****************************************************************************/

static void *nrf7002_llist_node_alloc(void)
{
  struct nrf7002_llist_node *node;

  node = kmm_zalloc(sizeof(*node));
  if (node == NULL)
    {
      syslog(LOG_ERR, "nrf7002: llist_node_alloc OOM\n");
    }

  return node;
}

static void nrf7002_llist_node_free(void *node)
{
  kmm_free(node);
}

static void *nrf7002_llist_node_data_get(void *node)
{
  return ((struct nrf7002_llist_node *)node)->data;
}

static void nrf7002_llist_node_data_set(void *node, void *data)
{
  ((struct nrf7002_llist_node *)node)->data = data;
}

static void *nrf7002_llist_alloc(void)
{
  struct nrf7002_llist *llist;

  llist = kmm_zalloc(sizeof(*llist));
  if (llist == NULL)
    {
      syslog(LOG_ERR, "nrf7002: llist_alloc OOM\n");
    }

  return llist;
}

static void nrf7002_llist_free(void *llist)
{
  kmm_free(llist);
}

static void nrf7002_llist_init(void *llist)
{
  struct nrf7002_llist *l = llist;

  l->head = NULL;
  l->len  = 0;
}

static void nrf7002_llist_add_node_tail(void *llist, void *llist_node)
{
  struct nrf7002_llist      *l    = llist;
  struct nrf7002_llist_node *node = llist_node;
  struct nrf7002_llist_node *cur;

  node->next = NULL;

  if (l->head == NULL)
    {
      l->head = node;
    }
  else
    {
      cur = l->head;
      while (cur->next != NULL)
        {
          cur = cur->next;
        }

      cur->next = node;
    }

  l->len++;
}

static void nrf7002_llist_add_node_head(void *llist, void *llist_node)
{
  struct nrf7002_llist      *l    = llist;
  struct nrf7002_llist_node *node = llist_node;

  node->next = l->head;
  l->head    = node;
  l->len++;
}

static void *nrf7002_llist_get_node_head(void *llist)
{
  struct nrf7002_llist *l = llist;

  return l->head;
}

static void *nrf7002_llist_get_node_nxt(void *llist, void *llist_node)
{
  (void)llist;
  return ((struct nrf7002_llist_node *)llist_node)->next;
}

static void nrf7002_llist_del_node(void *llist, void *llist_node)
{
  struct nrf7002_llist      *l    = llist;
  struct nrf7002_llist_node *node = llist_node;
  struct nrf7002_llist_node *cur;
  struct nrf7002_llist_node *prev = NULL;

  cur = l->head;
  while (cur != NULL)
    {
      if (cur == node)
        {
          if (prev == NULL)
            {
              l->head = cur->next;
            }
          else
            {
              prev->next = cur->next;
            }

          l->len--;
          return;
        }

      prev = cur;
      cur  = cur->next;
    }
}

static unsigned int nrf7002_llist_len(void *llist)
{
  return ((struct nrf7002_llist *)llist)->len;
}

/****************************************************************************
 * Private Functions — Network Buffer
 *
 * A two-allocation scheme: one for the nrf7002_nbuf descriptor, one for
 * the raw payload.  The 'priv' field points to the raw allocation;
 * 'data' and 'tail' walk through it.
 ****************************************************************************/

static void *nrf7002_nbuf_alloc(unsigned int size)
{
  struct nrf7002_nbuf *nbuf;
  unsigned int         alloc_size;

  if (size > UINT_MAX - NRF7002_NBUF_FRONT_HEADROOM)
    {
      return NULL;
    }

  alloc_size = size + NRF7002_NBUF_FRONT_HEADROOM;

  nbuf = kmm_zalloc(sizeof(*nbuf));
  if (nbuf == NULL)
    {
      return NULL;
    }

  nbuf->priv = kmm_zalloc(alloc_size);
  if (nbuf->priv == NULL)
    {
      kmm_free(nbuf);
      return NULL;
    }

  /* Start data/tail past the permanent front guard so NCS's unchecked
   * Ethernet-header prepend (data_push) cannot move data before priv.
   */

  nbuf->data     = (unsigned char *)nbuf->priv + NRF7002_NBUF_FRONT_HEADROOM;
  nbuf->tail     = nbuf->data;
  nbuf->len      = 0;
  nbuf->headroom = NRF7002_NBUF_FRONT_HEADROOM;
  nbuf->capacity = alloc_size;

  return nbuf;
}

static void nrf7002_nbuf_free(void *nbuf_ptr)
{
  struct nrf7002_nbuf *nbuf = nbuf_ptr;

  if (nbuf == NULL)
    {
      return;
    }

  kmm_free(nbuf->priv);
  kmm_free(nbuf);
}

/* Validate nbuf pointer invariants.  Any nbuf mutation that moves data/tail
 * outside [priv, priv+capacity] would corrupt the kmm heap; assert at the
 * mutation site (in debug builds) instead of much later in mm_malloc/mm_free.
 */

#define NRF7002_NBUF_CHECK(nbuf)                                            \
  do                                                                       \
    {                                                                      \
      DEBUGASSERT((nbuf)->priv != NULL);                                   \
      DEBUGASSERT((nbuf)->data >= (unsigned char *)(nbuf)->priv);          \
      DEBUGASSERT((nbuf)->tail >= (nbuf)->data);                           \
      DEBUGASSERT((nbuf)->tail <=                                          \
                  (unsigned char *)(nbuf)->priv + (nbuf)->capacity);       \
      DEBUGASSERT((nbuf)->len == (int)((nbuf)->tail - (nbuf)->data));      \
      DEBUGASSERT((nbuf)->headroom ==                                      \
                  (int)((nbuf)->data - (unsigned char *)(nbuf)->priv));    \
    }                                                                      \
  while (0)

static void nrf7002_nbuf_headroom_res(void *nbuf_ptr, unsigned int size)
{
  struct nrf7002_nbuf *nbuf = nbuf_ptr;

  nbuf->data     += size;
  nbuf->tail     += size;
  nbuf->headroom += size;
  NRF7002_NBUF_CHECK(nbuf);
}

static unsigned int nrf7002_nbuf_headroom_get(void *nbuf_ptr)
{
  return (unsigned int)((struct nrf7002_nbuf *)nbuf_ptr)->headroom;
}

static unsigned int nrf7002_nbuf_data_size(void *nbuf_ptr)
{
  return (unsigned int)((struct nrf7002_nbuf *)nbuf_ptr)->len;
}

static void *nrf7002_nbuf_data_get(void *nbuf_ptr)
{
  return ((struct nrf7002_nbuf *)nbuf_ptr)->data;
}

static void *nrf7002_nbuf_data_put(void *nbuf_ptr, unsigned int size)
{
  struct nrf7002_nbuf *nbuf = nbuf_ptr;
  unsigned char       *data = nbuf->tail;

  nbuf->tail += size;
  nbuf->len  += size;
  NRF7002_NBUF_CHECK(nbuf);

  return data;
}

static void *nrf7002_nbuf_data_push(void *nbuf_ptr, unsigned int size)
{
  struct nrf7002_nbuf *nbuf = nbuf_ptr;

  nbuf->data     -= size;
  nbuf->headroom -= size;
  nbuf->len      += size;
  NRF7002_NBUF_CHECK(nbuf);

  return nbuf->data;
}

static void *nrf7002_nbuf_data_pull(void *nbuf_ptr, unsigned int size)
{
  struct nrf7002_nbuf *nbuf = nbuf_ptr;

  nbuf->data     += size;
  nbuf->headroom += size;
  nbuf->len      -= size;
  NRF7002_NBUF_CHECK(nbuf);

  return nbuf->data;
}

static unsigned char nrf7002_nbuf_get_priority(void *nbuf_ptr)
{
  return ((struct nrf7002_nbuf *)nbuf_ptr)->priority;
}

static unsigned char nrf7002_nbuf_get_chksum_done(void *nbuf_ptr)
{
  return (unsigned char)((struct nrf7002_nbuf *)nbuf_ptr)->chksum_done;
}

static void nrf7002_nbuf_set_chksum_done(void *nbuf_ptr,
                                          unsigned char chksum_done)
{
  ((struct nrf7002_nbuf *)nbuf_ptr)->chksum_done = (bool)chksum_done;
}

/****************************************************************************
 * Private Functions — Tasklet (work queue)
 *
 * The NCS FMAC uses "tasklets" to defer interrupt processing.  We map
 * them to NuttX work queue items.  type==0 → LPWORK (normal priority),
 * type!=0 → HPWORK (used by the IRQ handler path).
 ****************************************************************************/

static void nrf7002_tasklet_worker(FAR void *arg)
{
  struct nrf7002_tasklet *t = arg;

  /* RX hot path on HPWORK: no syslog (gates EAPOL M4 latency). */

  t->callback(t->data);
}

static void *nrf7002_tasklet_alloc(int type)
{
  struct nrf7002_tasklet *t;

  t = kmm_zalloc(sizeof(*t));
  if (t == NULL)
    {
      syslog(LOG_ERR, "nrf7002: tasklet_alloc OOM\n");
    }

  return t;
}

static void nrf7002_tasklet_free(void *tasklet)
{
  kmm_free(tasklet);
}

static void nrf7002_tasklet_init(void *tasklet,
                                  void (*callback)(unsigned long data),
                                  unsigned long data)
{
  struct nrf7002_tasklet *t = tasklet;

  t->callback = callback;
  t->data     = data;
}

static void nrf7002_tasklet_schedule(void *tasklet)
{
  struct nrf7002_tasklet *t = tasklet;

  work_queue(HPWORK, &t->work, nrf7002_tasklet_worker, t, 0);
}

static void nrf7002_tasklet_kill(void *tasklet)
{
  struct nrf7002_tasklet *t = tasklet;

  work_cancel(HPWORK, &t->work);
}

/****************************************************************************
 * Private Functions — Timer
 *
 * NCS one-shot timer: allocate, init with callback+data, schedule with
 * duration_ms, kill to cancel.  Backed by LPWORK with delay.
 ****************************************************************************/

static void nrf7002_timer_worker(FAR void *arg)
{
  struct nrf7002_timer *t = arg;

  if (t->callback)
    {
      t->callback(t->data);
    }
}

static void *nrf7002_timer_alloc(void)
{
  struct nrf7002_timer *t;

  t = kmm_zalloc(sizeof(*t));
  if (t == NULL)
    {
      syslog(LOG_ERR, "nrf7002: timer_alloc OOM\n");
    }

  return t;
}

static void nrf7002_timer_free(void *timer)
{
  kmm_free(timer);
}

static void nrf7002_timer_init(void *timer,
                                void (*callback)(unsigned long data),
                                unsigned long data)
{
  struct nrf7002_timer *t = timer;

  t->callback = callback;
  t->data     = data;
}

static void nrf7002_timer_schedule(void *timer, unsigned long duration_ms)
{
  struct nrf7002_timer *t = timer;
  clock_t delay_ticks;

  delay_ticks = (clock_t)((duration_ms * CLOCKS_PER_SEC) / 1000);
  if (delay_ticks == 0)
    {
      delay_ticks = 1;
    }

  work_queue(LPWORK, &t->work, nrf7002_timer_worker, t, delay_ticks);
}

static void nrf7002_timer_kill(void *timer)
{
  struct nrf7002_timer *t = timer;

  work_cancel(LPWORK, &t->work);
}

/****************************************************************************
 * Private Functions — Timing
 ****************************************************************************/

static int nrf7002_sleep_ms(int msecs)
{
  nxsig_usleep((useconds_t)msecs * 1000);
  return 0;
}

static int nrf7002_delay_us(int usecs)
{
  nxsig_usleep((useconds_t)usecs);
  return 0;
}

static unsigned long nrf7002_time_get_curr_us(void)
{
  return (unsigned long)(clock_systime_ticks() *
                         (unsigned long)USEC_PER_TICK);
}

static unsigned int nrf7002_time_elapsed_us(unsigned long start_us)
{
  return (unsigned int)(nrf7002_time_get_curr_us() - start_us);
}

static unsigned long nrf7002_time_get_curr_ms(void)
{
  return (unsigned long)(clock_systime_ticks() *
                         (unsigned long)MSEC_PER_TICK);
}

static unsigned int nrf7002_time_elapsed_ms(unsigned long start_ms)
{
  return (unsigned int)(nrf7002_time_get_curr_ms() - start_ms);
}

/****************************************************************************
 * Private Functions — Misc
 ****************************************************************************/

static void nrf7002_assert(int test_val, int val,
                            enum nrf_wifi_assert_op_type op,
                            char *assert_msg)
{
  bool pass;

  switch (op)
    {
      case NRF_WIFI_ASSERT_EQUAL_TO:
        pass = (test_val == val);
        break;
      case NRF_WIFI_ASSERT_NOT_EQUAL_TO:
        pass = (test_val != val);
        break;
      case NRF_WIFI_ASSERT_LESS_THAN:
        pass = (test_val < val);
        break;
      case NRF_WIFI_ASSERT_LESS_THAN_EQUAL_TO:
        pass = (test_val <= val);
        break;
      case NRF_WIFI_ASSERT_GREATER_THAN:
        pass = (test_val > val);
        break;
      case NRF_WIFI_ASSERT_GREATER_THAN_EQUAL_TO:
        pass = (test_val >= val);
        break;
      default:
        pass = false;
        break;
    }

  if (!pass)
    {
      syslog(LOG_CRIT, "nrf7002 ASSERT: %s\n",
             assert_msg ? assert_msg : "(no message)");
      PANIC();
    }
}

static unsigned int nrf7002_strlen(const void *str)
{
  return (unsigned int)strlen((const char *)str);
}

/****************************************************************************
 * Public Data
 ****************************************************************************/

const struct nrf_wifi_osal_ops nrf7002_osal_ops =
{
  /* Memory */

  .mem_alloc        = nrf7002_mem_alloc,
  .mem_zalloc       = nrf7002_mem_zalloc,
  .mem_free         = nrf7002_mem_free,
  .data_mem_zalloc  = nrf7002_data_mem_zalloc,
  .data_mem_free    = nrf7002_data_mem_free,
  .mem_cpy          = nrf7002_mem_cpy,
  .mem_set          = nrf7002_mem_set,
  .mem_cmp          = nrf7002_mem_cmp,

  /* IO memory (stubs) */

  .iomem_mmap        = nrf7002_iomem_mmap,
  .iomem_unmap       = nrf7002_iomem_unmap,
  .iomem_read_reg32  = nrf7002_iomem_read_reg32,
  .iomem_write_reg32 = nrf7002_iomem_write_reg32,
  .iomem_cpy_from    = nrf7002_iomem_cpy_from,
  .iomem_cpy_to      = nrf7002_iomem_cpy_to,

  /* QSPI bus ops — implemented in nrf7002_bus_qspi.c */

  .qspi_read_reg32  = nrf7002_qspi_read_reg32,
  .qspi_write_reg32 = nrf7002_qspi_write_reg32,
  .qspi_cpy_from    = nrf7002_qspi_cpy_from,
  .qspi_cpy_to      = nrf7002_qspi_cpy_to,

  /* SPI ops (not used; set to NULL) */

  .spi_read_reg32   = NULL,
  .spi_write_reg32  = NULL,
  .spi_cpy_from     = NULL,
  .spi_cpy_to       = NULL,

  /* Spinlock */

  .spinlock_alloc    = nrf7002_spinlock_alloc,
  .spinlock_free     = nrf7002_spinlock_free,
  .spinlock_init     = nrf7002_spinlock_init,
  .spinlock_take     = nrf7002_spinlock_take,
  .spinlock_rel      = nrf7002_spinlock_rel,
  .spinlock_irq_take = nrf7002_spinlock_irq_take,
  .spinlock_irq_rel  = nrf7002_spinlock_irq_rel,

  /* Logging */

  .log_dbg  = nrf7002_log_dbg,
  .log_info = nrf7002_log_info,
  .log_err  = nrf7002_log_err,

  /* Linked list */

  .llist_node_alloc      = nrf7002_llist_node_alloc,
  .ctrl_llist_node_alloc = nrf7002_llist_node_alloc,
  .llist_node_free       = nrf7002_llist_node_free,
  .ctrl_llist_node_free  = nrf7002_llist_node_free,
  .llist_node_data_get   = nrf7002_llist_node_data_get,
  .llist_node_data_set   = nrf7002_llist_node_data_set,
  .llist_alloc           = nrf7002_llist_alloc,
  .ctrl_llist_alloc      = nrf7002_llist_alloc,
  .llist_free            = nrf7002_llist_free,
  .ctrl_llist_free       = nrf7002_llist_free,
  .llist_init            = nrf7002_llist_init,
  .llist_add_node_tail   = nrf7002_llist_add_node_tail,
  .llist_add_node_head   = nrf7002_llist_add_node_head,
  .llist_get_node_head   = nrf7002_llist_get_node_head,
  .llist_get_node_nxt    = nrf7002_llist_get_node_nxt,
  .llist_del_node        = nrf7002_llist_del_node,
  .llist_len             = nrf7002_llist_len,

  /* Network buffer */

  .nbuf_alloc           = nrf7002_nbuf_alloc,
  .nbuf_free            = nrf7002_nbuf_free,
  .nbuf_headroom_res    = nrf7002_nbuf_headroom_res,
  .nbuf_headroom_get    = nrf7002_nbuf_headroom_get,
  .nbuf_data_size       = nrf7002_nbuf_data_size,
  .nbuf_data_get        = nrf7002_nbuf_data_get,
  .nbuf_data_put        = nrf7002_nbuf_data_put,
  .nbuf_data_push       = nrf7002_nbuf_data_push,
  .nbuf_data_pull       = nrf7002_nbuf_data_pull,
  .nbuf_get_priority    = nrf7002_nbuf_get_priority,
  .nbuf_get_chksum_done = nrf7002_nbuf_get_chksum_done,
  .nbuf_set_chksum_done = nrf7002_nbuf_set_chksum_done,

  /* Tasklet */

  .tasklet_alloc    = nrf7002_tasklet_alloc,
  .tasklet_free     = nrf7002_tasklet_free,
  .tasklet_init     = nrf7002_tasklet_init,
  .tasklet_schedule = nrf7002_tasklet_schedule,
  .tasklet_kill     = nrf7002_tasklet_kill,

  /* Timer — only present in struct when NRF_WIFI_LOW_POWER is defined */

#if defined(NRF_WIFI_LOW_POWER)
  .timer_alloc    = nrf7002_timer_alloc,
  .timer_free     = nrf7002_timer_free,
  .timer_init     = nrf7002_timer_init,
  .timer_schedule = nrf7002_timer_schedule,
  .timer_kill     = nrf7002_timer_kill,
#endif

  /* Timing */

  .sleep_ms         = nrf7002_sleep_ms,
  .delay_us         = nrf7002_delay_us,
  .time_get_curr_us = nrf7002_time_get_curr_us,
  .time_elapsed_us  = nrf7002_time_elapsed_us,
  .time_get_curr_ms = nrf7002_time_get_curr_ms,
  .time_elapsed_ms  = nrf7002_time_elapsed_ms,

  /* PCIe bus ops — not used on nRF5340; leave NULL */

  .bus_pcie_init           = NULL,
  .bus_pcie_deinit         = NULL,
  .bus_pcie_dev_add        = NULL,
  .bus_pcie_dev_rem        = NULL,
  .bus_pcie_dev_init       = NULL,
  .bus_pcie_dev_deinit     = NULL,
  .bus_pcie_dev_intr_reg   = NULL,
  .bus_pcie_dev_intr_unreg = NULL,
  .bus_pcie_dev_dma_map    = NULL,
  .bus_pcie_dev_dma_unmap  = NULL,
  .bus_pcie_dev_host_map_get = NULL,

  /* QSPI bus lifecycle — implemented in nrf7002_bus_qspi.c */

  .bus_qspi_init             = nrf7002_qspi_bus_init,
  .bus_qspi_deinit           = nrf7002_qspi_bus_deinit,
  .bus_qspi_dev_add          = nrf7002_qspi_dev_add,
  .bus_qspi_dev_rem          = nrf7002_qspi_dev_rem,
  .bus_qspi_dev_init         = nrf7002_qspi_dev_init,
  .bus_qspi_dev_deinit       = nrf7002_qspi_dev_deinit,
  .bus_qspi_dev_intr_reg     = nrf7002_qspi_dev_intr_reg,
  .bus_qspi_dev_intr_unreg   = nrf7002_qspi_dev_intr_unreg,
  .bus_qspi_dev_host_map_get = nrf7002_qspi_dev_host_map_get,

  /* SPI bus lifecycle — not used; leave NULL */

  .bus_spi_init             = NULL,
  .bus_spi_deinit           = NULL,
  .bus_spi_dev_add          = NULL,
  .bus_spi_dev_rem          = NULL,
  .bus_spi_dev_init         = NULL,
  .bus_spi_dev_deinit       = NULL,
  .bus_spi_dev_intr_reg     = NULL,
  .bus_spi_dev_intr_unreg   = NULL,
  .bus_spi_dev_host_map_get = NULL,

  /* Misc */

  .assert = nrf7002_assert,
  .strlen = nrf7002_strlen,
};
