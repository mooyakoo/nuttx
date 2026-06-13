/* linux/version.h — NuttX shim for NCS nrf_wifi OSAL */
#ifndef _LINUX_VERSION_H
#define _LINUX_VERSION_H
/* Provide a dummy kernel version to avoid stdarg conditional.
 * LINUX_VERSION_CODE >= KERNEL_VERSION(5,14,0) means use linux/stdarg.h
 * We want the else branch (stdarg.h), so provide a version < 5.14.0
 */
#define LINUX_VERSION_CODE 0x050D00  /* 5.13.0 */
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#endif
