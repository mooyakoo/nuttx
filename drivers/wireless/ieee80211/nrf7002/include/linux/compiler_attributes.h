/* linux/compiler_attributes.h — NuttX shim for NCS nrf_wifi HAL */
#ifndef _LINUX_COMPILER_ATTRIBUTES_H
#define _LINUX_COMPILER_ATTRIBUTES_H

#ifndef __packed
#  define __packed   __attribute__((packed))
#endif
#ifndef __aligned
#  define __aligned(x) __attribute__((aligned(x)))
#endif
#ifndef __maybe_unused
#  define __maybe_unused __attribute__((unused))
#endif
#ifndef __always_inline
#  define __always_inline inline __attribute__((always_inline))
#endif

#endif /* _LINUX_COMPILER_ATTRIBUTES_H */
