/****************************************************************************
 * drivers/wireless/ieee80211/nrf7002/nrf7002_wpa.c
 *
 * Minimal WPA2-PSK 4-way handshake for the nRF7002 driver.
 *
 * Implements:
 *   - SHA-1 (from OpenBSD / public domain)
 *   - HMAC-SHA1
 *   - PBKDF2-SHA1  (PMK derivation)
 *   - PRF-512       (PTK derivation)
 *   - AES-128 key-unwrap (GTK extraction from M3)
 *   - EAPOL-Key frame parser / 4-way HS state machine
 *
 * References:
 *   IEEE 802.11-2020, Clause 12.7.6 (4-way HS)
 *   RFC 2898 (PBKDF2)
 *   RFC 3394 (AES Key Wrap)
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <arpa/inet.h>

#include <nuttx/kmalloc.h>
#include <nuttx/clock.h>

#include "nrf7002_wpa.h"
#include "nrf7002_driver.h"

/* FMAC API for key installation and data TX */

#include "system/fmac_api.h"
#include "system/fmac_peer.h"
#include "common/fmac_util.h"
#include "host_rpu_umac_if.h"
#include "osal_api.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define SHA1_DIGEST_LEN  20
#define SHA1_BLOCK_LEN   64
#define AES_BLOCK_LEN    16
#define PMK_LEN          32
#define PTK_LEN          64  /* 512 bits */

#define EAPOL_ETHERTYPE  0x888e

/* Zephyr's net_pkt_to_nbuf() reserves 100 bytes before handing EAPOL/data
 * frames to nrf_wifi_fmac_start_xmit().  Keep the same shape for the
 * hand-written control-port frames.
 */

#define NRF7002_TX_NBUF_HEADROOM 100

/* EAPOL-Key descriptor type (WPA/RSN = 2) */

#define EAPOL_KEY_DESC_RSN  2

/* Key Information flags (byte 0 of 2-byte big-endian field) */

#define EAPOL_KI_MIC     0x01  /* bit 8 */
#define EAPOL_KI_SECURE  0x02  /* bit 9 */
#define EAPOL_KI_ENCDATA 0x10  /* bit 12 = Encrypted Key Data */
#define EAPOL_KI_PAIRWISE 0x08 /* bit 3 of lo byte = key type (pairwise=1) */

/****************************************************************************
 * Private Types — SHA-1
 * Steve Reid's public domain SHA-1
 ****************************************************************************/

typedef struct
{
  uint32_t state[5];
  uint32_t count[2];
  uint8_t  buf[64];
} sha1_ctx_t;

/****************************************************************************
 * Private Functions — SHA-1
 ****************************************************************************/

#define SHA1_ROL(x, n)  (((x) << (n)) | ((x) >> (32 - (n))))

#define SHA1_BLK0(i) (W[i] = (((uint32_t)(buf[4*(i)])   << 24) | \
                               ((uint32_t)(buf[4*(i)+1]) << 16) | \
                               ((uint32_t)(buf[4*(i)+2]) <<  8) | \
                                (uint32_t)(buf[4*(i)+3])))

#define SHA1_BLK(i) (W[(i)&15] = SHA1_ROL(W[((i)+13)&15] ^ W[((i)+8)&15] ^ \
                                            W[((i)+2)&15]  ^ W[(i)&15],1))

#define SHA1_R0(v,w,x,y,z,i) \
  z += ((w & (x ^ y)) ^ y)        + SHA1_BLK0(i) + 0x5a827999 + SHA1_ROL(v,5); \
  w = SHA1_ROL(w, 30)

#define SHA1_R1(v,w,x,y,z,i) \
  z += ((w & (x ^ y)) ^ y)        + SHA1_BLK(i)  + 0x5a827999 + SHA1_ROL(v,5); \
  w = SHA1_ROL(w, 30)

#define SHA1_R2(v,w,x,y,z,i) \
  z += (w ^ x ^ y)                 + SHA1_BLK(i)  + 0x6ed9eba1 + SHA1_ROL(v,5); \
  w = SHA1_ROL(w, 30)

#define SHA1_R3(v,w,x,y,z,i) \
  z += (((w | x) & y) | (w & x))   + SHA1_BLK(i)  + 0x8f1bbcdc + SHA1_ROL(v,5); \
  w = SHA1_ROL(w, 30)

#define SHA1_R4(v,w,x,y,z,i) \
  z += (w ^ x ^ y)                 + SHA1_BLK(i)  + 0xca62c1d6 + SHA1_ROL(v,5); \
  w = SHA1_ROL(w, 30)

static void sha1_transform(uint32_t state[5], const uint8_t buf[64])
{
  uint32_t W[16];
  uint32_t a = state[0];
  uint32_t b = state[1];
  uint32_t c = state[2];
  uint32_t d = state[3];
  uint32_t e = state[4];

  SHA1_R0(a,b,c,d,e, 0); SHA1_R0(e,a,b,c,d, 1); SHA1_R0(d,e,a,b,c, 2); SHA1_R0(c,d,e,a,b, 3);
  SHA1_R0(b,c,d,e,a, 4); SHA1_R0(a,b,c,d,e, 5); SHA1_R0(e,a,b,c,d, 6); SHA1_R0(d,e,a,b,c, 7);
  SHA1_R0(c,d,e,a,b, 8); SHA1_R0(b,c,d,e,a, 9); SHA1_R0(a,b,c,d,e,10); SHA1_R0(e,a,b,c,d,11);
  SHA1_R0(d,e,a,b,c,12); SHA1_R0(c,d,e,a,b,13); SHA1_R0(b,c,d,e,a,14); SHA1_R0(a,b,c,d,e,15);
  SHA1_R1(e,a,b,c,d,16); SHA1_R1(d,e,a,b,c,17); SHA1_R1(c,d,e,a,b,18); SHA1_R1(b,c,d,e,a,19);
  SHA1_R2(a,b,c,d,e,20); SHA1_R2(e,a,b,c,d,21); SHA1_R2(d,e,a,b,c,22); SHA1_R2(c,d,e,a,b,23);
  SHA1_R2(b,c,d,e,a,24); SHA1_R2(a,b,c,d,e,25); SHA1_R2(e,a,b,c,d,26); SHA1_R2(d,e,a,b,c,27);
  SHA1_R2(c,d,e,a,b,28); SHA1_R2(b,c,d,e,a,29); SHA1_R2(a,b,c,d,e,30); SHA1_R2(e,a,b,c,d,31);
  SHA1_R2(d,e,a,b,c,32); SHA1_R2(c,d,e,a,b,33); SHA1_R2(b,c,d,e,a,34); SHA1_R2(a,b,c,d,e,35);
  SHA1_R2(e,a,b,c,d,36); SHA1_R2(d,e,a,b,c,37); SHA1_R2(c,d,e,a,b,38); SHA1_R2(b,c,d,e,a,39);
  SHA1_R3(a,b,c,d,e,40); SHA1_R3(e,a,b,c,d,41); SHA1_R3(d,e,a,b,c,42); SHA1_R3(c,d,e,a,b,43);
  SHA1_R3(b,c,d,e,a,44); SHA1_R3(a,b,c,d,e,45); SHA1_R3(e,a,b,c,d,46); SHA1_R3(d,e,a,b,c,47);
  SHA1_R3(c,d,e,a,b,48); SHA1_R3(b,c,d,e,a,49); SHA1_R3(a,b,c,d,e,50); SHA1_R3(e,a,b,c,d,51);
  SHA1_R3(d,e,a,b,c,52); SHA1_R3(c,d,e,a,b,53); SHA1_R3(b,c,d,e,a,54); SHA1_R3(a,b,c,d,e,55);
  SHA1_R3(e,a,b,c,d,56); SHA1_R3(d,e,a,b,c,57); SHA1_R3(c,d,e,a,b,58); SHA1_R3(b,c,d,e,a,59);
  SHA1_R4(a,b,c,d,e,60); SHA1_R4(e,a,b,c,d,61); SHA1_R4(d,e,a,b,c,62); SHA1_R4(c,d,e,a,b,63);
  SHA1_R4(b,c,d,e,a,64); SHA1_R4(a,b,c,d,e,65); SHA1_R4(e,a,b,c,d,66); SHA1_R4(d,e,a,b,c,67);
  SHA1_R4(c,d,e,a,b,68); SHA1_R4(b,c,d,e,a,69); SHA1_R4(a,b,c,d,e,70); SHA1_R4(e,a,b,c,d,71);
  SHA1_R4(d,e,a,b,c,72); SHA1_R4(c,d,e,a,b,73); SHA1_R4(b,c,d,e,a,74); SHA1_R4(a,b,c,d,e,75);
  SHA1_R4(e,a,b,c,d,76); SHA1_R4(d,e,a,b,c,77); SHA1_R4(c,d,e,a,b,78); SHA1_R4(b,c,d,e,a,79);

  state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

static void sha1_init(sha1_ctx_t *ctx)
{
  ctx->state[0] = 0x67452301;
  ctx->state[1] = 0xefcdab89;
  ctx->state[2] = 0x98badcfe;
  ctx->state[3] = 0x10325476;
  ctx->state[4] = 0xc3d2e1f0;
  ctx->count[0] = ctx->count[1] = 0;
}

static void sha1_update(sha1_ctx_t *ctx, const uint8_t *data, uint32_t len)
{
  uint32_t i;
  uint32_t j = (ctx->count[0] >> 3) & 63;

  if ((ctx->count[0] += len << 3) < (len << 3))
    {
      ctx->count[1]++;
    }

  ctx->count[1] += (len >> 29);

  if ((j + len) > 63)
    {
      i = 64 - j;
      memcpy(&ctx->buf[j], data, i);
      sha1_transform(ctx->state, ctx->buf);
      for (; i + 63 < len; i += 64)
        {
          sha1_transform(ctx->state, data + i);
        }
      j = 0;
    }
  else
    {
      i = 0;
    }

  memcpy(&ctx->buf[j], &data[i], len - i);
}

static void sha1_final(sha1_ctx_t *ctx, uint8_t digest[20])
{
  uint8_t finalcount[8];
  uint8_t c;
  int     i;

  for (i = 0; i < 8; i++)
    {
      finalcount[i] = (uint8_t)((ctx->count[(i >= 4 ? 0 : 1)]
                        >> ((3 - (i & 3)) * 8)) & 255);
    }

  c = 0x80;
  sha1_update(ctx, &c, 1);
  while ((ctx->count[0] & 504) != 448)
    {
      c = 0x00;
      sha1_update(ctx, &c, 1);
    }

  sha1_update(ctx, finalcount, 8);

  for (i = 0; i < 20; i++)
    {
      digest[i] = (uint8_t)((ctx->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
    }

  memset(ctx, 0, sizeof(*ctx));
}

static void sha1(const uint8_t *data, uint32_t len, uint8_t digest[20])
{
  sha1_ctx_t ctx;
  sha1_init(&ctx);
  sha1_update(&ctx, data, len);
  sha1_final(&ctx, digest);
}

/****************************************************************************
 * Private Functions — HMAC-SHA1
 ****************************************************************************/

static void hmac_sha1(const uint8_t *key, uint32_t klen,
                      const uint8_t *data, uint32_t dlen,
                      uint8_t digest[20])
{
  sha1_ctx_t ctx;
  uint8_t    k_pad[64];
  uint8_t    tk[20];
  int        i;

  if (klen > 64)
    {
      sha1(key, klen, tk);
      key  = tk;
      klen = 20;
    }

  memset(k_pad, 0x36, 64);
  for (i = 0; i < (int)klen; i++)
    {
      k_pad[i] ^= key[i];
    }

  sha1_init(&ctx);
  sha1_update(&ctx, k_pad, 64);
  sha1_update(&ctx, data, dlen);
  sha1_final(&ctx, digest);

  memset(k_pad, 0x5c, 64);
  for (i = 0; i < (int)klen; i++)
    {
      k_pad[i] ^= key[i];
    }

  sha1_init(&ctx);
  sha1_update(&ctx, k_pad, 64);
  sha1_update(&ctx, digest, 20);
  sha1_final(&ctx, digest);
}

/* HMAC-SHA1 over multiple scatter/gather data segments */

static void hmac_sha1_vector(const uint8_t *key, uint32_t klen,
                              int num_elem,
                              const uint8_t * const *data,
                              const uint32_t *data_len,
                              uint8_t digest[20])
{
  sha1_ctx_t ctx;
  sha1_ctx_t ctx2;
  uint8_t    k_pad[64];
  uint8_t    tk[20];
  int        i;

  if (klen > 64)
    {
      sha1(key, klen, tk);
      key  = tk;
      klen = 20;
    }

  memset(k_pad, 0x36, 64);
  for (i = 0; i < (int)klen; i++)
    {
      k_pad[i] ^= key[i];
    }

  sha1_init(&ctx);
  sha1_update(&ctx, k_pad, 64);
  for (i = 0; i < num_elem; i++)
    {
      sha1_update(&ctx, data[i], data_len[i]);
    }

  sha1_final(&ctx, digest);

  memset(k_pad, 0x5c, 64);
  for (i = 0; i < (int)klen; i++)
    {
      k_pad[i] ^= key[i];
    }

  sha1_init(&ctx2);
  sha1_update(&ctx2, k_pad, 64);
  sha1_update(&ctx2, digest, 20);
  sha1_final(&ctx2, digest);
}

/****************************************************************************
 * Private Functions — PBKDF2-SHA1
 * RFC 2898 §5.2
 ****************************************************************************/

static void pbkdf2_sha1(const char *passphrase,
                        const uint8_t *ssid, uint32_t ssid_len,
                        uint32_t iterations,
                        uint8_t *out, uint32_t out_len)
{
  uint32_t block;
  uint32_t bytes;
  uint32_t i;
  uint8_t  U[20];
  uint8_t  T[20];
  uint8_t  tmp[4];

  const uint8_t *pd[2];
  uint32_t       pl[2];

  pd[0] = ssid;
  pl[0] = ssid_len;
  pd[1] = tmp;
  pl[1] = 4;

  for (block = 1; out_len > 0; block++)
    {
      /* U1 = HMAC-SHA1(password, salt || INT(block)) */

      tmp[0] = (uint8_t)(block >> 24);
      tmp[1] = (uint8_t)(block >> 16);
      tmp[2] = (uint8_t)(block >>  8);
      tmp[3] = (uint8_t)(block);

      hmac_sha1_vector((const uint8_t *)passphrase, strlen(passphrase),
                       2, pd, pl, U);
      memcpy(T, U, 20);

      /* U2..Un = HMAC-SHA1(password, U_{n-1}) */

      for (i = 1; i < iterations; i++)
        {
          hmac_sha1((const uint8_t *)passphrase, strlen(passphrase),
                    U, 20, U);
          for (int j = 0; j < 20; j++)
            {
              T[j] ^= U[j];
            }
        }

      bytes = (out_len < 20) ? out_len : 20;
      memcpy(out, T, bytes);
      out     += bytes;
      out_len -= bytes;
    }
}

/****************************************************************************
 * Private Functions — IEEE 802.11 PRF
 * PRF(key, A, B, len_bits)
 *   for i = 0; i < ⌈len/160⌉; i++:
 *     H = HMAC-SHA1(key, A || 0x00 || B || i)
 *     output = output || H
 ****************************************************************************/

static void prf(const uint8_t *key,   uint32_t klen,
                const char    *label, uint32_t llen,
                const uint8_t *data,  uint32_t dlen,
                uint8_t       *out,   uint32_t out_bytes)
{
  uint8_t        counter = 0;
  uint8_t        digest[20];
  uint32_t       done = 0;
  uint8_t        zero = 0;
  const uint8_t *segs[4];
  uint32_t       lens[4];

  segs[0] = (const uint8_t *)label;
  lens[0] = llen;
  segs[1] = &zero;
  lens[1] = 1;
  segs[2] = data;
  lens[2] = dlen;
  segs[3] = &counter;
  lens[3] = 1;

  while (done < out_bytes)
    {
      hmac_sha1_vector(key, klen, 4, segs, lens, digest);
      uint32_t copy = (out_bytes - done < 20) ? (out_bytes - done) : 20;
      memcpy(out + done, digest, copy);
      done += copy;
      counter++;
    }
}

/****************************************************************************
 * Private Functions — AES-128 (for key unwrap)
 * Tiny AES from Kokke (public domain)
 ****************************************************************************/

#define NB 4
#define NK 4
#define NR 10

typedef uint8_t state_t[4][4];

static const uint8_t sbox[256] =
{
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t rsbox[256] =
{
  0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
  0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
  0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
  0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
  0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
  0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
  0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
  0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
  0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
  0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
  0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
  0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
  0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
  0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
  0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
  0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static const uint8_t rcon[11] =
{
  0x8d,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

static uint8_t xtime(uint8_t x) { return (x << 1) ^ ((x >> 7) * 0x1b); }
static uint8_t mul(uint8_t x, uint8_t y)
{
  return ((y & 1) * x) ^
         ((y >> 1 & 1) * xtime(x)) ^
         ((y >> 2 & 1) * xtime(xtime(x))) ^
         ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^
         ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x)))));
}

static void aes_key_expansion(const uint8_t *key, uint8_t rk[11][4][4])
{
  uint8_t tmp[4];
  int     i;

  for (i = 0; i < NK; i++)
    {
      rk[0][i][0] = key[4 * i];
      rk[0][i][1] = key[4 * i + 1];
      rk[0][i][2] = key[4 * i + 2];
      rk[0][i][3] = key[4 * i + 3];
    }

  for (i = NK; i < NB * (NR + 1); i++)
    {
      int prev_rnd = (i - 1) / NK;
      int prev_col = (i - 1) % NK;
      tmp[0] = rk[prev_rnd][prev_col][0];
      tmp[1] = rk[prev_rnd][prev_col][1];
      tmp[2] = rk[prev_rnd][prev_col][2];
      tmp[3] = rk[prev_rnd][prev_col][3];

      if (i % NK == 0)
        {
          uint8_t t = tmp[0];
          tmp[0] = sbox[tmp[1]] ^ rcon[i / NK];
          tmp[1] = sbox[tmp[2]];
          tmp[2] = sbox[tmp[3]];
          tmp[3] = sbox[t];
        }

      int cur_rnd = i / NK;
      int cur_col = i % NK;
      int src_rnd = (i - NK) / NK;
      int src_col = (i - NK) % NK;
      rk[cur_rnd][cur_col][0] = rk[src_rnd][src_col][0] ^ tmp[0];
      rk[cur_rnd][cur_col][1] = rk[src_rnd][src_col][1] ^ tmp[1];
      rk[cur_rnd][cur_col][2] = rk[src_rnd][src_col][2] ^ tmp[2];
      rk[cur_rnd][cur_col][3] = rk[src_rnd][src_col][3] ^ tmp[3];
    }
}


/****************************************************************************
 * Private Functions — AES Key Unwrap (RFC 3394)
 * Decrypts an AES-128 key-wrapped buffer in place.
 * Returns 0 on success, -1 if integrity check fails.
 ****************************************************************************/

/* We need AES decrypt for key unwrap */

static void aes_decrypt(const uint8_t *in, const uint8_t rk[11][4][4],
                         uint8_t *out)
{
  state_t state;
  int     round;
  int     r;
  int     c;

  for (r = 0; r < 4; r++)
    for (c = 0; c < 4; c++)
      state[r][c] = in[r + 4 * c];

  /* AddRoundKey NR */
  for (r = 0; r < 4; r++)
    for (c = 0; c < 4; c++)
      state[r][c] ^= rk[NR][c][r];

  for (round = NR - 1; round >= 0; round--)
    {
      /* InvShiftRows */
      uint8_t t;
      t = state[1][3]; state[1][3] = state[1][2]; state[1][2] = state[1][1];
      state[1][1] = state[1][0]; state[1][0] = t;
      t = state[2][0]; state[2][0] = state[2][2]; state[2][2] = t;
      t = state[2][1]; state[2][1] = state[2][3]; state[2][3] = t;
      t = state[3][0]; state[3][0] = state[3][1]; state[3][1] = state[3][2];
      state[3][2] = state[3][3]; state[3][3] = t;

      /* InvSubBytes */
      for (r = 0; r < 4; r++)
        for (c = 0; c < 4; c++)
          state[r][c] = rsbox[state[r][c]];

      /* AddRoundKey */
      for (r = 0; r < 4; r++)
        for (c = 0; c < 4; c++)
          state[r][c] ^= rk[round][c][r];

      /* InvMixColumns (skip first AddRoundKey, done above) */
      if (round > 0)
        {
          for (c = 0; c < 4; c++)
            {
              uint8_t s0 = state[0][c], s1 = state[1][c],
                      s2 = state[2][c], s3 = state[3][c];
              state[0][c] = mul(s0,0x0e)^mul(s1,0x0b)^mul(s2,0x0d)^mul(s3,0x09);
              state[1][c] = mul(s0,0x09)^mul(s1,0x0e)^mul(s2,0x0b)^mul(s3,0x0d);
              state[2][c] = mul(s0,0x0d)^mul(s1,0x09)^mul(s2,0x0e)^mul(s3,0x0b);
              state[3][c] = mul(s0,0x0b)^mul(s1,0x0d)^mul(s2,0x09)^mul(s3,0x0e);
            }
        }
    }

  for (r = 0; r < 4; r++)
    for (c = 0; c < 4; c++)
      out[r + 4 * c] = state[r][c];
}

static int aes_unwrap(const uint8_t *kek, uint32_t kek_len,
                      const uint8_t *cipher, uint32_t cipher_len,
                      uint8_t *plain)
{
  uint8_t rk[11][4][4];
  uint8_t a[8];
  uint8_t b[16];
  uint32_t n;
  int64_t  j;
  int      i;

  if (cipher_len < 16 || (cipher_len % 8) != 0)
    {
      return -1;
    }

  n = (cipher_len / 8) - 1;

  aes_key_expansion(kek, rk);

  memcpy(a, cipher, 8);
  memcpy(plain, cipher + 8, n * 8);

  for (j = 5; j >= 0; j--)
    {
      for (i = n; i >= 1; i--)
        {
          uint64_t t = (uint64_t)(n * (uint64_t)j + i);
          for (int k = 7; k >= 0; k--, t >>= 8)
            {
              a[k] ^= (uint8_t)(t & 0xff);
            }

          memcpy(b, a, 8);
          memcpy(b + 8, plain + (i - 1) * 8, 8);
          aes_decrypt(b, rk, b);
          memcpy(a, b, 8);
          memcpy(plain + (i - 1) * 8, b + 8, 8);
        }
    }

  /* Integrity check: A should be 0xa6a6a6a6a6a6a6a6 */

  for (i = 0; i < 8; i++)
    {
      if (a[i] != 0xa6)
        {
          return -1;
        }
    }

  return 0;
}

/****************************************************************************
 * Private Types — EAPOL frame
 ****************************************************************************/

/* Minimal EAPOL-Key frame layout (offsets from start of Ethernet payload) */

struct eapol_hdr
{
  uint8_t  version;
  uint8_t  type;     /* 3 = EAPOL-Key */
  uint16_t length;   /* BE, body length */
} __attribute__((packed));

struct eapol_key
{
  uint8_t  desc_type;     /* 2 = RSN */
  uint16_t key_info;      /* BE */
  uint16_t key_length;    /* BE */
  uint8_t  replay_cnt[8];
  uint8_t  nonce[32];
  uint8_t  key_iv[16];
  uint8_t  key_rsc[8];
  uint8_t  key_id[8];
  uint8_t  mic[16];
  uint16_t key_data_len;  /* BE */
  /* key_data follows */
} __attribute__((packed));

/****************************************************************************
 * Private Functions — Debug
 ****************************************************************************/

static void nrf7002_wpa_put_be16(uint8_t *pos, uint16_t val)
{
  pos[0] = (uint8_t)(val >> 8);
  pos[1] = (uint8_t)val;
}

static void nrf7002_wpa_hexdump(const char *label,
                                const uint8_t *data,
                                uint32_t len)
{
  static const char hex[] = "0123456789abcdef";
  char line[33];
  uint32_t off;

  for (off = 0; off < len; off += 16)
    {
      uint32_t chunk = len - off;
      uint32_t i;

      if (chunk > 16)
        {
          chunk = 16;
        }

      for (i = 0; i < chunk; i++)
        {
          line[2 * i]     = hex[data[off + i] >> 4];
          line[2 * i + 1] = hex[data[off + i] & 0x0f];
        }

      line[2 * chunk] = '\0';

      syslog(LOG_INFO, "nrf7002: WPA %s[%lu]=%s\n",
             label, (unsigned long)off, line);
    }
}

static enum nrf_wifi_status nrf7002_wpa_tx_eapol(struct nrf7002_priv *priv,
                                                 const uint8_t *frame,
                                                 uint32_t len)
{
  struct nrf_wifi_sys_fmac_dev_ctx *sys_dev_ctx;
  enum nrf_wifi_status              status;
  unsigned char                    *ra;
  void                             *nbuf;
  uint16_t                          ethertype;
  int                               peer_id;
  int                               ret;

  if (priv == NULL || priv->fmac_dev_ctx == NULL || frame == NULL ||
      len < 14)
    {
      return NRF_WIFI_STATUS_FAIL;
    }

  ethertype = ((uint16_t)frame[12] << 8) | frame[13];
  if (ethertype != EAPOL_ETHERTYPE)
    {
      syslog(LOG_ERR, "nrf7002: refusing non-EAPOL control TX type=0x%04x\n",
             ethertype);
      return NRF_WIFI_STATUS_FAIL;
    }

  if (!priv->carrier_up)
    {
      syslog(LOG_ERR, "nrf7002: EAPOL TX blocked: carrier down\n");
      return NRF_WIFI_STATUS_FAIL;
    }

  nbuf = nrf_wifi_osal_nbuf_alloc(len + NRF7002_TX_NBUF_HEADROOM);
  if (nbuf == NULL)
    {
      syslog(LOG_ERR, "nrf7002: EAPOL nbuf alloc FAILED\n");
      return NRF_WIFI_STATUS_FAIL;
    }

  nrf_wifi_osal_nbuf_headroom_res(nbuf, NRF7002_TX_NBUF_HEADROOM);
  nrf_wifi_osal_nbuf_data_put(nbuf, len);
  memcpy(nrf_wifi_osal_nbuf_data_get(nbuf), frame, len);

  sys_dev_ctx = wifi_dev_priv(priv->fmac_dev_ctx);
  if (sys_dev_ctx == NULL || sys_dev_ctx->vif_ctx[priv->vif_idx] == NULL)
    {
      syslog(LOG_ERR, "nrf7002: EAPOL TX blocked: missing vif context\n");
      nrf_wifi_osal_nbuf_free(nbuf);
      return NRF_WIFI_STATUS_FAIL;
    }

  ra = nrf_wifi_util_get_ra(sys_dev_ctx->vif_ctx[priv->vif_idx], nbuf);
  peer_id = nrf_wifi_fmac_peer_get_id(priv->fmac_dev_ctx, ra);
  if (peer_id == -1)
    {
      syslog(LOG_ERR, "nrf7002: EAPOL TX blocked: unknown peer\n");
      nrf_wifi_osal_nbuf_free(nbuf);
      return NRF_WIFI_STATUS_FAIL;
    }

  ret = nxsem_trywait(&priv->tx_tokens);
  if (ret < 0)
    {
      syslog(LOG_WARNING, "nrf7002: EAPOL TX blocked: TX token busy\n");
      nrf_wifi_osal_nbuf_free(nbuf);
      return NRF_WIFI_STATUS_FAIL;
    }

  status = nrf_wifi_fmac_start_xmit(priv->fmac_dev_ctx, priv->vif_idx, nbuf);

  /* On failure, nrf_wifi_fmac_start_xmit() has already freed nbuf. */

  nxsem_post(&priv->tx_tokens);

  return status;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/**
 * nrf7002_wpa_derive_pmk - Derive PMK from passphrase and SSID
 */
void nrf7002_wpa_derive_pmk(const char *passphrase,
                             const uint8_t *ssid, uint32_t ssid_len,
                             uint8_t pmk[32])
{
  pbkdf2_sha1(passphrase, ssid, ssid_len, 4096, pmk, 32);
}

/**
 * nrf7002_wpa_process_eapol - Handle incoming EAPOL frame for 4-way HS
 *
 * Called from nrf7002_rx_worker for ethertype 0x888E frames.
 * Returns true if frame was consumed (EAPOL-Key), false otherwise.
 */
bool nrf7002_wpa_process_eapol(struct nrf7002_priv *priv,
                                const uint8_t *frame, uint32_t len)
{
  const struct eapol_hdr *ehdr;
  const struct eapol_key *ekey;

  uint16_t            key_info;
  bool                is_pairwise;
  bool                has_mic;
  bool                is_msg1;
  bool                is_msg3;
  bool                new_handshake;
  const uint8_t      *kdata;
  uint32_t            kdata_len;
  uint8_t             gtk[32];
  uint8_t             mic_computed[20];
  uint8_t             prf_data[2 * 6 + 2 * 32]; /* two MACs + two nonces */
  struct nrf_wifi_umac_key_info key_info_fmac;
  enum nrf_wifi_status fmac_st;

  if (len < 14 + sizeof(*ehdr) + sizeof(*ekey))
    {
      return false;
    }

  if (((uint16_t)frame[12] << 8 | frame[13]) != EAPOL_ETHERTYPE)
    {
      return false;
    }

  /* Use byte offsets to avoid Cortex-M33 alignment faults on packed fields */

  /* EAPOL header: [ver][type][len_hi][len_lo] at frame+14 */

  uint8_t eapol_type = frame[14 + 1];  /* type field */

  if (eapol_type != 3)
    {
      return false; /* Not EAPOL-Key */
    }

  if (len < 14 + 4 + sizeof(*ekey))
    {
      syslog(LOG_WARNING, "nrf7002: EAPOL too short: %lu\n", (unsigned long)len);
      return false;
    }

  ehdr = (const struct eapol_hdr *)(frame + 14);
  ekey = (const struct eapol_key *)(frame + 14 + 4);

  /* key_info is big-endian in the frame */
  key_info = (uint16_t)(((const uint8_t *)&ekey->key_info)[0] << 8 |
                         ((const uint8_t *)&ekey->key_info)[1]);

  is_pairwise = (key_info & (1 << 3)) != 0;  /* bit 3 */
  has_mic     = (key_info & (1 << 8)) != 0;  /* bit 8 */
  is_msg1     = is_pairwise && !has_mic;
  is_msg3     = is_pairwise && has_mic && (key_info & (1 << 9));

  kdata_len = (uint32_t)(((const uint8_t *)&ekey->key_data_len)[0] << 8 |
                           ((const uint8_t *)&ekey->key_data_len)[1]);
  kdata = (const uint8_t *)ekey + sizeof(*ekey);

  if (!is_msg1 && !is_msg3)
    {
      syslog(LOG_INFO, "nrf7002: EAPOL not M1/M3, skip\n");
      return false;
    }

  if (priv->pmk_valid == 0)
    {
      syslog(LOG_WARNING, "nrf7002: EAPOL but PMK not set\n");
      return true;
    }

  if (is_msg1)
    {
      /* M1: AP→STA, contains Anonce.
       * Generate Snonce, derive PTK.
       */

      syslog(LOG_INFO, "nrf7002: 4-way M1 received\n");
      syslog(LOG_INFO, "nrf7002: M1 key_info=0x%04x desc_ver=%u\n",
             key_info, (unsigned int)(key_info & 0x0007));

      if ((key_info & 0x0007) != 2)
        {
          syslog(LOG_WARNING,
                 "nrf7002: unsupported M1 desc_ver=%u; M2 uses ver=2 HMAC-SHA1/AES\n",
                 (unsigned int)(key_info & 0x0007));
        }

      /* New handshake instance — keys not yet installed for this round. */

      priv->keys_installed = 0;

      /* Generate SNonce only when this is a *new* handshake (ANonce changed).
       * If the AP retransmits M1 with the same ANonce (because it did not get
       * our M2 in time), we MUST reuse the same SNonce so the PTK stays
       * identical and M2's MIC verifies on the AP — otherwise the AP keeps
       * resending M1 and eventually deauths.  Per IEEE 802.11 / wpa_supplicant
       * the SNonce is only renewed for a genuinely new 4-way handshake.
       */

      new_handshake = !priv->ptk_valid ||
                      memcmp(priv->anonce, ekey->nonce, 32) != 0;
      if (new_handshake)
        {
          arc4random_buf(priv->snonce, sizeof(priv->snonce));
          syslog(LOG_INFO, "nrf7002: generated fresh SNonce\n");
        }
      else
        {
          syslog(LOG_INFO, "nrf7002: reusing SNonce for M1 retry\n");
        }

      /* Save Anonce */

      memcpy(priv->anonce, ekey->nonce, 32);
      memcpy(priv->ap_replay, ekey->replay_cnt, 8);

      /* Derive PTK: PRF-512(PMK, "Pairwise key expansion",
       *   min(AP_MAC,STA_MAC) || max(AP_MAC,STA_MAC) ||
       *   min(Anonce,Snonce)  || max(Anonce,Snonce))
       */

      const uint8_t *mac_ap  = priv->target_bssid;
      const uint8_t *mac_sta = priv->netdev.d_mac.ether.ether_addr_octet;
      const char    *mac_first;
      const char    *mac_second;
      const char    *nonce_first;
      const char    *nonce_second;

      /* min/max of MACs */
      if (memcmp(mac_ap, mac_sta, 6) < 0)
        {
          memcpy(prf_data,     mac_ap,  6);
          memcpy(prf_data + 6, mac_sta, 6);
          mac_first  = "AP";
          mac_second = "STA";
        }
      else
        {
          memcpy(prf_data,     mac_sta, 6);
          memcpy(prf_data + 6, mac_ap,  6);
          mac_first  = "STA";
          mac_second = "AP";
        }

      /* min/max of nonces */
      if (memcmp(priv->anonce, priv->snonce, 32) < 0)
        {
          memcpy(prf_data + 12, priv->anonce, 32);
          memcpy(prf_data + 44, priv->snonce, 32);
          nonce_first  = "ANonce";
          nonce_second = "SNonce";
        }
      else
        {
          memcpy(prf_data + 12, priv->snonce, 32);
          memcpy(prf_data + 44, priv->anonce, 32);
          nonce_first  = "SNonce";
          nonce_second = "ANonce";
        }

      syslog(LOG_INFO, "nrf7002: PTK PRF order mac=%s,%s nonce=%s,%s\n",
             mac_first, mac_second, nonce_first, nonce_second);
      nrf7002_wpa_hexdump("PTK-PRF-MAC0", prf_data, 6);
      nrf7002_wpa_hexdump("PTK-PRF-MAC1", prf_data + 6, 6);
      nrf7002_wpa_hexdump("PTK-PRF-NONCE0", prf_data + 12, 32);
      nrf7002_wpa_hexdump("PTK-PRF-NONCE1", prf_data + 44, 32);

      prf(priv->pmk, 32,
          "Pairwise key expansion", 22,
          prf_data, 76,
          priv->ptk, 64);

      priv->ptk_valid = 1;

      nrf7002_wpa_hexdump("ANonce", priv->anonce, 32);
      nrf7002_wpa_hexdump("SNonce", priv->snonce, 32);
      nrf7002_wpa_hexdump("PMK", priv->pmk, 32);
      nrf7002_wpa_hexdump("PTK-KCK", priv->ptk, 16);

      syslog(LOG_INFO, "nrf7002: PTK derived\n");

      /* Build M2 response.
       * M2: STA→AP, contains Snonce + RSN IE, MIC over entire frame.
       * NCS sends EAPOL through the data TX API, with the EAPOL ethertype
       * and assoc_info.control_port enabled, not through mgmt_tx.
       */

      nrf7002_wpa_send_m2(priv);
    }
  else if (is_msg3)
    {
      /* M3: AP→STA, contains encrypted GTK in key_data.
       *
       * Latency-critical path: the AP arms a 100 ms timeout waiting for M4.
       * If M4 is late the AP retransmits M3 with a higher replay counter and
       * the handshake degrades.  So this path must be as fast as possible:
       * NO syslog before M4 is on the wire, and keys are installed only once.
       */

      clock_t m3_t0 = clock_systime_ticks();

      if (!priv->ptk_valid)
        {
          syslog(LOG_WARNING, "nrf7002: M3 but PTK not valid\n");
          return true;
        }

      /* Verify ANonce in M3 matches the ANonce from M1.
       * Per wpa_supplicant process_3_of_4: the AP reuses the M1 ANonce in M3.
       */

      if (memcmp(ekey->nonce, priv->anonce, 32) != 0)
        {
          syslog(LOG_WARNING, "nrf7002: M3 ANonce != M1 — dropping\n");
          return true;
        }

      /* Verify MIC using KCK = ptk[0..15].
       * MIC = HMAC-SHA1(KCK, EAPOL frame with MIC field zeroed)[0..15].
       */

      uint32_t eapol_frame_len = 4 + (uint32_t)ntohs(ehdr->length);
      uint8_t *tmp_frame = kmm_malloc(eapol_frame_len);
      if (tmp_frame == NULL)
        {
          return true;
        }

      memcpy(tmp_frame, frame + 14, eapol_frame_len);
      memset(tmp_frame + 4 + 1 + 2 + 2 + 8 + 32 + 16 + 8 + 8, 0, 16);
      hmac_sha1(priv->ptk, 16, tmp_frame, eapol_frame_len, mic_computed);
      kmm_free(tmp_frame);

      if (memcmp(mic_computed, ekey->mic, 16) != 0)
        {
          syslog(LOG_ERR, "nrf7002: M3 MIC mismatch\n");
          return true;
        }

      /* CRITICAL: send M4 FIRST (plaintext, before key install), with the
       * replay counter copied from THIS M3.  This must happen before any
       * slow operation (key install, syslog) so the AP receives M4 inside
       * its 100 ms window and does not retransmit M3.
       */

      nrf7002_wpa_send_m4(priv, ekey->replay_cnt);
      memcpy(priv->ap_replay, ekey->replay_cnt, 8);

      {
        clock_t m3_t1 = clock_systime_ticks();
        syslog(LOG_INFO, "nrf7002: M3->M4 took %lu ms\n",
               (unsigned long)TICK2MSEC(m3_t1 - m3_t0));
      }

      /* Install pairwise/group keys and authorize the port only once.
       * A retransmitted M3 (AP didn't get our first M4 in time) just needs
       * another M4 — re-installing keys would disturb the live link.
       */

      if (priv->keys_installed)
        {
          syslog(LOG_INFO, "nrf7002: M3 retransmit — re-sent M4 only\n");
          return true;
        }

      syslog(LOG_INFO, "nrf7002: M4 sent, installing keys\n");

      memset(&key_info_fmac, 0, sizeof(key_info_fmac));
      memcpy(key_info_fmac.key.nrf_wifi_key, priv->ptk + 32, 16);
      key_info_fmac.key.nrf_wifi_key_len = 16;
      key_info_fmac.cipher_suite         = 0x000fac04; /* CCMP */
      key_info_fmac.key_type             = NRF_WIFI_KEYTYPE_PAIRWISE;
      key_info_fmac.key_idx              = 0;
      key_info_fmac.valid_fields         = NRF_WIFI_CIPHER_SUITE_VALID |
                                            NRF_WIFI_KEY_VALID |
                                            NRF_WIFI_KEY_TYPE_VALID |
                                            NRF_WIFI_KEY_IDX_VALID;

      fmac_st = nrf_wifi_sys_fmac_add_key(priv->fmac_dev_ctx, priv->vif_idx,
                                           &key_info_fmac,
                                           (const char *)priv->target_bssid);
      if (fmac_st != NRF_WIFI_STATUS_SUCCESS)
        {
          syslog(LOG_ERR, "nrf7002: add PTK failed (%d)\n", (int)fmac_st);
        }
      else
        {
          syslog(LOG_INFO, "nrf7002: PTK installed\n");
        }

      /* Unwrap GTK from key_data (if encrypted) */

      if ((key_info & (1 << 12)) && kdata_len >= 16)
        {
          uint32_t plain_len = kdata_len - 8;
          uint8_t *plain = kmm_malloc(plain_len);
          int unwrap_ret = -1;
          if (plain)
            {
              unwrap_ret = aes_unwrap(priv->ptk + 16, 16, kdata, kdata_len, plain);
            }
          if (plain && unwrap_ret == 0)
            {
              /* Scan all KDEs in plain to find the GTK KDE.
               * M3 key_data may contain multiple packed KDEs, e.g.:
               *   RSN IE (tag=0x30) followed by GTK KDE (tag=0xdd).
               * Skip IEs (tag < 0xdd) and scan until GTK KDE found.
               *
               * KDE format: [0xdd][len][OUI 3B][type 1B][data...]
               * IE  format: [tag][len][data...]
               * GTK KDE OUI = 00-0f-ac, type = 01
               */

              uint32_t pos = 0;
              while (pos + 2 <= plain_len)
                {
                  uint8_t  tag = plain[pos];
                  uint8_t  elen = plain[pos + 1];

                  if (pos + 2 + elen > plain_len)
                    {
                      break;  /* truncated */
                    }

                  if (tag == 0xdd && elen >= 6 &&
                      plain[pos + 2] == 0x00 &&
                      plain[pos + 3] == 0x0f &&
                      plain[pos + 4] == 0xac &&
                      plain[pos + 5] == 0x01)
                    {
                      /* GTK KDE: [0xdd][len][00-0f-ac-01][key_id][rsc...][gtk] */

                      uint8_t  gtk_idx = plain[pos + 6] & 0x03;
                      uint32_t gtk_len = elen - 6;  /* subtract OUI+type+key_id+rsc */

                      /* The GTK is at plain[pos+8], length = elen-6 minus 1B rsc */
                      /* Layout: OUI(3) type(1) key_id(1) rsc(1) = 6 bytes overhead */
                      /* actual gtk starts at pos+8, length = elen - 6 */

                      if (gtk_len >= 8 && gtk_len <= 32)
                        {
                          memcpy(gtk, plain + pos + 8, gtk_len);

                          memset(&key_info_fmac, 0, sizeof(key_info_fmac));
                          memcpy(key_info_fmac.key.nrf_wifi_key, gtk, gtk_len);
                          key_info_fmac.key.nrf_wifi_key_len = gtk_len;
                          key_info_fmac.cipher_suite         = 0x000fac04;
                          key_info_fmac.key_type             = NRF_WIFI_KEYTYPE_GROUP;
                          key_info_fmac.key_idx              = gtk_idx;
                          key_info_fmac.nrf_wifi_flags       =
                            NRF_WIFI_KEY_DEFAULT_TYPE_MULTICAST;
                          key_info_fmac.valid_fields         =
                            NRF_WIFI_CIPHER_SUITE_VALID |
                            NRF_WIFI_KEY_VALID |
                            NRF_WIFI_KEY_TYPE_VALID |
                            NRF_WIFI_KEY_IDX_VALID;

                          fmac_st = nrf_wifi_sys_fmac_add_key(priv->fmac_dev_ctx,
                                                               priv->vif_idx,
                                                               &key_info_fmac,
                                                               NULL);
                          if (fmac_st != NRF_WIFI_STATUS_SUCCESS)
                            {
                              syslog(LOG_ERR, "nrf7002: add GTK failed (%d)\n",
                                     (int)fmac_st);
                            }
                          else
                            {
                              syslog(LOG_INFO, "nrf7002: GTK installed (idx=%u len=%lu)\n",
                                     gtk_idx, (unsigned long)gtk_len);
                            }
                        }
                      break;  /* found GTK KDE */
                    }

                  pos += 2 + elen;  /* advance to next KDE/IE */
                }
            }

          kmm_free(plain);
        }

      {
        bool port_authorized = false;

        /* Authorize the 802.1X controlled port.
         *
         * With control_port=1 in the assoc request, the RPU firmware holds
         * all non-EAPOL TX in an unauthorized state.  After PTK/GTK are
         * installed we must call SET_STATION with NRF_WIFI_STA_FLAG_AUTHORIZED
         * (bit 1) so the RPU opens the data port.  Without this the RPU
         * silently drops every non-EAPOL frame and the AP disconnects us
         * due to inactivity.
         */

        {
          struct nrf_wifi_umac_chg_sta_info chg_sta;
          enum nrf_wifi_status port_st;

          memset(&chg_sta, 0, sizeof(chg_sta));
          memcpy(chg_sta.mac_addr, priv->target_bssid,
                 NRF7002_MAC_ADDR_LEN);

          chg_sta.sta_flags2.nrf_wifi_mask = NRF_WIFI_STA_FLAG_AUTHORIZED;
          chg_sta.sta_flags2.nrf_wifi_set  = NRF_WIFI_STA_FLAG_AUTHORIZED;

          port_st = nrf_wifi_sys_fmac_chg_sta(priv->fmac_dev_ctx,
                                               priv->vif_idx,
                                               &chg_sta);
          if (port_st != NRF_WIFI_STATUS_SUCCESS)
            {
              syslog(LOG_ERR, "nrf7002: port_authorize failed (%d)\n",
                     (int)port_st);
            }
          else
            {
              struct nrf_wifi_sys_fmac_dev_ctx *sys_dev_ctx;
              int peer_id;

              sys_dev_ctx = wifi_dev_priv(priv->fmac_dev_ctx);
              peer_id = nrf_wifi_fmac_peer_get_id(priv->fmac_dev_ctx,
                                                  priv->target_bssid);
              if (sys_dev_ctx != NULL && peer_id >= 0 && peer_id < MAX_PEERS)
                {
                  sys_dev_ctx->tx_config.peers[peer_id].authorized = true;
                }

              syslog(LOG_INFO, "nrf7002: port authorized - data TX enabled\n");
              port_authorized = true;
            }
        }

        /* Mark the handshake complete so a retransmitted M3 only re-sends M4
         * and does not re-install keys or re-authorize the port.
         */

        if (port_authorized)
          {
            priv->keys_installed = 1;
            syslog(LOG_INFO, "nrf7002: EAPOL-4WAY-HS-COMPLETED\n");
          }
      }
    }

  return true;
}

/**
 * nrf7002_wpa_send_m2 - Send EAPOL M2 (STA response to M1)
 */
void nrf7002_wpa_send_m2(struct nrf7002_priv *priv)
{
  /* M2: [eth_hdr(14)] [EAPOL hdr(4)] [eapol_key(95)] [RSN IE(22)] */

  static const uint8_t rsn_ie[] =
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

  uint32_t body_len = sizeof(struct eapol_key) + sizeof(rsn_ie);
  uint32_t total    = 14 + 4 + body_len;
  uint8_t *frame    = kmm_zalloc(total);
  uint8_t  mic[20];

  if (frame == NULL)
    {
      return;
    }

  /* Ethernet header */

  memcpy(frame,     priv->target_bssid, 6);  /* dst = AP */
  memcpy(frame + 6, priv->netdev.d_mac.ether.ether_addr_octet, 6);
  frame[12] = 0x88;
  frame[13] = 0x8e;

  /* EAPOL header */

  frame[14] = 0x02;  /* version 2 */
  frame[15] = 0x03;  /* EAPOL-Key */
  frame[16] = (uint8_t)((body_len >> 8) & 0xff);
  frame[17] = (uint8_t)(body_len & 0xff);

  /* EAPOL-Key */

  struct eapol_key *ek = (struct eapol_key *)(frame + 18);
  ek->desc_type = 2;  /* RSN */

  /* key_info: pairwise(3), MIC(8), version(bits 0-2)=2 (HMAC-SHA1-128+AES) */
  /* bit 0-2: version=2, bit 3=pairwise, bit 8=MIC */

  uint16_t ki = (2) | (1 << 3) | (1 << 8);
  uint8_t *ek_bytes = (uint8_t *)ek;

  nrf7002_wpa_put_be16(ek_bytes + 1, ki);

  /* hostap sends zero Key Length in RSN/WPA2 M2/M4 frames. */

  nrf7002_wpa_put_be16(ek_bytes + 3, 0);

  /* replay counter from M1 */
  memcpy(ek->replay_cnt, priv->ap_replay, 8);

  /* Snonce */
  memcpy(ek->nonce, priv->snonce, 32);

  /* key_data = RSN IE */
  nrf7002_wpa_put_be16(ek_bytes + sizeof(*ek) - 2, sizeof(rsn_ie));
  memcpy((uint8_t *)ek + sizeof(*ek), rsn_ie, sizeof(rsn_ie));

  /* Compute MIC = HMAC-SHA1(KCK, frame+14)[0..15] */

  hmac_sha1(priv->ptk, 16, frame + 14, 4 + body_len, mic);
  memcpy(ek->mic, mic, 16);
  nrf7002_wpa_hexdump("computed-MIC", ek->mic, 16);

  /* Transmit via the NCS control-port path: EAPOL ethertype over data
   * start_xmit with assoc_info.control_port enabled, not mgmt_tx.
   */

  {
    enum nrf_wifi_status st;

    st = nrf7002_wpa_tx_eapol(priv, frame, total);
    syslog(LOG_INFO, "nrf7002: M2 sent st=%d\n", (int)st);
  }

  kmm_free(frame);
}

/**
 * nrf7002_wpa_send_m4 - Send EAPOL M4 (confirms key installation)
 */
void nrf7002_wpa_send_m4(struct nrf7002_priv *priv,
                          const uint8_t replay_cnt[8])
{
  uint32_t body_len = sizeof(struct eapol_key);
  uint32_t total    = 14 + 4 + body_len;
  uint8_t *frame    = kmm_zalloc(total);
  uint8_t  mic[20];

  if (frame == NULL)
    {
      return;
    }

  /* Ethernet header */

  memcpy(frame,     priv->target_bssid, 6);
  memcpy(frame + 6, priv->netdev.d_mac.ether.ether_addr_octet, 6);
  frame[12] = 0x88;
  frame[13] = 0x8e;

  /* EAPOL header */

  frame[14] = 0x02;
  frame[15] = 0x03;
  frame[16] = (uint8_t)((body_len >> 8) & 0xff);
  frame[17] = (uint8_t)(body_len & 0xff);

  /* EAPOL-Key: pairwise, secure, MIC set */

  struct eapol_key *ek = (struct eapol_key *)(frame + 18);
  ek->desc_type = 2;

  uint16_t ki = (2) | (1 << 3) | (1 << 8) | (1 << 9);
  uint8_t *ek_bytes = (uint8_t *)ek;

  nrf7002_wpa_put_be16(ek_bytes + 1, ki);
  nrf7002_wpa_put_be16(ek_bytes + 3, 0);

  memcpy(ek->replay_cnt, replay_cnt, 8);

  /* Compute MIC */

  hmac_sha1(priv->ptk, 16, frame + 14, 4 + body_len, mic);
  memcpy(ek->mic, mic, 16);

  {
    enum nrf_wifi_status st;

    st = nrf7002_wpa_tx_eapol(priv, frame, total);
    syslog(LOG_INFO, "nrf7002: M4 sent st=%d\n", (int)st);
  }

  kmm_free(frame);
}
