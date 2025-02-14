#ifndef FSSL_DEFINES_H
#define FSSL_DEFINES_H

#define fssl_force_inline __attribute__((always_inline)) inline

#define fssl_le_write_u64(p, n) \
  (p)[7] = ((n) >> 56) & 0xff;  \
  (p)[6] = ((n) >> 48) & 0xff;  \
  (p)[5] = ((n) >> 40) & 0xff;  \
  (p)[4] = ((n) >> 32) & 0xff;  \
  (p)[3] = ((n) >> 24) & 0xff;  \
  (p)[2] = ((n) >> 16) & 0xff;  \
  (p)[1] = ((n) >> 8) & 0xff;   \
  (p)[0] = (n) & 0xff;

#define fssl_le_write_u32(p, n) \
  (p)[3] = ((n) >> 24) & 0xff;  \
  (p)[2] = ((n) >> 16) & 0xff;  \
  (p)[1] = ((n) >> 8) & 0xff;   \
  (p)[0] = (n) & 0xff;

#define fssl_le_read_u32(p)                                                  \
  ((uint32_t)((p)[0]) | (uint32_t)((p)[1] << 8) | (uint32_t)((p)[2] << 16) | \
   (uint32_t)((p)[3] << 24))

#endif
