#ifndef RAND_H
# define RAND_H

# include <stdint.h>

struct			s_split_mix_64
{
	uint64_t	s;
};

// xoshiro256+ Implementation
// see: https://prng.di.unimi.it/xoshiro256plus.c

typedef struct s_xoshiro_256
{
	uint64_t	state[4];
}				t_xoshiro_256;

// `xoshiro256_init` initialize the internal state
// of the PRNG based of the provided `seed` using the SplitMix64 algorithm.
// The `jump` is how many calls to `*_next` it will call to scramble the
// internal state.
t_xoshiro_256	xoshiro256_init(uint64_t seed, int jump);
uint64_t		xoshiro256_next(t_xoshiro_256 *x);

// `xoshiro_double` generate a 64-bit float in the range [0, 1] as described
// here: https://prng.di.unimi.it/random_real.c
// A double precision floating point (float64) number reserve:
// - 1 bit for the sign
// - 11 bits for the exponent
// - 52 bits for the fractional part (mantissa)
// `xoshiro_double` generate a random 64-bit number shifts it right by 11 bits
// and then multiply it by `0x1.0p-53` (1.0 / (1L << 53)) to obtain a double.
double			xoshiro_double(t_xoshiro_256 *x);

#endif