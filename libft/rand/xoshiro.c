#include <libft/rand.h>

static uint64_t	split_mix_next(struct s_split_mix_64 *sp)
{
	uint64_t	z;

	sp->s += 0x9e3779b97f4a7c15;
	z = sp->s;
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
	return (z ^ (z >> 31));
}

static uint64_t	rotl(const uint64_t x, int k)
{
	return ((x << k) | (x >> (64 - k)));
}

t_xoshiro_256	xoshiro256_init(uint64_t seed, int jump)
{
	int						i;
	t_xoshiro_256			s;
	struct s_split_mix_64	sp;

	i = 0;
	sp = (struct s_split_mix_64){seed};
	s.state[0] = split_mix_next(&sp);
	s.state[1] = split_mix_next(&sp);
	s.state[2] = split_mix_next(&sp);
	s.state[3] = split_mix_next(&sp);
	while (i < jump)
	{
		xoshiro256_next(&s);
		i++;
	}
	return (s);
}

uint64_t	xoshiro256_next(t_xoshiro_256 *x)
{
	uint64_t	result;
	uint64_t	t;

	result = x->state[0] + x->state[3];
	t = x->state[1] << 17;
	x->state[2] ^= x->state[0];
	x->state[3] ^= x->state[1];
	x->state[1] ^= x->state[2];
	x->state[0] ^= x->state[3];
	x->state[2] ^= t;
	x->state[3] = rotl(x->state[3], 45);
	return (result);
}
