#include <libft/rand.h>

double	xoshiro_double(t_xoshiro_256 *x)
{
	static uint64_t	constant = 0x3ca0000000000000;

	return ((xoshiro256_next(x) >> 11) * (*(double *)&constant));
}
