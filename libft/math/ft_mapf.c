#include <libft.h>

double	ft_mapf(const double in[2], const double out[2], double val)
{
	return ((val - in[0]) * (out[1] - out[0]) / (in[1] - in[0]) + out[0]);
}
