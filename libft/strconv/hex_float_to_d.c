#include <libft/strconv.h>

static int	index_of(const char *table, char c)
{
	int	i;

	i = 0;
	while (table[i])
	{
		if (table[i] == c)
			return (i);
		i++;
	}
	return (-1);
}

static uint64_t	atoi_hex(const char *str)
{
	int			i;
	uint64_t	value;

	value = 0;
	i = 0;
	while (str[i] && index_of(HEX_BASE, str[i]) != -1)
	{
		value *= 16;
		value += index_of(HEX_BASE, str[i]);
		i++;
	}
	return (value);
}

double	hex_float_to_d(const char *str)
{
	const uint64_t	cast = atoi_hex(str);
        const void      *c = &cast;
	return (*(double *)c);
}
