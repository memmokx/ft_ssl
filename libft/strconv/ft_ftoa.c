#include <libft/strconv.h>

static int	ftoa_decimals(t_string *buffer, uint64_t decimals,
			uint64_t n_decimals)
{
	if (n_decimals / 10 != 1)
	{
		if (!ftoa_decimals(buffer, decimals / 10, n_decimals / 10))
			return (STRING_ALLOC_FAILURE);
	}
	return (string_append_char(buffer, (decimals % 10) + '0'));
}

static void	ftoa_internal(t_string *buffer, uint64_t n_decimals,
			uint64_t decimals, uint64_t units)
{
	t_string	tmp;

	tmp = ft_utoa(units);
	if (!string_append_string(buffer, &tmp, true))
	{
		string_destroy(buffer);
		return ;
	}
	if (!string_append_char(buffer, '.'))
	{
		string_destroy(buffer);
		return ;
	}
	if (!ftoa_decimals(buffer, decimals, n_decimals))
		string_destroy(buffer);
}

t_string	ft_ftoa(double f)
{
	const uint64_t	n_decimals = 1000000000000;
	uint64_t		decimals;
	uint64_t		units;
	t_string		tmp;

	if (f < 0)
	{
		decimals = (uint64_t)(f * (double)-n_decimals) % n_decimals;
		units = (uint64_t)(f * -1);
	}
	else
	{
		decimals = (uint64_t)(f * (double)n_decimals) % n_decimals;
		units = (uint64_t)(f * 1);
	}
	tmp = string_new_capacity(32);
	if (!tmp.ptr)
		return (tmp);
	if (f < 0)
		string_append_char(&tmp, '-');
	ftoa_internal(&tmp, n_decimals, decimals, units);
	return (tmp);
}
