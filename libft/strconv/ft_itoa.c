#include <libft/strconv.h>

t_string	ft_itoa(int n)
{
	return (ft_itoa_base(n, DEC_BASE, 10));
}

t_string	ft_itoa_base(int n, const char *base, int radix)
{
	t_string	str;

	if (n < 0)
	{
		str = ft_utoa_base((uint64_t)(-n), base, radix);
		if (str.ptr)
			string_insert_char(&str, '-', 0);
	}
	else
		str = ft_utoa_base((uint64_t)n, base, radix);
	return (str);
}
