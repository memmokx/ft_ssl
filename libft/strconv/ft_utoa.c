#include <libft/strconv.h>

static inline size_t	conversion_len(uint64_t n, int radix)
{
	size_t	len;

	len = 0;
	while (n)
	{
		n /= radix;
		len++;
	}
	return (len);
}

static int	utoa_base_internal(t_string *str, uint64_t n, const char *base,
		int radix)
{
	if (n / (uint64_t)radix != 0)
	{
		if (!utoa_base_internal(str, n / radix, base, radix))
			return (STRING_ALLOC_FAILURE);
	}
	return (string_append_char(str, base[n % radix]));
}

t_string	ft_utoa(uint64_t n)
{
	return (ft_utoa_base(n, DEC_BASE, 10));
}

t_string	ft_utoa_base(uint64_t n, const char *base, int radix)
{
	const size_t	len = conversion_len(n, radix);
	t_string		str;

	str = string_new_capacity(len + 1);
	if (!str.ptr)
		return (str);
	if (!utoa_base_internal(&str, n, base, radix))
		string_destroy(&str);
	return (str);
}
