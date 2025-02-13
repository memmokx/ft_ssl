#include "ft_printf.h"

int	printf_convert_hex(t_string *buffer, unsigned int n)
{
	t_string	tmp;

	tmp = ft_utoa_base(n, HEX_BASE, 16);
	if (tmp.ptr == NULL)
		return (STRING_ALLOC_FAILURE);
	return (string_append_string(buffer, &tmp, true));
}

int	printf_convert_hex_upper(t_string *buffer, unsigned int n)
{
	t_string	tmp;

	tmp = ft_utoa_base(n, HEX_BASE_UPPER, 16);
	if (tmp.ptr == NULL)
		return (STRING_ALLOC_FAILURE);
	return (string_append_string(buffer, &tmp, true));
}
