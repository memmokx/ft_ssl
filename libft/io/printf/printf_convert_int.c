#include "ft_printf.h"

int	printf_convert_int(t_string *buffer, int64_t n)
{
	t_string	tmp;

	tmp = ft_itoa(n);
	if (tmp.ptr == NULL)
		return (STRING_ALLOC_FAILURE);
	return (string_append_string(buffer, &tmp, true));
}

int	printf_convert_unsigned(t_string *buffer, uint64_t n)
{
	t_string	tmp;

	tmp = ft_utoa(n);
	if (tmp.ptr == NULL)
		return (STRING_ALLOC_FAILURE);
	return (string_append_string(buffer, &tmp, true));
}
