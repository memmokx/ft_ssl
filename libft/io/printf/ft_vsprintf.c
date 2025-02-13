#include "ft_printf.h"
#include <libft/string.h>

static inline int	printf_push_arg(t_string *buffer, char specifier,
		va_list args, int *result)
{
	if (specifier == 'c')
		*result = string_append_char(buffer, va_arg(args, int));
	else if (specifier == 's')
		*result = printf_convert_string(buffer, va_arg(args, char *));
	else if (specifier == '%')
		*result = string_append_char(buffer, '%');
	else if (specifier == 'd' || specifier == 'i')
		*result = printf_convert_int(buffer, va_arg(args, int));
	else if (specifier == 'u')
		*result = printf_convert_unsigned(buffer, va_arg(args, unsigned int));
	else if (specifier == 'x')
		*result = printf_convert_hex(buffer, va_arg(args, unsigned int));
	else if (specifier == 'X')
		*result = printf_convert_hex_upper(buffer, va_arg(args, unsigned int));
	else if (specifier == 'p')
		*result = printf_convert_pointer(buffer, va_arg(args, void *));
	else if (specifier == 'f')
		*result = printf_convert_float(buffer, va_arg(args, double));
	else if (specifier == 'g')
		*result = printf_convert_float_hex(buffer, va_arg(args, double));
	else
		return (-1);
	return (0);
}

int	ft_vsprintf(char **out, const char *format, va_list args)
{
	t_string	buffer;
	int			alloc_result;

	alloc_result = STRING_ALLOC_SUCCESS;
	buffer = string_new_capacity(ft_strlen(format));
	if (!buffer.ptr)
		return (-1);
	while (*format)
	{
		if (*format == '%')
		{
			format++;
			if (printf_push_arg(&buffer, *format, args, &alloc_result) == -1
				|| alloc_result == STRING_ALLOC_FAILURE)
			{
				string_destroy(&buffer);
				return (-1);
			}
		}
		else
			string_append_char(&buffer, *format);
		format++;
	}
	*out = buffer.ptr;
	return ((int)buffer.len);
}
