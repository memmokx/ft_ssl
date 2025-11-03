#include "ft_printf.h"
#include <libft/string.h>
#include <stddef.h>

static inline int	printf_push_arg(t_string *buffer, char specifier,
		va_list args,int flags, int *result)
{
	if (specifier == 'c')
		*result = string_append_char(buffer, va_arg(args, int));
	else if (specifier == 's')
		*result = printf_convert_string(buffer, va_arg(args, char *));
	else if (specifier == '%')
		*result = string_append_char(buffer, '%');
	else if (specifier == 'd' || specifier == 'i') {
	  if (flags == 0)
	    *result = printf_convert_int(buffer, va_arg(args, int));
	  if (flags == 1)
	    *result = printf_convert_int(buffer, va_arg(args, long int));
	  if (flags == 2)
	    *result = printf_convert_int(buffer, va_arg(args, long long int));
	}
	else if (specifier == 'u') {
	  if (flags == 0)
	    *result = printf_convert_unsigned(buffer, va_arg(args, unsigned int));
	  if (flags == 1)
	    *result = printf_convert_unsigned(buffer, va_arg(args, unsigned long int));
	  if (flags == 2)
	    *result = printf_convert_unsigned(buffer, va_arg(args, unsigned long long int));
	  if (flags == 3)
	    *result = printf_convert_unsigned(buffer, va_arg(args, size_t));
	}
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

static const char *printf_read_flags(const char *fmt,int *flags) {
  *flags = 0;

  if (*fmt == 'l')
  {
    *flags += 1;
    fmt++;
  }

  if (*fmt == 'l')
  {
    *flags += 1;
    fmt++;
  }

  if (*fmt == 'z')
  {
    *flags = 3;
    fmt++;
  }

  return fmt;
}

int	ft_vsprintf(char **out, const char *format, va_list args)
{
	t_string	buffer;
        int                     flags;
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
		        format = printf_read_flags(format, &flags);
			if (printf_push_arg(&buffer, *format, args, flags, &alloc_result) == -1
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
