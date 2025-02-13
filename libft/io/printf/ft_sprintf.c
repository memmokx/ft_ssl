#include "ft_printf.h"
#include <libft/string.h>

t_string	ft_sprintf(const char *format, ...)
{
	va_list	args;
	int		ret;
	char	*buffer;

	if (!format)
		return ((t_string){0});
	va_start(args, format);
	ret = ft_vsprintf(&buffer, format, args);
	va_end(args);
	if (ret == -1)
		return ((t_string){0});
	return (string_new_owned(buffer));
}
