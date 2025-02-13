#include "ft_printf.h"
#include <stdlib.h>
#include <unistd.h>

int	ft_fprintf(int fd, const char *format, ...)
{
	va_list	args;
	int		ret;
	char	*buffer;

	if (!format)
		return (-1);
	va_start(args, format);
	ret = ft_vsprintf(&buffer, format, args);
	if (ret != -1)
	{
		write(fd, buffer, ret);
		free(buffer);
	}
	va_end(args);
	return (ret);
}
