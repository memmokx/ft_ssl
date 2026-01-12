#include <libft.h>
#include <unistd.h>

void	ft_putstr(const char *str)
{
	(void)write(1, str, ft_strlen(str));
}
