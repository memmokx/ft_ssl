#include <libft.h>
#include <unistd.h>

void	ft_putstr_fd(int fd, const char *str)
{
	write(fd, str, ft_strlen(str));
}
