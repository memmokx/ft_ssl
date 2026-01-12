#include <libft.h>
#include <unistd.h>

void	ft_putchar(char c)
{
	(void)write(1, &c, 1);
}
