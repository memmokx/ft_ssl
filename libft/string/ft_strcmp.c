#include <libft/string.h>

int	ft_strcmp(const char *s1, const char *s2)
{
	size_t			i;
	unsigned char	*u1;
	unsigned char	*u2;

	i = 0;
	u1 = (unsigned char *)s1;
	u2 = (unsigned char *)s2;
	while (s1[i] != 0 && u1[i] == u2[i])
		i++;
	return (u1[i] - u2[i]);
}
