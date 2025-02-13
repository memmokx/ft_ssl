#include <libft/string.h>

int	ft_strncmp(const char *s1, const char *s2, size_t n)
{
	size_t	i;

	if (!s1 || !s2)
		return (0);
	i = 0;
	while (s1[i] && i < n && s1[i] == s2[i])
		++i;
	if (i == n)
		return (0);
	return (s1[i] - s2[i]);
}
