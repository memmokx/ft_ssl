#include <libft/string.h>
#include <libft/memory.h>
#include <stddef.h>

static size_t	compute_size(char **list, size_t size, const char *delim)
{
	size_t	total;
	size_t	i;

	if (size == 0)
		return (1);
	i = 0;
	total = (size - 1) * ft_strlen(delim);
	while (i < size)
	{
		total += ft_strlen(list[i]);
		i++;
	}
	return (total + 1);
}

char	*ft_strjoin(char **list, size_t size, const char *delim)
{
	char	*result;
	size_t	i;

	i = 0;
	result = (char *)ft_calloc(compute_size(list, size, delim), sizeof(char));
	if (!result)
		return (NULL);
	while (size > 1 && i < size - 1)
	{
		ft_strcat(result, list[i]);
		ft_strcat(result, (char *)delim);
		i++;
	}
	if (size == 0)
		return (result);
	ft_strcat(result, list[i]);
	return (result);
}
