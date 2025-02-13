#include <libft/string.h>

void	ft_strcat(char *buffer, char *str)
{
	int	i;
	int	j;

	i = ft_strlen(buffer);
	j = 0;
	while (str[j])
	{
		buffer[i + j] = str[j];
		j++;
	}
	buffer[i + j] = 0;
}
