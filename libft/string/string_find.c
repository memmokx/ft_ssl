#include <libft/string.h>

static char	*find_next_token(char *ptr, t_string token)
{
	while (*ptr)
	{
		if (ft_strncmp(ptr, token.ptr, token.len) == 0)
			return (ptr);
		++ptr;
	}
	return (NULL);
}

char	*string_next_token(t_string *str, t_string token)
{
	static char	*base_ptr;
	static char	*ptr;

	if (!str)
		return (NULL);
	if (base_ptr != str->ptr)
	{
		base_ptr = str->ptr;
		ptr = str->ptr;
	}
	if (!ptr)
		ptr = base_ptr;
	ptr = find_next_token(str->ptr, token);
	return (ptr);
}

bool	string_starts_with(t_string str, t_string to_find)
{
	size_t	i;

	if (!str.ptr || !to_find.ptr)
		return (false);
	if (to_find.len > str.len)
		return (false);
	i = 0;
	while (i < to_find.len && str.ptr[i] == to_find.ptr[i])
		i++;
	if (i == to_find.len)
		return (true);
	return (((uint8_t)str.ptr[i] - (uint8_t)to_find.ptr[i]) == 0);
}

int	ft_strfind(const char *str, const char *to_find)
{
	int	i;
	int	pattern_len;

	if (!str || !to_find)
		return (-1);
	pattern_len = (int)ft_strlen(to_find);
	i = 0;
	while (str[i])
	{
		if (ft_strncmp(str + i, to_find, pattern_len) == 0)
			return (i);
		++i;
	}
	return (-1);
}
