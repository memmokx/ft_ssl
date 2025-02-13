#include <libft/string.h>
#include <malloc.h>

void	split_destroy(t_split *split)
{
	size_t	i;

	if (!split || !split->strs)
		return ;
	i = 0;
	while (i < split->size)
	{
		string_destroy(&split->strs[i]);
		i++;
	}
	free(split->strs);
	split->strs = NULL;
	split->size = 0;
}

static bool	allocate_split(t_string *str, t_split *split, char c)
{
	int		i;
	int		count;
	bool	new_str;

	if (!split)
		return (false);
	i = 0;
	new_str = true;
	count = 0;
	while (str->ptr[i])
	{
		if (str->ptr[i++] == c)
			new_str = true;
		else if (new_str)
		{
			new_str = false;
			++count;
		}
	}
	if (count > 0)
		split->strs = malloc(count * sizeof(t_string));
	if (!split->strs)
		return (false);
	split->size = count;
	return (true);
}

static int	next_str_index(const char *str, char c)
{
	int		i;

	i = 0;
	while (str[i])
	{
		if (str[i] != c)
			return (i);
		++i;
	}
	return (-1);
}

static int	next_str_size(const char *str, char c)
{
	int	i;

	i = 0;
	while (str[i])
	{
		if (str[i] == c)
			return (i);
		++i;
	}
	return (i);
}

t_split	string_split(t_string *str, char c)
{
	t_split	split;
	char	*ptr;
	size_t	i;
	size_t	j;

	split = (t_split){0};
	if (!str || !str->ptr)
		return ((t_split){0});
	if (!allocate_split(str, &split, c))
		return ((t_split){0});
	ptr = str->ptr;
	j = 0;
	i = 0;
	while (j < split.size)
	{
		i += next_str_index(ptr + i, c);
		split.strs[j] = string_slice(str, i, i + next_str_size(ptr + i, c));
		i += next_str_size(ptr + i, c);
		++j;
	}
	return (split);
}
