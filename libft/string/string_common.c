#include <libft/string.h>
#include <libft/memory.h>

t_string	string_slice(t_string *str, size_t start, size_t end)
{
	t_string	tmp;

	if (!str->ptr)
		return ((t_string){0});
	if (start > str->cap || end > str->cap || start > end)
		return ((t_string){0});
	tmp = string_new_capacity((end - start) + 1);
	if (!tmp.ptr)
		return (tmp);
	ft_memmove(tmp.ptr, &str->ptr[start], end - start);
	tmp.len = end - start;
	tmp.ptr[tmp.len] = 0;
	return (tmp);
}

static int	in_set(char c, char const *set)
{
	while (*set)
	{
		if (*set == c)
			return (1);
		set++;
	}
	return (0);
}

t_string	string_trim(t_string *str, const char *cutset, bool destroy)
{
	size_t		i;
	size_t		end;
	t_string	string;

	i = 0;
	while (i < str->len && in_set(str->ptr[i], cutset))
		i++;
	end = str->len;
	while (end > i && in_set(str->ptr[end - 1], cutset))
		end--;
	string = string_slice(str, i, end);
	if (destroy)
		string_destroy(str);
	return (string);
}

bool	string_equal(const t_string *str1, const t_string *str2)
{
	if (!str1 || !str2 || !str1->ptr || !str2->ptr)
		return (false);
	if (ft_strcmp(str1->ptr, str2->ptr) == 0)
		return (true);
	return (false);
}

ssize_t	string_index_of(const t_string str, char c)
{
	size_t	i;

	if (!str.ptr)
		return (-1);
	i = 0;
	while (i < str.len)
	{
		if (str.ptr[i] == c)
			return ((ssize_t)i);
		i++;
	}
	return (-1);
}
