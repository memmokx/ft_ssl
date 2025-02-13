#include <libft/memory.h>
#include <libft/string.h>
#include <stdlib.h>

t_string	string_new(const char *str)
{
	t_string	string;
	size_t		len;

	string = (t_string){0};
	if (!str)
		return (string);
	len = ft_strlen(str);
	string.ptr = ft_calloc(sizeof(char), len + 1);
	if (!string.ptr)
		return (string);
	ft_memcpy(string.ptr, str, len);
	string.len = len;
	string.cap = len + 1;
	return (string);
}

t_string	string_new_owned(char *str)
{
	t_string	string;
	size_t		len;

	string = (t_string){0};
	if (!str)
		return (string);
	len = ft_strlen(str);
	string.ptr = str;
	string.len = len;
	string.cap = len + 1;
	return (string);
}

t_string	string_new_capacity(size_t capacity)
{
	t_string	string;

	string = (t_string){0};
	string.ptr = ft_calloc(sizeof(char), capacity);
	if (!string.ptr)
		return (string);
	string.len = 0;
	string.cap = capacity;
	return (string);
}

void	string_destroy(t_string *string)
{
	if (string->ptr)
		free(string->ptr);
	string->ptr = NULL;
	string->len = 0;
	string->cap = 0;
}
