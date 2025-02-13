#include <libft/memory.h>
#include <libft/string.h>

int	string_append(t_string *str, const char *append)
{
	size_t	len;

	if (!append || !str->ptr)
		return (STRING_ALLOC_FAILURE);
	len = ft_strlen(append);
	if (str->len + len >= str->cap)
	{
		if (string_grow(str, str->len + len) != STRING_ALLOC_SUCCESS)
			return (STRING_ALLOC_FAILURE);
	}
	ft_memcpy(str->ptr + str->len, append, len);
	str->len += len;
	str->ptr[str->len] = 0;
	return (STRING_ALLOC_SUCCESS);
}

int	string_append_char(t_string *str, char c)
{
	if (!str->ptr)
		return (STRING_ALLOC_FAILURE);
	if (str->len + 1 >= str->cap)
	{
		if (string_grow(str, str->len + 1) != STRING_ALLOC_SUCCESS)
			return (STRING_ALLOC_FAILURE);
	}
	str->ptr[str->len] = c;
	str->len++;
	str->ptr[str->len] = 0;
	return (STRING_ALLOC_SUCCESS);
}

int	string_append_string(t_string *str, t_string *append, bool destroy)
{
	if (!append->ptr || !str->ptr)
		return (STRING_ALLOC_FAILURE);
	if (str->len + append->len >= str->cap)
	{
		if (string_grow(str, str->len + append->len) != STRING_ALLOC_SUCCESS)
		{
			if (destroy)
				string_destroy(append);
			return (STRING_ALLOC_FAILURE);
		}
	}
	ft_memcpy(str->ptr + str->len, append->ptr, append->len);
	str->len += append->len;
	str->ptr[str->len] = 0;
	if (destroy)
		string_destroy(append);
	return (STRING_ALLOC_SUCCESS);
}
