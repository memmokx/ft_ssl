#include <libft/memory.h>
#include <libft/string.h>

int	string_insert_char(t_string *str, char c, size_t index)
{
	if (index > str->len)
		return (STRING_ALLOC_SUCCESS);
	if (str->len + 1 >= str->cap)
	{
		if (string_grow(str, str->len + 1) != STRING_ALLOC_SUCCESS)
			return (STRING_ALLOC_FAILURE);
	}
	ft_memmove(str->ptr + index + 1, str->ptr + index, str->len - index);
	str->ptr[index] = c;
	str->len++;
	str->ptr[str->len] = 0;
	return (STRING_ALLOC_SUCCESS);
}
