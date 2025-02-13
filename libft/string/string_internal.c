#include <libft/string.h>
#include <libft/memory.h>
#include <stdlib.h>

static inline size_t	grow_capacity(size_t current, size_t minimum)
{
	size_t	new_cap;

	new_cap = current;
	while (new_cap <= minimum)
		new_cap += new_cap / 2 + 8;
	return (new_cap);
}

int	string_grow(t_string *string, size_t new_cap)
{
	char	*new_ptr;

	new_cap = grow_capacity(string->cap, new_cap);
	new_ptr = ft_calloc(sizeof(char), new_cap);
	if (!new_ptr)
		return (STRING_ALLOC_FAILURE);
	ft_memcpy(new_ptr, string->ptr, string->len);
	free(string->ptr);
	string->ptr = new_ptr;
	string->cap = new_cap;
	return (STRING_ALLOC_SUCCESS);
}
