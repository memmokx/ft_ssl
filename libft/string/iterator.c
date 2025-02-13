#include <libft/string.h>

t_iterator_scalar	iterator_scalar_new(t_string string, char scalar)
{
	return ((t_iterator_scalar){
		.scalar = scalar,
		.offset = 0,
		.string = string,
	});
}

t_string	iterator_scalar_next(t_iterator_scalar *iterator, bool dupe)
{
	size_t		i;
	t_string	result;

	if (!iterator || !iterator->string.ptr
		|| iterator->offset > iterator->string.len)
		return ((t_string){0});
	i = 0;
	result = (t_string){0};
	while (i + iterator->offset < iterator->string.len)
	{
		if (iterator->string.ptr[i + iterator->offset] == iterator->scalar)
		{
			i++;
			if (dupe)
				result = string_slice(&iterator->string, iterator->offset,
						iterator->offset + i);
			else
				result = (t_string){
					&iterator->string.ptr[iterator->offset], i, i};
			iterator->offset += i;
			break ;
		}
		i++;
	}
	return (result);
}
