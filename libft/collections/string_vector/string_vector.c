#include <libft/collections.h>
#include <libft/memory.h>

t_str_vec	str_vec_new(void)
{
	return ((t_str_vec){0});
}

void	str_vec_push_back(t_str_vec *vec, t_string str)
{
	t_str_node	*node;

	if (!vec)
		return ;
	if (vec->start)
	{
		node = vec->start;
		while (node->next)
			node = node->next;
		node->next = ft_calloc(1, sizeof(t_str_node));
		if (!node->next)
			return ;
		node = node->next;
	}
	else
	{
		vec->start = ft_calloc(1, sizeof(t_str_node));
		if (!vec->start)
			return ;
		node = vec->start;
	}
	node->str = str;
	node->next = NULL;
	vec->size++;
}

void	str_vec_pop(t_str_vec *vec)
{
	t_str_node	*next;

	if (!vec || !vec->start)
		return ;
	next = vec->start->next;
	if (vec->start->str.ptr)
		string_destroy(&vec->start->str);
	free(vec->start);
	vec->start = next;
	vec->size--;
}

t_string	str_vec_at(t_str_vec *vec, size_t idx)
{
	t_str_node	*node;
	size_t		i;

	if (!vec || !vec->start || idx >= vec->size)
		return ((t_string){0});
	i = 0;
	node = vec->start;
	while (node && i != idx)
	{
		node = node->next;
		++i;
	}
	if (node && i == idx)
		return (node->str);
	return ((t_string){0});
}

void	str_vec_destroy(t_str_vec *vec, bool retain)
{
	t_str_node	*node;
	t_str_node	*tmp;

	if (!vec || !vec->start)
		return ;
	tmp = NULL;
	node = vec->start;
	while (node)
	{
		tmp = node;
		node = node->next;
		if (tmp->str.ptr && !retain)
			string_destroy(&tmp->str);
		free(tmp);
	}
	vec->start = NULL;
	vec->size = 0;
}
