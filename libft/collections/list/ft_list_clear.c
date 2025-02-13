#include <libft/collections.h>
#include <stdlib.h>

void	ft_list_clear(t_list **list, void (*del)(void *))
{
	t_list	*n;

	if (!del)
		return ;
	while (list && *list)
	{
		del((*list)->data);
		n = (*list)->next;
		free(*list);
		*list = n;
	}
}
