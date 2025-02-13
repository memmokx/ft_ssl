#include <libft/collections.h>
#include <stdlib.h>

void	ft_list_del_one(t_list *list, void (*del)(void *))
{
	if (!list || !del)
		return ;
	del(list->data);
	free(list);
}
