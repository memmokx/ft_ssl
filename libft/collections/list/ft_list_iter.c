#include <libft/collections.h>

void	ft_list_iter(t_list *list, void (*f)(void *))
{
	if (!list || !f)
		return ;
	f(list->data);
	list = list->next;
	while (list != NULL)
	{
		f(list->data);
		list = list->next;
	}
}
