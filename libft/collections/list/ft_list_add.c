#include <libft/collections.h>

void	ft_list_add_front(t_list **list, t_list *new)
{
	t_list	*tmp;

	tmp = *list;
	*list = new;
	new->next = tmp;
}

void	ft_list_add_back(t_list **list, t_list *new)
{
	t_list	*tmp;

	if (!list)
		return ;
	if (*list == NULL)
	{
		*list = new;
		return ;
	}
	tmp = ft_list_last(*list);
	tmp->next = new;
}
