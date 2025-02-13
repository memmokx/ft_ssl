#ifndef COLLECTIONS_H
# define COLLECTIONS_H

# include <stddef.h>
# include "string.h"

typedef struct s_list
{
	void			*data;
	struct s_list	*next;
}					t_list;

t_list				*ft_list_new(void *value);
void				ft_list_add_front(t_list **list, t_list *new);
void				ft_list_add_back(t_list **list, t_list *new);
t_list				*ft_list_last(t_list *list);
void				ft_list_clear(t_list **list, void (*del)(void *));
void				ft_list_iter(t_list *list, void (*f)(void *));
void				ft_list_del_one(t_list *list, void (*del)(void *));
void				ft_list_noop(void *c);

// string vector
typedef struct s_string_node
{
	t_string				str;
	struct s_string_node	*next;
}	t_str_node;

typedef struct s_string_vector
{
	size_t		size;
	t_str_node	*start;
}	t_str_vec;

t_str_vec			str_vec_new(void);
void				str_vec_push_back(t_str_vec *vec, t_string str);
void				str_vec_pop(t_str_vec *vec);
t_string			str_vec_at(t_str_vec *vec, size_t idx);
void				str_vec_destroy(t_str_vec *vec, bool retain);

#endif
