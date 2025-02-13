#include <libft/string.h>

t_string	string_concat(t_string *s1, t_string *s2, char destroy)
{
	t_string	result;

	result = string_new_capacity(s1->len + s2->len + 1);
	string_append_string(&result, s1, destroy >> 1 & 0b01);
	string_append_string(&result, s2, destroy & 0b01);
	return (result);
}
