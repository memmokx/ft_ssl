#ifndef STRING_H
# define STRING_H

# include <stdbool.h>
# include <stddef.h>
# include <stdint.h>
# include <stdlib.h>
# include <unistd.h>

size_t							ft_strlen(const char *str);
char							*ft_strjoin(char **list, size_t size,
									const char *delim);
void							ft_strcat(char *buffer, char *str);
char							*ft_strdup(const char *str);
int								ft_strcmp(const char *s1, const char *s2);
int								ft_strncmp(const char *s1, const char *s2,
									size_t n);
int								ft_strfind(const char *str,
									const char *to_find);
ssize_t							ft_index_of(const char *str, const char c);

# define STRING_ALLOC_FAILURE 0
# define STRING_ALLOC_SUCCESS 1

typedef struct s_string			t_string;
typedef struct s_split_result	t_split;
typedef struct s_string
{
	char						*ptr;
	size_t						len;
	size_t						cap;
}								t_string;

typedef struct s_split_result
{
	size_t						size;
	t_string					*strs;
}								t_split;

void							split_destroy(t_split *split);

t_string						string_new(const char *str);
t_string						string_new_owned(char *str);
t_string						string_new_capacity(size_t capacity);
void							string_destroy(t_string *str);

t_string						string_slice(t_string *str, size_t start,
									size_t end);

int								string_append(t_string *str,
									const char *append);
int								string_append_char(t_string *str, char c);
int								string_append_string(t_string *str,
									t_string *append, bool destroy);
t_string						string_concat(t_string *s1, t_string *s2,
									char destroy);
int								string_insert_char(t_string *str, char c,
									size_t index);
t_split							string_split(t_string *str, char c);
t_string						string_trim(t_string *str, const char *cutset,
									bool destroy);
bool							string_equal(const t_string *str1, const t_string *str2);
ssize_t							string_index_of(t_string str, char c);
bool							string_starts_with(t_string str,
									t_string to_find);
char							*string_next_token(t_string *str,
									t_string token);
size_t							string_find_str(t_string *str,
									t_string to_find);
int								string_find_char(t_string *str,
									const char to_find);

//			Internal string methods

int								string_grow(t_string *str, size_t new_cap);

// Iterator

typedef struct s_iterator_scalar
{
	char						scalar;
	size_t						offset;
	t_string					string;
}								t_iterator_scalar;

t_iterator_scalar				iterator_scalar_new(t_string string,
									char scalar);

/*!
 * @param iterator The iterator instance.
 * @param dupe If the result string should be duped (allocation required)
 * @return The next string in the iterator, a NULL .ptr field indicates
 * we reached the end or an error occured, the result .ptr is a C-String only
 * if `dupe` was set to true.
 */
t_string						iterator_scalar_next(
									t_iterator_scalar *iterator,
									bool dupe);

#define libft_static_string(str) (t_string){.ptr = str, .len = sizeof(str) - 1, .cap = sizeof(str)}
typedef t_string string;

#endif
