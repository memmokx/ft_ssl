#ifndef GET_NEXT_LINE_H
# define GET_NEXT_LINE_H

# include <stddef.h>
# include <unistd.h>
# include <stdlib.h>
# include <libft.h>

# ifndef BUFFER_SIZE
#  define BUFFER_SIZE 128
# endif

# define INITIAL_BUFFER_SIZE 256

struct s_reader
{
	char	*read_buffer;
	char	*grow_buffer;
	size_t	size;
	size_t	cursor;
	int		last_read;
	int		at_eof;
};

char	*get_next_line(int fd);

int		init_reader(struct s_reader *reader);
int		reader_grow(struct s_reader *reader, int additional);
int		reader_fill(struct s_reader *reader, int remaining);

int		ft_sstrchr(char *buf, char c, size_t size);

#endif
