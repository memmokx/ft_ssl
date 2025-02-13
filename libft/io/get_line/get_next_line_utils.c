#include "get_next_line.h"

int	ft_sstrchr(char *buf, char c, size_t size)
{
	int	i;

	i = 0;
	while (i < (int)size && buf[i])
	{
		if (buf[i] == c)
			return (i);
		i++;
	}
	return (-1);
}

int	init_reader(struct s_reader *reader)
{
	reader->read_buffer = (char *)ft_calloc(BUFFER_SIZE, sizeof(char));
	if (!reader->read_buffer)
		return (0);
	reader->grow_buffer = (char *)ft_calloc(INITIAL_BUFFER_SIZE, sizeof(char));
	if (!reader->grow_buffer)
		return (0);
	reader->size = INITIAL_BUFFER_SIZE;
	reader->cursor = 0;
	return (1);
}

int	reader_grow(struct s_reader *reader, int additional)
{
	char	*old;
	size_t	old_size;
	int		i;

	i = 0;
	old_size = reader->size;
	old = reader->grow_buffer;
	while (reader->size <= old_size + additional)
		reader->size += INITIAL_BUFFER_SIZE * 2;
	reader->grow_buffer = (char *)ft_calloc(reader->size, sizeof(char));
	if (!reader->grow_buffer)
	{
		free(old);
		return (0);
	}
	while (i < (int)reader->cursor)
	{
		reader->grow_buffer[i] = old[i];
		i++;
	}
	free(old);
	return (1);
}

int	reader_fill(struct s_reader *reader, int remaining)
{
	int	i;

	i = 0;
	if (reader->cursor + remaining > reader->size)
		if (!reader_grow(reader, (reader->cursor + remaining) - reader->size))
			return (0);
	while (i + reader->cursor < reader->size && i < remaining)
	{
		reader->grow_buffer[reader->cursor + i] = reader->read_buffer[i];
		reader->read_buffer[i] = 0;
		i++;
	}
	reader->cursor += i;
	return (1);
}
