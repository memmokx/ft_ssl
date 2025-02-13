#include "get_next_line.h"

static void	reader_free(struct s_reader *reader)
{
	if (reader->grow_buffer)
		free(reader->grow_buffer);
	if (reader->read_buffer)
		free(reader->read_buffer);
	reader->grow_buffer = NULL;
	reader->read_buffer = NULL;
}

static int	read_and_append(struct s_reader *reader, int fd)
{
	if (!reader->read_buffer)
		return (0);
	reader->last_read = read(fd, reader->read_buffer, BUFFER_SIZE);
	if (reader->last_read == -1)
	{
		reader_free(reader);
		return (0);
	}
	if (reader->last_read != BUFFER_SIZE && fd != STDIN_FILENO)
		reader->at_eof = 1;
	if (reader->last_read == 0)
	{
		reader->at_eof = 1;
		return (1);
	}
	return (reader_fill(reader, reader->last_read));
}

static char	*get_line_from_reader(struct s_reader *reader, size_t size)
{
	char	*output;
	size_t	i;

	output = (char *)ft_calloc(size + 1, sizeof(char));
	if (!output)
	{
		reader_free(reader);
		return (NULL);
	}
	i = -1;
	while (++i < size)
		output[i] = reader->grow_buffer[i];
	output[i] = 0;
	i = 0;
	while (i < (reader->cursor - size))
	{
		reader->grow_buffer[i] = reader->grow_buffer[i + size];
		i++;
	}
	if (i < reader->size)
		reader->grow_buffer[i] = 0;
	reader->cursor -= size;
	if (reader->at_eof && reader->cursor == 0)
		reader_free(reader);
	return (output);
}

static char	*read_line(struct s_reader *reader, int fd)
{
	int		newline_index;
	char	*line;

	newline_index = ft_sstrchr(reader->grow_buffer, '\n', reader->cursor);
	while (newline_index == -1)
	{
		if (reader->at_eof && reader->cursor == 0)
		{
			reader_free(reader);
			return (NULL);
		}
		if (reader->at_eof)
			return (get_line_from_reader(reader, reader->cursor));
		if (!read_and_append(reader, fd))
			return (NULL);
		newline_index = ft_sstrchr(reader->grow_buffer, '\n', reader->cursor);
	}
	line = get_line_from_reader(reader, newline_index + 1);
	if (!line)
		return (NULL);
	return (line);
}

char	*get_next_line(int fd)
{
	static struct s_reader	reader;

	if (BUFFER_SIZE <= 0)
		return (NULL);
	if (!reader.grow_buffer && reader.size == 0 && !init_reader(&reader))
		return (NULL);
	if (reader.at_eof && reader.cursor == 0)
	{
		if (reader.grow_buffer || reader.read_buffer)
			reader_free(&reader);
		return (NULL);
	}
	return (read_line(&reader, fd));
}
