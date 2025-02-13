#include <libft/string.h>
#include <unistd.h>
#include <fcntl.h>

#define BUFFER_SIZE 8192

static t_string	read_internal(int fd)
{
	ssize_t		n_read;
	char		buffer[BUFFER_SIZE];
	t_string	str_buffer;

	str_buffer = (t_string){0};
	while (true)
	{
		n_read = read(fd, &buffer, BUFFER_SIZE);
		if (n_read == -1 || n_read == 0)
			break ;
		if (str_buffer.ptr == NULL)
			str_buffer = string_new_capacity(n_read);
		if (!string_append_string(&str_buffer,
								  &((t_string){.ptr = &buffer[0], n_read, n_read}), false))
			return ((t_string){0});
		if (n_read != BUFFER_SIZE)
			break ;
	}
	if (n_read == -1)
		string_destroy(&str_buffer);
	return (str_buffer);
}

t_string	ft_read_file(t_string path)
{
	const int	fd = open(path.ptr, O_RDONLY);
	t_string	result;

	if (fd < 0)
		return ((t_string){0});
	result = read_internal(fd);
	close(fd);
	return (result);
}