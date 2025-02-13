#include <libft.h>
#include <stdlib.h>

void	*ft_calloc(size_t nmemb, size_t size)
{
	void	*block;
	size_t	total;

	if (nmemb == 0 || size == 0)
		return (ft_calloc(1, 1));
	total = nmemb * size;
	if (total / size != nmemb)
		return (NULL);
	block = malloc(total);
	if (!block)
		return (NULL);
	ft_bzero(block, total);
	return (block);
}
