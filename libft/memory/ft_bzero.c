#include <libft.h>
#include <stdint.h>

static void	fill_small(uint8_t *block, size_t n)
{
	while (n != 0)
	{
		*block++ = 0;
		n--;
	}
}

void	ft_bzero(void *s, size_t n)
{
	uint8_t	*block;
	size_t	word_size;
	size_t	t;

	t = 0;
	word_size = sizeof(uint64_t);
	block = (uint8_t *)s;
	if (n < 3 * word_size)
	{
		fill_small(block, n);
		return ;
	}
	while (t < n / word_size)
	{
		*(uint64_t *)block = 0;
		block += word_size;
		t++;
	}
	fill_small(block, n & (word_size - 1));
}
