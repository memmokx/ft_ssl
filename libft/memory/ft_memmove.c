#include <libft/memory.h>

void	*ft_memmove(void *dest, const void *src, size_t n)
{
	int				i;
	unsigned char	*dst_block;
	unsigned char	*src_block;

	i = 0;
	dst_block = (unsigned char *)dest;
	src_block = (unsigned char *)src;
	if (src < dest)
	{
		i = n - 1;
		while (i >= 0)
		{
			dst_block[i] = src_block[i];
			i--;
		}
		return (dest);
	}
	return (ft_memcpy(dest, src, n));
}
