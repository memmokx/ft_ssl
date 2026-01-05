#include <libft.h>
#include <stdint.h>

void ft_bzero(void* s, size_t n) {
  uint8_t* block = s;

  int64_t i = n;
  while (i--)
    *block++ = 0;
}
