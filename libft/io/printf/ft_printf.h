#ifndef FT_PRINTF_H
# define FT_PRINTF_H

# include <libft/strconv.h>
# include <libft/string.h>
# include <stdarg.h>

int	printf_convert_int(t_string *buffer, int n);
int	printf_convert_unsigned(t_string *buffer, unsigned int n);
int	printf_convert_hex(t_string *buffer, unsigned int n);
int	printf_convert_hex_upper(t_string *buffer, unsigned int n);
int	printf_convert_pointer(t_string *buffer, void *ptr);
int	printf_convert_float(t_string *buffer, double f);
int	printf_convert_string(t_string *buffer, char *str);
int	printf_convert_float_hex(t_string *buffer, double f);

int	ft_vsprintf(char **out, const char *format, va_list args);

#endif