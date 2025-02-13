#include <libft/strconv.h>
#include <limits.h>

static bool	is_space(char c)
{
	return (c == ' ' || c == '\n' || c == '\v'
		|| c == '\t' || c == '\r' || c == '\f');
}

int64_t	ft_safe_atol(const char *str, bool *error)
{
	int			i;
	int			sign;
	__int128_t	n;

	i = 0;
	n = 0;
	sign = 1;
	while (is_space(str[i]))
		i++;
	if (str[i] == '-')
		sign = -1;
	if (str[i] == '+' || str[i] == '-')
		i++;
	if (str[i] == 0)
		*error = true;
	while (str[i] && !*error)
	{
		if ((str[i] < '0' || str[i] > '9'))
			*error = true;
		n = (n * 10) + str[i] - '0';
		if ((sign == 1 && n > LLONG_MAX) || (sign != 1 && n * sign < LLONG_MIN))
			*error = true;
		i++;
	}
	return (n * sign);
}
