static int	ft_isspace(char c)
{
	return (c == '\n' || c == '\v' || c == '\f'
		|| c == '\t' || c == '\r' || c == ' ');
}

int	ft_atoi(const char *nptr)
{
	int	i;
	int	sign;
	int	val;

	val = 0;
	sign = 1;
	i = 0;
	while (nptr[i] && ft_isspace(nptr[i]))
		i++;
	if (nptr[i] == '-' || nptr[i] == '+')
	{
		if (nptr[i] == '-')
			sign = -1;
		i++;
	}
	while (nptr[i])
	{
		if (nptr[i] < '0' || nptr[i] > '9')
			break ;
		val *= 10;
		val += nptr[i] - '0';
		i++;
	}
	return (val * sign);
}
