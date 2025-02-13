static double	get_decimal(const char *str, int i)
{
	double	dec;
	double	dec_pow;

	dec = 0;
	dec_pow = 1;
	while (str[i] >= '0' && str[i] <= '9')
	{
		dec = dec * 10 + (str[i] - '0');
		dec_pow *= 10;
		i++;
	}
	return (dec / dec_pow);
}

double	ft_atof(const char *str)
{
	double	nb;
	int		sign;
	int		i;
	double	dec;

	i = 0;
	nb = 0;
	sign = 1;
	dec = 0;
	if (str[i] == '-')
		sign = -1;
	if (str[i] == '-' || str[i] == '+')
		i++;
	while (str[i] >= '0' && str[i] <= '9')
	{
		nb = nb * 10 + (str[i] - '0');
		i++;
	}
	if (str[i] == '.')
	{
		i++;
		dec = get_decimal(str, i);
	}
	return ((nb + dec) * sign);
}
