NAME = ft_ssl
CC = cc

CFLAGS = -Wall -Wextra -std=c23 -fsanitize=address

INCLUDE = -Iinclude -Ilibft/include

FSSL_SRC = src/fssl/encoding.c src/fssl/hash.c src/fssl/md5.c
CLI_SRC = src/cli/app.c src/cli/node.c
MAIN_SRC = src/main.c src/digest.c

SRC = $(MAIN_SRC) $(CLI_SRC) $(FSSL_SRC)
OBJ = $(SRC:.c=.o)

LIBFT = libft/libft.a

COLOUR_GREEN=\033[0;32m
COLOUR_GRAY=\033[0;90m
COLOUR_RED=\033[0;31m
COLOUR_BLUE=\033[0;34m
COLOUR_END=\033[0m

ifdef OPT
	CFLAGS += -O2 -flto
endif

ifndef NO_SILENT
.SILENT:
endif

all: $(NAME)

$(NAME): $(OBJ) $(LIBFT)
	$(CC) $(CFLAGS) $(OBJ) $(LIBFT) $(MLX) -o $@ $(INCLUDE)
	@echo "$(COLOUR_GREEN)Compiled:$(COLOUR_END) $(NAME)"

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@ $(INCLUDE)
	@echo "$(COLOUR_BLUE)Compiled:$(COLOUR_END) $< $(COLOUR_GRAY)$(CC) $(CFLAGS)$(COLOUR_END)"

$(LIBFT):
	@echo "$(COLOUR_GREEN)Compiling libft$(COLOUR_END)"
	@make -j8 -C libft/ all --no-print-directory

clean:
	@rm -f $(OBJ)
	@make -C libft clean --no-print-directory

fclean: clean
	@rm -f $(NAME)
	@rm -f $(LIBFT)

re : fclean all