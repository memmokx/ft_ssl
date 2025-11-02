NAME = libft.a
SRC = string/ft_strlen.c \
	  string/ft_strcat.c \
	  string/ft_strjoin.c \
	  string/ft_strcmp.c \
	  string/ft_strncmp.c \
	  string/string.c \
	  string/iterator.c \
	  string/string_common.c \
	  string/string_concat.c \
	  string/string_find.c \
	  string/string_append.c \
	  string/string_insert.c \
	  string/string_internal.c \
	  string/string_split.c \
	  string/ft_strdup.c \
	  strconv/ft_atof.c \
	  strconv/ft_atoi.c \
	  strconv/ft_safe_atoi.c \
	  strconv/ft_utoa.c \
	  strconv/ft_itoa.c \
	  strconv/ft_ftoa.c \
	  strconv/hex_float_to_d.c \
	  io/ft_putstr.c \
	  io/ft_putstr_fd.c \
	  io/ft_putendl.c \
	  io/ft_putchar.c \
	  io/ft_read_file.c \
	  io/printf/ft_vsprintf.c \
	  io/printf/ft_fprintf.c \
	  io/printf/ft_printf.c \
	  io/printf/ft_sprintf.c \
	  io/printf/printf_convert_int.c \
	  io/printf/printf_convert_hex.c \
	  io/printf/printf_convert_other.c \
	  io/get_line/get_next_line.c \
	  io/get_line/get_next_line_utils.c \
	  memory/ft_bzero.c \
	  memory/ft_free.c \
	  memory/ft_calloc.c \
	  memory/ft_memcpy.c \
	  memory/ft_memmove.c \
	  math/ft_abs.c	\
	  math/ft_normalize.c \
	  math/ft_mapf.c \
	  collections/list/ft_list.c \
	  collections/list/ft_list_iter.c \
	  collections/list/ft_list_clear.c \
	  collections/list/ft_list_del_one.c \
	  collections/list/ft_list_add.c \
	  collections/string_vector/string_vector.c \
	  rand/rand.c \
	  rand/xoshiro.c

OBJ = $(SRC:.c=.o)

CC				= cc
CFLAGS			= -Wall -Werror -Wextra

COLOUR_GREEN=$(shell tput setaf 2)
COLOUR_GRAY=$(shell tput setaf 254)
COLOUR_RED=$(shell tput setaf 1)
COLOUR_BLUE=$(shell tput setaf 4)
BOLD=$(shell tput bold)
COLOUR_END=$(shell tput sgr0)

ifdef OPT
	CFLAGS += -march=native -O3 -flto
endif
ifdef DEBUG
	CFLAGS += -g
endif
ifdef SANITIZE
	CFLAGS += -g -fsanitize=address,undefined,leak
endif


ifndef NO_SILENT
.SILENT:
endif

all: $(NAME)

%.o: %.c
	$(CC) $(CFLAGS) $< -c -o $@ -I. -Iinclude/
	@echo "$(COLOUR_BLUE)Compiled:$(COLOUR_END) $< $(COLOUR_GRAY)$(CC) $(CFLAGS)$(COLOUR_END)"

$(NAME): $(OBJ)
	ar -rcs $(NAME) $(OBJ)
	@echo "$(COLOUR_GREEN)Compiled:$(COLOUR_END) $(BOLD)$@$(COLOUR_END)"

clean:
	rm -rf $(OBJ)

fclean: clean
	rm -rf $(NAME)

re: fclean all