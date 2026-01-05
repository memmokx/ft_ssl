NAME = ft_ssl
CC ?= cc

CFLAGS = -std=c23 -Wall -Wextra -Werror -Wno-unknown-warning-option -Wno-error=old-style-declaration -fPIC
LIBS = -lbsd

FSSL_DES_VANILLA = 2
FSSL_DES_BONUS = 3
FSSL_CLI_FEATURES = $(FSSL_DES_VANILLA)

INCLUDE = -Iinclude -Ilibft/include

FSSL_SRC = src/fssl/encoding.c \
		src/fssl/hash.c \
		src/fssl/md5.c \
		src/fssl/sha256.c \
		src/fssl/sha512.c \
		src/fssl/sha1.c \
		src/fssl/blake2s.c \
		src/fssl/des.c \
		src/fssl/des3.c \
		src/fssl/chacha20.c \
		src/fssl/cipher.c \
		src/fssl/error.c \
		src/fssl/password.c \
		src/fssl/kdf.c \
		src/fssl/pkcs.c \
		src/fssl/rand.c

CLI_SRC = src/cli/app.c src/cli/node.c
MAIN_SRC = src/main.c \
		src/cli.c \
		src/io/io.c \
		src/io/base64.c \
		src/io/file.c \
		src/io/cipher.c \
		src/commands/digest.c \
		src/commands/cipher.c \
		src/commands/standard.c

TEST_SRC = tests/fssl/test_md5.c \
 		tests/fssl/test_sha256.c \
 		tests/fssl/test_sha1.c \
 		tests/fssl/test_sha512.c \
 		tests/fssl/test_blake2.c \
 		tests/fssl/test_des.c \
 		tests/fssl/test_hmac.c \
 		tests/fssl/test_kdf.c \
 		tests/fssl/test_base64.c


LIBFSSL_OBJ = $(FSSL_SRC:.c=.o)

SRC = $(MAIN_SRC) $(CLI_SRC) $(FSSL_SRC)
OBJ = $(SRC:.c=.o)
TEST_OBJ = $(TEST_SRC:.c=.o)


TESTS_BIN = tests/bin
LIBFT = libft/libft.a
LIBFSSL = libfssl.so

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

lib: $(LIBFSSL)

$(TESTS_BIN): $(TEST_OBJ) lib
	$(CC) $(CFLAGS) $(TEST_OBJ) $(LIBFSSL) -o $@ $(LIBS) -lcriterion -Wl,-rpath=$(PWD) $(INCLUDE)

test: $(TESTS_BIN)
	@echo "$(COLOUR_GREEN)Running unit tests$(COLOUR_END)"
	./$(TESTS_BIN)

BASE_LIT_TESTS = tests/cli/base64 \
				tests/cli/md5 \
				tests/cli/des

lit-test-bonus: bonus
	@lit --path="$(PWD)" $(BASE_LIT_TESTS) tests/cli/des-bonus

lit-test: $(NAME)
	@lit --path="$(PWD)" $(BASE_LIT_TESTS)

$(LIBFSSL): $(LIBFSSL_OBJ) $(LIBFT)
	$(CC) -shared $(CFLAGS) $(LIBFSSL_OBJ) $(LIBFT) -o $@ $(LIBS) $(INCLUDE)
	@echo "$(COLOUR_GREEN)Compiled:$(COLOUR_END) $(BOLD)$@$(COLOUR_END)"

$(NAME): $(OBJ) $(LIBFT)
	$(CC) $(CFLAGS) $(OBJ) $(LIBFT) -o $@ $(LIBS) $(INCLUDE)
	@echo "$(COLOUR_GREEN)Compiled:$(COLOUR_END) $(BOLD)$@$(COLOUR_END)"

%.o: %.c
	$(CC) $(CFLAGS) -D FSSL_CLI_FEATURES=$(FSSL_CLI_FEATURES) -c $< -o $@ $(INCLUDE)
	@echo "$(COLOUR_BLUE)Compiled:$(COLOUR_END) $< $(COLOUR_GRAY)$(CC) $(CFLAGS)$(COLOUR_END)"

$(LIBFT):
	@echo "$(COLOUR_GREEN)Compiling libft$(COLOUR_END)"
	@make -j8 -C libft/ all --no-print-directory

format:
	clang-format -i $(SRC) $(TEST_SRC)
clean:
	@rm -f $(OBJ)
	@rm -f $(TEST_OBJ)
	@make -C libft clean --no-print-directory

fclean: clean
	@rm -f $(NAME)
	@rm -f $(LIBFSSL)
	@rm -f $(LIBFT)
	@rm -f $(TESTS_BIN)

re : fclean all

bonus: FSSL_CLI_FEATURES=$(FSSL_DES_BONUS)
bonus: $(NAME)

.PHONY: re all fclean clean lib test format bonus
