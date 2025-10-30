#ifndef FSSL_PASSWORD_H
#define FSSL_PASSWORD_H

#include <unistd.h>

char* fssl_read_password(const char* prompt, char* buf, size_t buf_len);

#endif
