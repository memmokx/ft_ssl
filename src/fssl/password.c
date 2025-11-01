#include <bsd/readpassphrase.h>
#include <fssl/password.h>

char* fssl_read_password(const char* prompt, char* buf, size_t buf_capacity) {
  return readpassphrase(prompt, buf, buf_capacity, RPP_ECHO_OFF);
}