#ifndef SSL_COMMON_H
#define SSL_COMMON_H

#include <libft/io.h>
#include <stdint.h>

#define ssl_min(a, b)      \
  ({                   \
    auto _a = (a);     \
    auto _b = (b);     \
    _a < _b ? _a : _b; \
  })

#define ssl_assert(expr)                                                       \
  do {                                                                         \
    if (expr) {                                                                \
    } else {                                                                   \
      ft_fprintf(2, "%s:%d: assertion fail: %s\n", __FILE__, __LINE__, #expr); \
      __builtin_trap();                                                        \
    }                                                                          \
  } while (false)

#define SSL_LEVEL_WARN "warn     "
#define SSL_LEVEL_ERROR "error    "

#define ssl_log(level, fmt, ...) \
  ft_fprintf(2, "%s   %s:%d " fmt, level, __FILE__, __LINE__, ##__VA_ARGS__)
#define ssl_log_warn(fmt, ...) ssl_log(SSL_LEVEL_WARN, fmt, ##__VA_ARGS__)
#define ssl_log_err(fmt, ...) ssl_log(SSL_LEVEL_ERROR, fmt, ##__VA_ARGS__)

#endif