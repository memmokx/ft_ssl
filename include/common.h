#ifndef SSL_COMMON_H
#define SSL_COMMON_H

#include <libft/io.h>
#include <stdint.h>

#define REGISTER_OPTION(T) \
  typedef struct {         \
    T v;                   \
    bool some;             \
  } Option__##T

#define Option(T) Option__##T

#define Some(value) {.v = (value), .some = true}
#define None(T)   \
  (Option(T)) {   \
    .some = false \
  }

#define option_some(opt) ((opt).v)
#define option_is_some(opt) ((opt).some)
#define option_is_none(opt) (!(opt).some)

/*!
 * Returns the contained Some value. Panic if the value is none.
 */
#define option_unwrap(opt)    \
  ({                          \
    typeof(opt) _opt = (opt); \
    if (option_is_none(_opt)) \
      __builtin_trap();       \
    _opt.v;                   \
  })

// clang-format off

#define option_let_some(opt, variable) \
    (option_is_some(opt)) \
      for (bool _c_c = true; _c_c; _c_c = false) \
        for (const auto variable = (opt).v; _c_c; _c_c = false) \

#define option_let_some_else(opt, variable) \
    if (option_is_some(opt)) \
      for (bool _c_c = true; _c_c; _c_c = false) \
        for (variable = (opt).v; _c_c; _c_c = false) {}

// clang-format on

REGISTER_OPTION(uint8_t);
REGISTER_OPTION(uint16_t);

#define RESULT_CONCAT_(a, b) a##b
#define RESULT_CONCAT_IMPL(a, b) RESULT_CONCAT_(a, b)
#define RESULT_NAME(T, E) RESULT_CONCAT_IMPL(Result__, RESULT_CONCAT_IMPL(T, E))

#define REGISTER_RESULT(T, E) \
  typedef struct {            \
    enum { OK, ERR } state;   \
    union {                   \
      T ok;                   \
      E err;                  \
    };                        \
  } RESULT_NAME(T, E)

#define Result(T, E) RESULT_NAME(T, E)
#define Ok(value) {.state = OK, .ok = (value)}
#define Err(value) {.state = ERR, .err = (value)}

#define min(a, b)      \
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