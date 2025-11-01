#ifndef SSL_IO_H
#define SSL_IO_H

#include "common.h"

typedef ssize_t (*reader_read_fn)(void* ctx, uint8_t* buf, size_t n);
typedef void (*reader_reset_fn)(void* ctx);
typedef void (*reader_deinit_fn)(void** ctx);

typedef ssize_t (*writer_write_fn)(void* ctx, const uint8_t* buf, size_t n);
typedef void (*writer_reset_fn)(void* ctx);
typedef void (*writer_deinit_fn)(void** ctx);

typedef struct {
  void* instance;
  reader_read_fn read;
  reader_reset_fn reset;
  reader_deinit_fn deinit;
} IoReader;

typedef struct {
  void* instance;
  writer_write_fn write;
  writer_reset_fn reset;
  writer_deinit_fn deinit;
} IoWriter;

typedef struct {
  IoReader* inner;

  uint8_t input[1024];
  uint8_t output[1024];

  size_t ilen;
  size_t iptr;
  size_t olen;
  size_t optr;

  bool eof;
  bool ignore_nl;
} Base64Reader;

typedef struct {
  IoWriter* inner;
} Base64Writer;

typedef struct {
  int fd;
  bool close;
} FileReader;

REGISTER_OPTION(IoReader);
REGISTER_RESULT(size_t, fssl_error_t);

extern const IoReader io_stdin;

ssize_t io_reader_read(const IoReader* reader, uint8_t* buf, size_t n);
void io_reader_reset(const IoReader* reader);
void io_reader_deinit(IoReader* reader);

Option(IoReader) b64_reader_new(IoReader* reader, bool ignore_nl);
Option(IoReader) file_reader_new(const char *file, bool close_on_deinit);

#endif