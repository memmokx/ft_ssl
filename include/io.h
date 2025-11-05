#ifndef SSL_IO_H
#define SSL_IO_H

#include <fcntl.h>
#include "common.h"

typedef ssize_t (*reader_read_fn)(void* ctx, uint8_t* buf, size_t n);
typedef void (*reader_reset_fn)(void* ctx);
typedef void (*reader_deinit_fn)(void** ctx);

typedef ssize_t (*writer_write_fn)(void* ctx, const uint8_t* buf, size_t n);
typedef void (*writer_reset_fn)(void* ctx);
typedef void (*writer_close_fn)(void* ctx);
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
  IoWriter W;
  writer_close_fn close;
} IoWriterCloser;

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
  uint8_t output[1024];
  size_t buflen;

  uint8_t buf[3];
} Base64Writer;

typedef struct {
  int fd;
  bool close;
} FileReader;

typedef struct {
  int fd;
  bool close;
} FileWriter;

REGISTER_OPTION(IoReader);
REGISTER_OPTION(IoWriter);
REGISTER_OPTION(IoWriterCloser);

REGISTER_RESULT(size_t, fssl_error_t);

extern const IoReader io_stdin;
extern const IoWriter io_stdout;

ssize_t io_reader_read(const IoReader* reader, uint8_t* buf, size_t n);
void io_reader_reset(const IoReader* reader);
void io_reader_deinit(IoReader* reader);

ssize_t io_writer_write(const IoWriter* writer, const uint8_t* buf, size_t n);
void io_writer_reset(const IoWriter* writer);
void io_writer_deinit(IoWriter* writer);
void io_writer_close(const IoWriterCloser* writer);

Option(IoReader) b64_reader_new(IoReader* parent, bool ignore_nl);
Option(IoReader) file_reader_new(const char* file, bool close_on_deinit);
/*!
 * @brief Create a new CipherReader that allows decryption of the data read from
 * the parent.
 *
 * This object DOES NOT own the cipher object, it will not be freed on _deinit.
 * io_reader_reset calls WILL call fssl_cipher_reset.
 * @param parent The parent IoReader, data will be read from it and then decrypted.
 * @param cipher The cipher object, it will be used to decrypt the read data.
 * @return None if memory allocation fail. On success: new CipherReader object.
 */
Option(IoReader) cipher_reader_new(IoReader* parent, fssl_cipher_t* cipher);

Option(IoWriterCloser) b64_writer_new(IoWriter* inner);
Option(IoWriter) file_writer_new(const char* file, bool close_on_deinit, int oflag);

IoWriterCloser io_writer_closer_from(IoWriter writer);

ssize_t io_copy(IoReader* reader, IoWriter* writer);

#endif