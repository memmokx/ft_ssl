#ifndef SSL_IO_H
#define SSL_IO_H

#include <fssl/fssl.h>
#include <fcntl.h>
#include "common.h"
#include <libft/memory.h>

#define IO_READER_RETARGET(_ptr, _len, _buf) \
  do {                                       \
    if (_ptr > 0 && _ptr < _len) {           \
      const size_t _rest = _len - _ptr;      \
      ft_memmove(_buf, _buf + _ptr, _rest);  \
      _len = _rest;                          \
      _ptr = 0;                              \
    } else if (_ptr >= _len)                 \
      _ptr = _len = 0;                       \
  } while (false)

typedef struct IoReader IoReader;
typedef struct IoWriter IoWriter;

typedef struct {
  ssize_t (*read)(IoReader* io, uint8_t* buf, size_t n);
  void (*reset)(IoReader* io);
  void (*deinit)(IoReader* io);
} IoReaderVT;

typedef struct {
  ssize_t (*write)(IoWriter* io, const uint8_t* buf, size_t n);
  void (*close)(IoWriter* io);
  void (*reset)(IoWriter* io);
  void (*deinit)(IoWriter* io);
} IoWriterVT;

struct IoReader {
  const IoReaderVT* vt;
};

struct IoWriter {
  const IoWriterVT* vt;
};

typedef struct {
  IoReader base;
  int fd;
  bool close;
} FileReader;

typedef struct {
  IoWriter base;
  int fd;
  bool close;
} FileWriter;

extern const IoReader* io_stdin;
extern const IoWriter* io_stdout;

ssize_t io_reader_read(IoReader* reader, uint8_t* buf, size_t n);
void io_reader_reset(IoReader* reader);
void io_reader_free(IoReader* reader);

ssize_t io_writer_write(IoWriter* writer, const uint8_t* buf, size_t n);
void io_writer_reset(IoWriter* writer);
void io_writer_free(IoWriter* writer);
void io_writer_close(IoWriter* writer);

#define io_free(x) \
  _Generic((x), IoReader*: io_reader_free, IoWriter*: io_writer_free, default: nullptr)(x)

IoReader* b64_reader_new(IoReader* parent, bool ignore_nl);
IoReader* file_reader_new(const char* file, bool close_on_deinit);
/*!
 * @brief Create a new CipherReader that allows decryption of the data read from
 * the parent.
 *
 * This object DOES NOT own the cipher object, it will not be freed on _deinit.
 * io_reader_reset calls WILL call fssl_cipher_reset.
 * @param parent The parent IoReader, data will be read from it and then decrypted.
 * @param cipher The cipher object, it will be used to decrypt the read data.
 * @return \c nullptr if memory allocation fail. On success: new CipherReader object.
 */
IoReader* cipher_reader_new(IoReader* parent, fssl_cipher_t* cipher);

/*!
 * Create a new CipherWriter which encrypts data it receives using the given \a `cipher`.
 * When closed it will pad and encrypt the remaining data then flush it to the parent \c IoWriter.
 *
 * @param parent The parent \c IoWriterCloser, encrypted data will be written into it.
 * @param cipher The cipher object used to encrypt the data.
 * @return \c nullptr on error, otherwise a \c IoWriter
 */
IoWriter* cipher_writer_new(IoWriter* parent, fssl_cipher_t* cipher);
IoWriter* b64_writer_new(IoWriter* inner);
IoWriter* file_writer_new(const char* file, bool close_on_deinit, int oflag);

ssize_t io_copy(IoReader* reader, IoWriter* writer);

#endif