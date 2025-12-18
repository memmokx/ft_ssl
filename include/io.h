#ifndef SSL_IO_H
#define SSL_IO_H

#include <fcntl.h>
#include <fssl/fssl.h>
#include <libft/memory.h>
#include "common.h"

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

extern const IoReader* io_stdin;
extern const IoWriter* io_stdout;

/*!
 * Read up to \a n bytes from \a reader into \a buf.
 *
 * @param reader The target reader.
 * @param buf The buffer to read into.
 * @param n The maximum number of bytes to read.
 * @return The number of bytes read, or \c -1 on error.
 * 0 indicates EOF.
 */
ssize_t io_reader_read(IoReader* reader, uint8_t* buf, size_t n);

/*!
 * Reset the reader to its initial state.
 * @param reader The target reader.
 */
void io_reader_reset(IoReader* reader);

/*!
 * Release an \c IoReader object.
 * This will call the reader's deinit method, then free the object.
 * @param reader The reader to free.
 */
void io_reader_free(IoReader* reader);

/*!
 * Write up to \a n bytes from \a buf into \a writer.
 *
 * @param writer The target writer.
 * @param buf The buffer to write from.
 * @param n The number of bytes to write.
 * @return The number of bytes written, or \c -1 on error.
 */
ssize_t io_writer_write(IoWriter* writer, const uint8_t* buf, size_t n);

/*!
 * Reset the writer to its initial state.
 * @param writer The target writer.
 */
void io_writer_reset(IoWriter* writer);

/*!
 * Release an \c IoWriter object.
 * This will call the writer's deinit method, then free the object.
 * @param writer The writer to free.
 */
void io_writer_free(IoWriter* writer);

/*!
 * Close the writer, flushing any remaining data.
 * @param writer The target writer.
 */
void io_writer_close(IoWriter* writer);

#define io_free(x) \
  _Generic((x), IoReader*: io_reader_free, IoWriter*: io_writer_free, default: nullptr)(x)

/*!
 * Create a new base64 \c IoReader that decodes data read from the parent.
 *
 * @param parent The parent IoReader, data will be read from it and then decoded.
 * @param ignore_nl Whether to ignore newlines and whitespace in the input.
 * @return \c nullptr if memory allocation fail. Else a new \c IoReader object.
 */
IoReader* b64_reader_new(IoReader* parent, bool ignore_nl);

/*!
 * @brief Create a new \c IoReader that reads from a file.
 *
 * @param file The file path to read from.
 * @param close_on_deinit Whether to close the file descriptor on deinit.
 * @return \c nullptr if memory allocation fail or file open fails.
 * Else a new \c IoReader object.
 */
IoReader* file_reader_new(const char* file, bool close_on_deinit);

/*!
 * Create a new CipherReader that allows decryption of the data read from
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

/*!
 * Create a new base64 \c IoWriter that encodes data written to it.
 *
 * io_writer_close will flush any remaining data, adding padding if necessary.
 * @param parent The parent IoWriter, encoded data will be written into it.
 * @return \c nullptr if memory allocation fail. Else a new \c IoWriter object.
 */
IoWriter* b64_writer_new(IoWriter* parent);

/*!
 * @brief Create a new \c IoWriter that writes to a file.
 *
 * @param file The file path to write to.
 * @param close_on_deinit Whether to close the file descriptor on deinit.
 * @param oflag Additional flags to pass to \c open(). By default, only \c O_WRONLY is set.
 * @return \c nullptr if memory allocation fail or file open fails.
 * Else a new \c IoWriter object.
 */
IoWriter* file_writer_new(const char* file, bool close_on_deinit, int oflag);

/*!
 * Copy data from \a reader to \a writer until EOF or error.
 *
 * @param reader The source reader.
 * @param writer The destination writer.
 * @return The total number of bytes copied, or \c -1 on error.
 */
ssize_t io_copy(IoReader* reader, IoWriter* writer);

#endif