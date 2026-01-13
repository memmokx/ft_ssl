#include "io.h"

ssize_t io_reader_read(IoReader* reader, uint8_t* buf, size_t n) {
  ssl_assert(reader && reader->vt);

  return reader->vt->read(reader, buf, n);
}

void io_reader_reset(IoReader* reader) {
  ssl_assert(reader && reader->vt);

  reader->vt->reset(reader);
}

/*!
 * @brief Free an IoReader object.
 *
 * This will call the deinit method, then free the reader itself.
 *
 * Warning: if no deinit method is provided, the reader will not be deinitialized.
 * @param reader The reader to free.
 */
void io_reader_free(IoReader* reader) {
  if (reader && reader->vt && reader->vt->deinit) {
    reader->vt->deinit(reader);
    free(reader);
  }
}

ssize_t io_writer_write(IoWriter* writer, const uint8_t* buf, size_t n) {
  ssl_assert(writer && writer->vt);

  return writer->vt->write(writer, buf, n);
}

void io_writer_reset(IoWriter* writer) {
  ssl_assert(writer && writer->vt);

  writer->vt->reset(writer);
}

/*!
 * @brief Free an IoWriter object.
 *
 * This will call the deinit method, then free the writer itself.
 *
 * Warning: if no deinit method is provided, the writer will not be deinitialized.
 * @param writer The writer to free.
 */
void io_writer_free(IoWriter* writer) {
  if (writer && writer->vt && writer->vt->deinit) {
    writer->vt->deinit(writer);
    free(writer);
  }
}

void io_writer_close(IoWriter* writer) {
  ssl_assert(writer && writer->vt);

  if (writer->vt->close)
    writer->vt->close(writer);
}

ssize_t io_copy(IoReader* reader, IoWriter* writer) {
  if (!reader || !writer)
    return -1;

  uint8_t buffer[8192];

  ssize_t total = 0;
  while (true) {
    const ssize_t r = io_reader_read(reader, buffer, sizeof(buffer));
    if (r < 0)
      return -1;
    if (r == 0)
      break;

    const ssize_t w = io_writer_write(writer, buffer, r);
    if (w < 0)
      return -1;
    if (w == 0)
      break;

    if (r != w) {
      ssl_log_warn("w != r. {w: %lu, r: %lu}\n", w, r);
      break;
    }

    total += r;
  }

  return total;
}
