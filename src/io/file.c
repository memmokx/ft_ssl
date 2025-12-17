#include "io.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>

static ssize_t file_reader_read(IoReader* ptr, uint8_t* buf, const size_t n) {
  const auto ctx = (FileReader*)ptr;
  if (!ctx || !buf)
    return -1;

  const ssize_t result = read(ctx->fd, buf, n);
  if (result < 0)
    ssl_log_warn("file_reader: read: %s\n", strerror(errno));
  return result;
}

static void file_reader_reset(IoReader* ptr) {
  (void)ptr;
}

static void file_reader_deinit(IoReader* ptr) {
  if (!ptr)
    return;

  const auto instance = (FileReader*)ptr;
  if (instance->close)
    close(instance->fd);
}

static const IoReaderVT file_reader_vtable = {
    .read = file_reader_read,
    .reset = file_reader_reset,
    .deinit = file_reader_deinit,
};

IoReader* file_reader_new(const char* file, const bool close_on_deinit) {
  FileReader* instance = malloc(sizeof(FileReader));
  if (!instance)
    return nullptr;

  const int fd = open(file, O_RDONLY);
  if (fd < 0) {
    ssl_log_warn("file_reader: open(%s): %s\n", file, strerror(errno));
    free(instance);
    return nullptr;
  }

  *instance = (FileReader){
      .base = {.vt = &file_reader_vtable},
      .fd = fd,
      .close = close_on_deinit,
  };

  return (IoReader*)instance;
}

static ssize_t file_writer_write(IoWriter* ptr, const uint8_t* buf, size_t n) {
  const auto ctx = (FileWriter*)ptr;

  if (!ctx || !buf)
    return -1;

  const ssize_t result = write(ctx->fd, buf, n);
  if (result < 0) {
    ssl_log_err("file_writer: write(%d, ...): %s\n", ctx->fd, strerror(errno));
    return -1;
  }

  return result;
}

static void file_writer_reset(IoWriter* ctx) {
  (void)ctx;
}

static void file_writer_deinit(IoWriter* ptr) {
  const auto w = (FileWriter*)ptr;
  if (!w)
    return;

  if (w->close)
    close(w->fd);
  *w = (FileWriter){};
}

static const IoWriterVT file_writer_vtable = {
    .write = file_writer_write,
    .reset = file_writer_reset,
    .deinit = file_writer_deinit,
};

IoWriter* file_writer_new(const char* file, const bool close_on_deinit, const int oflag) {
  FileWriter* instance = malloc(sizeof(FileWriter));
  if (!instance)
    return nullptr;

  // TODO: permissions?
  const int fd = open(file, O_WRONLY | oflag, 0644);
  if (fd < 0) {
    ssl_log_err("file_writer: open(%s): %s\n", file, strerror(errno));
    free(instance);
    return nullptr;
  }

  *instance = (FileWriter){
      .base = {.vt = &file_writer_vtable}, .fd = fd, .close = close_on_deinit};
  return (IoWriter*)instance;
}

const IoReader* io_stdin = (IoReader*)&(FileReader){
    .base =
        {
            .vt = &(IoReaderVT){.read = file_reader_read,
                                .reset = file_reader_reset,
                                .deinit = nullptr},
        },
    .fd = STDIN_FILENO,
    .close = false,
};

const IoWriter* io_stdout = (IoWriter*)&(FileWriter){
    .base =
        {
            .vt = &(IoWriterVT){.write = file_writer_write,
                                .reset = file_writer_reset,
                                .deinit = nullptr},
        },
    .fd = STDOUT_FILENO,
    .close = false,
};
