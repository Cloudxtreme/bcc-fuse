/*
 * Copyright (c) 2015 PLUMgrid, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <map>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <thread>
#include <vector>

// forward declarations from fuse.h
extern "C" {
struct fuse_operations;
struct fuse_file_info;
}

namespace bcc {

class Mount;
class Inode;
class Dir;
class File;
class Path;

typedef int (*fuse_fill_dir_t) (void *buf, const char *name,
        const struct stat *stbuf, off_t off);
class Mount {
 private:
  // fetch this from fuse private_data
  static Mount * instance();

  // wrapper functions, to be registered with fuse
  static int getattr_(const char *path, struct stat *st) {
    return instance()->getattr(path, st);
  }
  static int readdir_(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
                      struct fuse_file_info *fi) {
    return instance()->readdir(path, buf, filler, offset, fi);
  }
  static int mkdir_(const char *path, mode_t mode) {
    return instance()->mkdir(path, mode);
  }
  static int mknod_(const char *path, mode_t mode, dev_t rdev) {
    return instance()->mknod(path, mode, rdev);
  }
  static int unlink_(const char *path) {
    return instance()->unlink(path);
  }
  static int open_(const char *path, struct fuse_file_info *fi) {
    return instance()->open(path, fi);
  }
  static int read_(const char *path, char *buf, size_t size, off_t offset,
                   struct fuse_file_info *fi) {
    return instance()->read(path, buf, size, offset, fi);
  }
  static int write_(const char *path, const char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi) {
    return instance()->write(path, buf, size, offset, fi);
  }
  static int truncate_(const char *path, off_t newsize) {
    return instance()->truncate(path, newsize);
  }
  static int flush_(const char *path, struct fuse_file_info *fi) {
    return instance()->flush(path, fi);
  }
  static int readlink_(const char *path, char *buf, size_t size) {
    return instance()->readlink(path, buf, size);
  }
  static int ioctl_(const char *path, int cmd, void *arg, struct fuse_file_info *fi,
                    unsigned int flags, void *data) {
    return instance()->ioctl(path, cmd, arg, fi, flags, data);
  }

  // implementations of fuse callbacks
  int getattr(const char *path, struct stat *st);
  int readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
              struct fuse_file_info *fi);
  int mkdir(const char *path, mode_t mode);
  int mknod(const char *path, mode_t mode, dev_t rdev);
  int unlink(const char *path);
  int open(const char *path, struct fuse_file_info *fi);
  int read(const char *path, char *buf, size_t size, off_t offset,
           struct fuse_file_info *fi);
  int write(const char *path, const char *buf, size_t size, off_t offset,
            struct fuse_file_info *fi);
  int flush(const char *path, struct fuse_file_info *fi);
  int truncate(const char *path, off_t newsize);
  int readlink(const char *path, char *buf, size_t size);
  int ioctl(const char *path, int cmd, void *arg, struct fuse_file_info *fi,
            unsigned int flags, void *data);

 public:
  Mount();
  ~Mount();
  int run(int argc, char **argv);

  unsigned flags() const { return flags_; }

  template <typename... Args>
  void log(const char *fmt, Args&&... args) {
    fprintf(log_, fmt, std::forward<Args>(args)...);
    fflush(log_);
  }

 private:
  std::unique_ptr<struct fuse_operations> oper_;
  std::map<std::string, void *> modules_;
  static std::vector<std::string> props_;
  static std::vector<std::string> subdirs_;
  FILE *log_;
  std::unique_ptr<Dir> root_;
  unsigned flags_;
};

// Inode base class
class Inode {
 public:
  enum InodeType {
    dir_e, file_e, link_e, socket_e,
  };
  Inode(InodeType type) : parent_(nullptr), type_(type) {}
  virtual ~Inode() {}
  Inode(const Inode &) = delete;
  InodeType type() const { return type_; }
  void set_type(InodeType type) { type_ = type; }
  void set_parent(Dir *parent) { parent_ = parent; }
  std::string path() const;

  virtual Inode * leaf(Path *path) { return this; }

  virtual int getattr(struct stat *st) = 0;

 protected:
  Dir *parent_;
  InodeType type_;
};

class Link : public Inode {
 public:
  Link(mode_t mode, const std::string &dst);
  int getattr(struct stat *st) override;
  virtual int readlink(char *buf, size_t size);
 protected:
  std::string dst_;
};

class Socket : public Inode {
 public:
  Socket(mode_t mode, dev_t rdev);
  int getattr(struct stat *st) override;
 protected:
  dev_t rdev_;
};

class FunctionSocket : public Socket {
 public:
  FunctionSocket(mode_t mode, dev_t rdev, int fd);
  ~FunctionSocket();
  int getattr(struct stat *st) override;
  int mknod();
 private:
  int fd_;
  std::thread thread_;
  bool ready_;
};

class Dir : public Inode {
 public:
  Dir(mode_t mode);
  Inode * leaf(Path *path) override;
  void add_child(const std::string &name, std::unique_ptr<Inode> node);
  void remove_child(const std::string &name);
  int getattr(struct stat *st) override;
  int readdir(void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi);
  virtual int mkdir(const char *name, mode_t mode) { return -EACCES; }
  virtual int mknod(const char *name, mode_t mode, dev_t rdev);
  std::string path(const Inode *node) const;
 protected:
  std::map<std::string, std::unique_ptr<Inode>> children_;
  size_t n_files_;
  size_t n_dirs_;
  mode_t mode_;
};

class RootDir : public Dir {
 public:
  explicit RootDir(mode_t mode) : Dir(mode) {}
  int mkdir(const char *name, mode_t mode);
};

class ProgramDir : public Dir {
 public:
  ProgramDir(mode_t mode);
  ~ProgramDir();
  int load(const char *text);
  void unload();
 private:
  void *bpf_module_;
};

class MapDir : public Dir {
 public:
  MapDir(mode_t mode, int fd);
 private:
  int fd_;
};

class FunctionDir : public Dir {
 public:
  FunctionDir(mode_t mode, void *bpf_module, int id);
  // load function and return open fd
  int load(const std::string &type);
  void unload();
 private:
  void *bpf_module_;
  int id_;
};

class File : public Inode {
 public:
  File() : Inode(file_e) {}
  int getattr(struct stat *st) override;
  int open(struct fuse_file_info *fi);
  virtual int read(char *buf, size_t size, off_t offset, struct fuse_file_info *fi) { return -EACCES; }
  virtual int write(const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) { return -EACCES; }
  virtual int truncate(off_t newsize) { return -EACCES; }
  virtual int flush(struct fuse_file_info *fi) { return 0; }
 protected:
  virtual size_t size() const = 0;
  int read_helper(const std::string &data, char *buf, size_t size,
                  off_t offset, struct fuse_file_info *fi);
 private:
  size_t size_;
};

class StringFile : public File {
 public:
  StringFile() : File() {}
  int read(char *buf, size_t size, off_t offset, struct fuse_file_info *fi) override;
  int write(const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) override;
  int truncate(off_t newsize) = 0;
  int flush(struct fuse_file_info *fi) = 0;
 protected:
  size_t size() const { return data_.size(); }
  std::string data_;
};

class SourceFile : public StringFile {
 public:
  SourceFile() : StringFile() {}
  int truncate(off_t newsize) override;
  int flush(struct fuse_file_info *fi) override;
};

class StatFile : public File {
 public:
  StatFile(const std::string &data) : File(), data_(data) {}
  int read(char *buf, size_t size, off_t offset, struct fuse_file_info *fi) override;

  void set_data(const std::string data) { data_ = data; }
 protected:
  size_t size() const override { return data_.size(); }
 private:
  std::string data_;
};

class FunctionTypeFile : public StringFile {
 public:
  FunctionTypeFile() : StringFile() {}
  int truncate(off_t newsize) override;
  int flush(struct fuse_file_info *fi) override;
};

}  // namespace bcc
