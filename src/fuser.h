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

#include <memory>
#include <sys/stat.h>
#include <sys/types.h>

// forward declarations from fuse.h
extern "C" {
struct fuse_operations;
struct fuse_file_info;
}

class Fuser {
 private:
  typedef int (*fuse_fill_dir_t) (void *buf, const char *name,
          const struct stat *stbuf, off_t off);
  static Fuser * self();

  static int getattr_(const char *path, struct stat *st) {
    return self()->getattr(path, st);
  }
  static int readdir_(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
                      struct fuse_file_info *fi) {
    return self()->readdir(path, buf, filler, offset, fi);
  }
  static int open_(const char *path, struct fuse_file_info *fi) {
    return self()->open(path, fi);
  }
  static int read_(const char *path, char *buf, size_t size, off_t offset,
                   struct fuse_file_info *fi) {
    return self()->read(path, buf, size, offset, fi);
  }

  int getattr(const char *path, struct stat *st);
  int readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
              struct fuse_file_info *fi);
  int open(const char *path, struct fuse_file_info *fi);
  int read(const char *path, char *buf, size_t size, off_t offset,
           struct fuse_file_info *fi);
 public:
  Fuser();
  ~Fuser();
  int run(int argc, char **argv);

 private:
  std::unique_ptr<struct fuse_operations> oper_;
};
