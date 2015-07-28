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

#include <fuse.h>
#include <string>

#include "mount.h"
#include "string_util.h"

using std::string;

namespace bcc {

File::File(Mount *mount) : Inode(mount, file_e) {
}

Inode * File::leaf(Path *path) {
  return this;
}

int File::getattr(struct stat *st) {
  st->st_mode = S_IFREG | 0444;
  st->st_nlink = 1;
  st->st_size = size();
  return 0;
}

int File::open(struct fuse_file_info *fi) {
  fi->fh = (uintptr_t)this;
  return 0;
}

int File::read_helper(const string &data, char *buf, size_t size,
                      off_t offset, struct fuse_file_info *fi)  {
  if (offset < (off_t)data.size()) {
    if (offset + size > data.size())
      size = data.size() - offset;
    memcpy(buf, data.data() + offset, size);
  }
  return size;
}

int SourceFile::read(char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  if (offset < (off_t)data_.size()) {
    if (offset + size > data_.size())
      size = data_.size() - offset;
    memcpy(buf, data_.data() + offset, size);
  }
  return size;
}

int SourceFile::write(const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  if (offset > (off_t)data_.size())
    offset = data_.size();
  data_.replace(offset, size, buf, size);
  return size;
}

int SourceFile::flush(struct fuse_file_info *fi) {
  if (data_.empty() || data_ == "\n")
    return 0;
  parent_->unload_program();
  if (parent_->load_program(data_.c_str()))
    return -EIO;
  return 0;
}

int SourceFile::truncate(off_t newsize) {
  parent_->unload_program();
  data_.resize(newsize);
  return 0;
}

int StatFile::read(char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  return read_helper(data_, buf, size, offset, fi);
}

int FunctionFile::read(char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  return read_helper((std::to_string(fd_) + "\n").c_str(), buf, size, offset, fi);
}

}  // namespace bcc
