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

#include <bcc/libbpf.h>
#include <fuse.h>
#include <iostream>
#include <iomanip>
#include <memory>
#include <string>
#include <sstream>
#include <unistd.h>

#include <bcc/bpf_common.h>

#include "mount.h"
#include "string_util.h"

using std::move;
using std::string;
using std::stringstream;
using std::unique_ptr;

namespace bcc {

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
  } else {
    size = 0;
  }
  return size;
}

int StringFile::read(char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  if (offset < (off_t)data_.size()) {
    if (offset + size > data_.size())
      size = data_.size() - offset;
    memcpy(buf, data_.data() + offset, size);
  } else {
    size = 0;
  }
  return size;
}

int StringFile::write(const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  if (offset > (off_t)data_.size())
    offset = data_.size();
  data_.replace(offset, size, buf, size);
  return size;
}

int SourceFile::write(const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  dirty_ = true;
  return StringFile::write(buf, size, offset, fi);
}

int SourceFile::truncate(off_t newsize) {
  dirty_ = true;
  if (ProgramDir *parent = dynamic_cast<ProgramDir *>(parent_))
    parent->unload();
  data_.resize(newsize);
  return 0;
}

int SourceFile::flush(struct fuse_file_info *fi) {
  if (!dirty_)
    return 0;
  dirty_ = false;
  if (data_.empty() || data_ == "\n")
    return 0;
  if (ProgramDir *parent = dynamic_cast<ProgramDir *>(parent_)) {
    parent->unload();
    if (parent->load(data_.c_str()))
      return -EIO;
  }
  return 0;
}

int StatFile::read(char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  return read_helper(data_, buf, size, offset, fi);
}

int FunctionTypeFile::truncate(off_t newsize) {
  if (FunctionDir *parent = dynamic_cast<FunctionDir *>(parent_))
    parent->unload();
  data_.resize(newsize);
  return 0;
}

int FunctionTypeFile::flush(struct fuse_file_info *fi) {
  if (data_.empty() || data_ == "\n")
    return 0;
  if (FunctionDir *parent = dynamic_cast<FunctionDir *>(parent_)) {
    parent->unload();
    if (parent->load(data_))
      return -EIO;
  }
  return 0;
}

MapDumpFile::MapDumpFile(void *bpf_module, int id)
    : File(), bpf_module_(bpf_module), id_(id),
    fd_(bpf_table_fd_id(bpf_module_, id_)),
    key_size_(bpf_table_key_size_id(bpf_module_, id_)),
    leaf_size_(bpf_table_leaf_size_id(bpf_module_, id_)) {
}

size_t MapDumpFile::size() const {
  unique_ptr<uint8_t[]> key(new uint8_t[key_size_]);
  memset(&key[0], 0, key_size_);
  size_t size = 0;
  while (bpf_get_next_key(fd_, &key[0], &key[0]) == 0) {
    size += leaf_size_ * 2 + key_size_ * 2 + 2;
  }
  log("MapDumpFile::size %zu\n", size);
  return 4096;
}

int MapDumpFile::read(char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  unique_ptr<uint8_t[]> key(new uint8_t[key_size_]);
  unique_ptr<uint8_t[]> leaf(new uint8_t[leaf_size_]);
  unique_ptr<char[]> key_str(new char[key_size_ * 8]);
  unique_ptr<char[]> leaf_str(new char[leaf_size_ * 8]);
  memset(&key[0], 0, key_size_);
  stringstream ss;
  while (bpf_get_next_key(fd_, &key[0], &key[0]) == 0) {
    if (bpf_lookup_elem(fd_, &key[0], &leaf[0]) == 0) {
      if (bpf_table_key_snprintf(bpf_module_, id_, &key_str[0], key_size_ * 8, &key[0]))
        return -EIO;
      if (bpf_table_leaf_snprintf(bpf_module_, id_, &leaf_str[0], leaf_size_ * 8, &leaf[0]))
        return -EIO;
      ss << &key_str[0] << " " << &leaf_str[0] << "\n";
    }
  }
  return read_helper(ss.str(), buf, size, offset, fi);
}

MapEntry::MapEntry(unique_ptr<uint8_t[]> key, size_t leaf_size)
    : StringFile(), key_(move(key)), leaf_size_(leaf_size), dirty_(false) {
  refresh();
}

int MapEntry::getattr(struct stat *st) {
  if (int rc = refresh())
    return rc;
  return StringFile::getattr(st);
}

int MapEntry::read(char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  return read_helper(data_, buf, size, offset, fi);
}

int MapEntry::truncate(off_t newsize) {
  if (data_.size() != (size_t)newsize)
    dirty_ = true;
  data_.resize(newsize);
  return 0;
}

int MapEntry::flush(struct fuse_file_info *fi) {
  unique_ptr<uint8_t[]> leaf(new uint8_t[leaf_size_]);
  MapDir *md = dynamic_cast<MapDir *>(parent_);
  if (!md) return -EBADF;

  if (!dirty_)
    return 0;
  if (data_.empty() || data_ == "\n")
    return 0;
  int fd = md->map_fd();
  if (bpf_table_leaf_sscanf(md->mod(), md->map_id(), data_.c_str(), &leaf[0]))
    return -EIO;
  if (bpf_update_elem(fd, &key_[0], &leaf[0], 0))
    return -EIO;
  return 0;
}

int MapEntry::unlink() {
  MapDir *md = dynamic_cast<MapDir *>(parent_);
  if (!md) return -EBADF;

  if (bpf_delete_elem(md->map_fd(), &key_[0]))
    return -ENOENT;
  return 0;
}

int MapEntry::write(const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  dirty_ = true;
  return StringFile::write(buf, size, offset, fi);
}

int MapEntry::refresh() {
  unique_ptr<uint8_t[]> leaf(new uint8_t[leaf_size_]);
  unique_ptr<char[]> leaf_str(new char[leaf_size_ * 8]);
  MapDir *md = dynamic_cast<MapDir *>(parent_);
  if (!md) return -EBADF;

  int fd = md->map_fd();
  if (bpf_lookup_elem(fd, &key_[0], &leaf[0]))
    return 0;
  if (bpf_table_leaf_snprintf(md->mod(), md->map_id(), &leaf_str[0], leaf_size_ * 8, &leaf[0]))
    return -EIO;
  data_ = string(&leaf_str[0]) + "\n";
  return 0;
}

int MapEntry::open(struct fuse_file_info *fi) {
  if (int rc = refresh())
    return rc;
  return File::open(fi);
}

}  // namespace bcc
