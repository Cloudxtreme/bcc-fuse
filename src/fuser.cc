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

#include <cstring>
#include <fuse.h>
#include <string>
#include "fuser.h"

using std::string;

Fuser::Fuser() {
  oper_.reset(new fuse_operations);
  memset(&*oper_, 0, sizeof(*oper_));
  oper_->getattr = getattr_;
  oper_->readdir = readdir_;
  oper_->open = open_;
  oper_->read = read_;
}

Fuser::~Fuser() {
}

Fuser * Fuser::self() {
  return static_cast<Fuser *>(fuse_get_context()->private_data);
}

int Fuser::getattr(const char *path, struct stat *st) {
  int rc = 0;
  memset(st, 0, sizeof(*st));
  if (!strcmp(path, "/")) {
    st->st_mode = S_IFDIR | 0755;
    st->st_nlink = 2;
  } else if (!strcmp(path, "/hello")) {
    st->st_mode = S_IFREG | 0444;
    st->st_nlink = 1;
    string data = "Hello, World!\n";
    st->st_size = data.size();
  } else {
    rc = -ENOENT;
  }
  return rc;
}
int Fuser::readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
                   struct fuse_file_info *fi) {
  if (strcmp(path, "/"))
    return -ENOENT;
  filler(buf, ".", nullptr, 0);
  filler(buf, "..", nullptr, 0);
  filler(buf, "hello", nullptr, 0);
  return 0;
}
int Fuser::open(const char *path, struct fuse_file_info *fi) {
  if (strcmp(path, "/hello"))
    return -ENOENT;
  if ((fi->flags & 3) != O_RDONLY)
    return -EACCES;
  return 0;
}
int Fuser::read(const char *path, char *buf, size_t size, off_t offset,
                struct fuse_file_info *fi) {
  if (strcmp(path, "/hello"))
    return -ENOENT;
  string data = "Hello, World!\n";
  if ((size_t)offset < data.size()) {
    if ((size_t)offset + size > data.size())
      size = data.size() - offset;
    memcpy(buf, data.data() + offset, size);
  } else {
    size = 0;
  }
  return size;
}

int Fuser::run(int argc, char **argv) {
  return fuse_main(argc, argv, &*oper_, this);
}
