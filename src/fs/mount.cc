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

#include <algorithm>
#include <cstring>
#include <fuse.h>
#include <string>
#include <vector>

#include "mount.h"
#include "string_util.h"

namespace bcc {

using std::find;
using std::string;
using std::vector;

Mount::Mount() : flags_(0) {
  log_ = fopen("/tmp/bcc-fuse.log", "w");
  oper_.reset(new fuse_operations);
  root_.reset(new RootDir(0755));
  root_->set_mount(this);
  memset(&*oper_, 0, sizeof(*oper_));
  oper_->getattr = getattr_;
  oper_->readdir = readdir_;
  oper_->mkdir = mkdir_;
  oper_->mknod = mknod_;
  oper_->create = create_;
  oper_->unlink = unlink_;
  oper_->open = open_;
  oper_->read = read_;
  oper_->write = write_;
  oper_->truncate = truncate_;
  oper_->flush = flush_;
  oper_->readlink = readlink_;
  oper_->ioctl = ioctl_;
}

Mount::~Mount() {
  fclose(log_);
}

Mount * Mount::instance() {
  return static_cast<Mount *>(fuse_get_context()->private_data);
}

int Mount::getattr(const char *path, struct stat *st) {
  log("getattr: %s\n", path);
  memset(st, 0, sizeof(*st));
  Path p(path);
  Inode *leaf = root_->leaf(&p);
  if (!leaf || p.next())
    return -ENOENT;
  return leaf->getattr(st);
}

int Mount::readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
                   struct fuse_file_info *fi) {
  log("readdir: %s\n", path);
  Path p(path);
  Inode *leaf = root_->leaf(&p);
  if (!leaf || p.next())
    return -ENOENT;
  if (Dir *dir = dynamic_cast<Dir *>(leaf))
    return dir->readdir(buf, filler, offset, fi);
  return -EBADF;
}

int Mount::mkdir(const char *path, mode_t mode) {
  log("mkdir: %s\n", path);
  Path p(path);
  Inode *leaf = root_->leaf(&p);
  p.consume();
  if (!p.cur())
    return -EEXIST;
  if (p.next())
    return -ENOENT;
  if (Dir *dir = dynamic_cast<Dir *>(leaf))
    return dir->mkdir(p.cur(), mode);
  return -ENOTDIR;
}

int Mount::mknod(const char *path, mode_t mode, dev_t rdev) {
  log("mknod: %s %#x %#x\n", path, mode, rdev);
  Path p(path);
  Inode *leaf = root_->leaf(&p);
  // special case hack for binding on top of myself
  if (FDSocket *fd_sock = dynamic_cast<FDSocket *>(leaf))
    return fd_sock->mknod();
  p.consume();
  if (!p.cur())
    return -EEXIST;
  if (p.next())
    return -ENOENT;
  if (Dir *dir = dynamic_cast<Dir *>(leaf))
    return dir->mknod(p.cur(), mode, rdev);
  return -ENOTDIR;
}

int Mount::create(const char *path, mode_t mode, struct fuse_file_info *fi) {
  log("create: %s\n", path);
  Path p(path);
  Inode *leaf = root_->leaf(&p);
  p.consume();
  if (!p.cur())
    return -EEXIST;
  if (p.next())
    return -ENOENT;
  if (Dir *dir = dynamic_cast<Dir *>(leaf))
    return dir->create(p.cur(), mode, fi);
  return -ENOTDIR;
}

int Mount::unlink(const char *path) {
  log("unlink: %s\n", path);
  Path p(path);
  Inode *leaf = root_->leaf(&p);
  if (!leaf || p.next())
    return -ENOENT;
  if (Dir *dir = dynamic_cast<MapDir *>(leaf->parent()))
    return dir->unlink(p.cur());
  return -EPERM;
}

int Mount::open(const char *path, struct fuse_file_info *fi) {
  log("open: %s\n", path);
  Path p(path);
  Inode *leaf = root_->leaf(&p);
  if (!leaf || p.next())
    return -ENOENT;
  if (File *file = dynamic_cast<File *>(leaf))
    return file->open(fi);
  return -EISDIR;
}

int Mount::read(const char *path, char *buf, size_t size, off_t offset,
                struct fuse_file_info *fi) {
  log("read: %s sz=%zu off=%zu\n", path, size, offset);
  Inode *leaf = (Inode *)fi->fh;
  if (!leaf)
    return -ENOENT;
  if (File *file = dynamic_cast<File *>(leaf))
    return file->read(buf, size, offset, fi);
  return -EISDIR;
}

int Mount::write(const char *path, const char *buf, size_t size, off_t offset,
                 struct fuse_file_info *fi) {
  log("write: %s sz=%zu off=%zu\n", path, size, offset);
  Inode *leaf = (Inode *)fi->fh;
  if (!leaf)
    return -ENOENT;
  if (File *file = dynamic_cast<File *>(leaf))
    return file->write(buf, size, offset, fi);
  return -EISDIR;
}

int Mount::truncate(const char *path, off_t newsize) {
  log("truncate: %s sz=%zd\n", path, newsize);
  Path p(path);
  Inode *leaf = root_->leaf(&p);
  if (!leaf || p.next())
    return -ENOENT;
  if (File *file = dynamic_cast<File *>(leaf))
    return file->truncate(newsize);
  return -EISDIR;
}

int Mount::flush(const char *path, struct fuse_file_info *fi) {
  log("flush: %s\n", path);
  Inode *leaf = (Inode *)fi->fh;
  if (!leaf)
    return -ENOENT;
  if (File *file = dynamic_cast<File *>(leaf))
    return file->flush(fi);
  return -EISDIR;
}

int Mount::readlink(const char *path, char *buf, size_t size) {
  log("readlink: %s\n", path);
  Path p(path);
  Inode *leaf = root_->leaf(&p);
  if (!leaf || p.next())
    return -ENOENT;
  if (Link *link = dynamic_cast<Link *>(leaf))
    return link->readlink(buf, size);
  return -EINVAL;
}


int Mount::ioctl(const char *path, int cmd, void *arg, struct fuse_file_info *fi,
                 unsigned int flags, void *data) {
  log("ioctl: %s\n", path);
  return 0;
}

int Mount::run(int argc, char **argv) {
  mountpath_.assign(argv[argc - 1]);
  return fuse_main(argc, argv, &*oper_, this);
}

}  // namespace bcc
