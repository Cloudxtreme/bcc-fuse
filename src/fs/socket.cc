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

#include <future>
#include <unistd.h>

#include "client.h"
#include "mount.h"
#include "string_util.h"

using std::thread;

namespace bcc {

Socket::Socket(mode_t mode, dev_t rdev)
  : Inode(socket_e), rdev_(rdev) {
}

int Socket::getattr(struct stat *st) {
  st->st_mode = S_IFSOCK | 0777;
  st->st_nlink = 1;
  return 0;
}

FunctionSocket::~FunctionSocket() {
  close(fd_);
  thread_.join();
}

FunctionSocket::FunctionSocket(mode_t mode, dev_t rdev, int fd)
    : Socket(mode, rdev), fd_(fd), ready_(false) {
  auto fn = [&] () {
    auto p = "/tmp/bcc/" + path();
    bcc_send_fd(p.c_str(), fd_);
  };
  // todo: make this lighter weight - select loop and/or on-demand
  thread_ = thread(fn);
}

int FunctionSocket::getattr(struct stat *st) {
  if (!ready_)
    return -ENOENT;
  return Socket::getattr(st);
}

int FunctionSocket::mknod() {
  if (ready_)
    return -EEXIST;
  ready_ = true;
  return 0;
}

}  // namespace bcc
