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
#include <bcc/bpf_common.h>

#include "mount.h"
#include "string_util.h"

using std::map;
using std::string;
using std::unique_ptr;

namespace bcc {

Link::Link(mode_t mode, const string &dst)
    : Inode(link_e, mode), dst_(dst) {
}

int Link::getattr(struct stat *st) {
  st->st_mode = S_IFLNK | 0777;
  st->st_nlink = 1;
  st->st_size = dst_.size();
  return 0;
}

int Link::readlink(char *buf, size_t size) {
  strncpy(buf, dst_.c_str(), size);
  return 0;
}

}  // namespace bcc
