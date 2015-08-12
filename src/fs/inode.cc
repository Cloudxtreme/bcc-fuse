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

#include <string>
#include "mount.h"

using std::string;

namespace bcc {

Inode::Inode(InodeType type, mode_t mode)
    : parent_(nullptr), type_(type), mode_(mode) {
  mount_ = Mount::instance();
}

string Inode::path() const {
  if (parent_)
    return parent_->path(this);
  return mount_->mountpath();
}

}  // namespace bcc
