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

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <sstream>
#include <vector>

namespace bcc {

static inline
std::string operator"" _s(const char *s, size_t n) { return std::string(s, n); }

static inline
std::vector<std::string> split(const std::string &s, char delim) {
  std::stringstream ss(s);
  std::string item;
  std::vector<std::string> tokens;
  while (std::getline(ss, item, delim))
    if (!item.empty())
      tokens.push_back(item);
  return tokens;
}

template <class T, class... Args>
typename std::enable_if<!std::is_array<T>::value, std::unique_ptr<T>>::type
make_unique(Args &&... args) {
  return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}

class Path {
 public:
  explicit Path(const char *path)
      : p_(path), orig_(path), cur_("."), save_(nullptr) {
    next_ = strtok_r((char *)p_.c_str(), "/", &save_);
  }
  Path * consume() {
    cur_ = next_;
    next_ = strtok_r(nullptr, "/", &save_);
    return this;
  }
  const char * full() const { return orig_; }
  const char * next() const { return next_; }
  const char * cur() const { return cur_; }
 private:
  Path(const Path &) = delete;
  std::string p_;
  const char *orig_;
  const char *next_;
  const char *cur_;
  char *save_;
};

}  // namespace bcc
