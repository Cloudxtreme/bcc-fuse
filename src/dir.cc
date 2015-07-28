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

Dir::Dir(Mount *mount, mode_t mode)
    : Inode(mount, dir_e), n_files_(0), n_dirs_(0), mode_(mode) {
}

Inode * Dir::leaf(Path *path) {
  if (!path->next())
    return this;
  auto it = children_.find(path->next());
  if (it == children_.end())
    return this;
  return it->second->leaf(path->consume());
}

int Dir::getattr(struct stat *st) {
  st->st_mode = S_IFDIR | mode_;
  st->st_nlink = 2 + n_dirs_;
  return 0;
}

int Dir::readdir(void *buf, fuse_fill_dir_t filler, off_t offset,
                 struct fuse_file_info *fi) {
  //log("Dir::readdir [%s] [%s]\n", path->cur(), path->next());
  filler(buf, ".", nullptr, 0);
  filler(buf, "..", nullptr, 0);
  for (auto it = children_.begin(); it != children_.end(); ++it)
    filler(buf, it->first.c_str(), nullptr, 0);
  return 0;
}

void Dir::add_child(const string &name, unique_ptr<Inode> node) {
  children_[name] = std::move(node);
}

void Dir::remove_child(const string &name) {
  children_.erase(name);
}

int RootDir::mkdir(const char *path, mode_t mode) {
  auto it = children_.find(path);
  if (it != children_.end())
    return -EEXIST;
  children_[path] = make_unique<ProgramDir>(mount(), mode);
  ++n_dirs_;
  return 0;
}

ProgramDir::ProgramDir(Mount *mount, mode_t mode)
    : Dir(mount, mode), bpf_module_(nullptr) {
  children_["maps"] = make_unique<Dir>(mount, mode);
  n_dirs_ = 1;
  children_["source"] = make_unique<SourceFile>(mount, this);
  children_["valid"] = make_unique<StatFile>(mount, "0\n");
  n_files_ = 2;
}

int ProgramDir::load_program(const char *text) {
  StatFile *validf = dynamic_cast<StatFile *>(&*children_["valid"]);
  if (!validf) return 1;
  void *m = bpf_module_create_from_string(text, mount_->flags());
  if (!m) {
    validf->set_data("0\n");
    return 1;
  }
  bpf_module_ = m;
  validf->set_data("1\n");
  map<string, int> function_fds;
  size_t num_functions = bpf_num_functions(bpf_module_);
  for (size_t i = 0; i < num_functions; ++i) {
    function_fds[bpf_function_name(bpf_module_, i)] = -1;
  }
  children_["functions"] = make_unique<FunctionDir>(mount(), mode_, function_fds);
  ++n_dirs_;

  Dir *mapd = dynamic_cast<Dir *>(&*children_["maps"]);
  size_t num_tables = bpf_num_tables(bpf_module_);
  for (size_t i = 0; i < num_tables; ++i) {
    mapd->add_child(bpf_table_name(bpf_module_, i),
                    make_unique<MapDir>(mount(), mode_, bpf_table_fd_id(bpf_module_, i)));
  }
  return 0;
}

int ProgramDir::unload_program() {
  StatFile *validf = dynamic_cast<StatFile *>(&*children_["valid"]);
  if (!validf) return 1;
  if (bpf_module_)
    bpf_module_destroy(bpf_module_);
  validf->set_data("0\n");
  children_.erase("functions");
  --n_dirs_;
  bpf_module_ = nullptr;
  return 0;
}

FunctionDir::FunctionDir(Mount *mount, mode_t mode, const map<string, int> &function_fds)
    : Dir(mount, mode), function_fds_(function_fds) {

  for (auto function : function_fds_) {
    children_[function.first] = make_unique<FunctionFile>(mount, function.second);
    ++n_files_;
  }
}

MapDir::MapDir(Mount *mount, mode_t mode, int fd)
    : Dir(mount, mode), fd_(fd) {
  children_["fd"] = make_unique<StatFile>(mount, std::to_string(fd_) + "\n");
  n_files_ = 1;
  children_["link"] = make_unique<Link>(mount, mode_, "/tmp/bcc-fd-" + std::to_string(fd_));
  ++n_dirs_;
}

}  // namespace bcc
