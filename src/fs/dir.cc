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
#include <fuse.h>
#include <string>
#include <bcc/bpf_common.h>
#include <bcc/libbpf.h>
#include <unistd.h>

#include "mount.h"
#include "string_util.h"

using std::map;
using std::move;
using std::string;
using std::unique_ptr;

namespace bcc {

Dir::Dir(mode_t mode)
    : Inode(dir_e), n_files_(0), n_dirs_(0), mode_(mode) {
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
  filler(buf, ".", nullptr, 0);
  filler(buf, "..", nullptr, 0);
  for (auto it = children_.begin(); it != children_.end(); ++it)
    filler(buf, it->first.c_str(), nullptr, 0);
  return 0;
}

int Dir::mknod(const char *name, mode_t mode, dev_t rdev) {
  if (S_ISSOCK(mode))
    add_child(name, make_unique<Socket>(mode, rdev));
  else
    return -EPERM;
  return 0;
}

void Dir::add_child(const string &name, unique_ptr<Inode> node) {
  remove_child(name);
  if (node->type() == file_e)
    ++n_files_;
  else
    ++n_dirs_;
  node->set_parent(this);
  children_[name] = move(node);
}

void Dir::remove_child(const string &name) {
  auto it = children_.find(name);
  if (it != children_.end()) {
    if (it->second->type() == file_e)
      --n_files_;
    else
      --n_dirs_;
    it->second->set_parent(nullptr);
    children_.erase(it);
  }
}

string Dir::path(const Inode *node) const {
  for (auto&& it : children_) {
    if (&*it.second == node)
      return Inode::path() + "/" + it.first;
  }
  return "?";
}

int RootDir::mkdir(const char *path, mode_t mode) {
  auto it = children_.find(path);
  if (it != children_.end())
    return -EEXIST;
  add_child(path, make_unique<ProgramDir>(mode));
  return 0;
}

ProgramDir::ProgramDir(mode_t mode)
    : Dir(mode), bpf_module_(nullptr) {
  add_child("source", make_unique<SourceFile>());
  add_child("valid", make_unique<StatFile>("0\n"));
}

ProgramDir::~ProgramDir() {
  unload();
}

int ProgramDir::load(const char *text) {
  StatFile *validf = dynamic_cast<StatFile *>(&*children_["valid"]);
  if (!validf) return 1;
  void *m = bpf_module_create_from_string(text, 0);
  if (!m) {
    validf->set_data("0\n");
    return 1;
  }
  bpf_module_ = m;
  validf->set_data("1\n");

  auto functions = make_unique<Dir>(mode_);
  size_t num_functions = bpf_num_functions(bpf_module_);
  for (size_t i = 0; i < num_functions; ++i) {
    functions->add_child(bpf_function_name(bpf_module_, i),
                         make_unique<FunctionDir>(mode_, bpf_module_, i));
  }
  add_child("functions", move(functions));

  auto maps = make_unique<Dir>(mode_);
  size_t num_tables = bpf_num_tables(bpf_module_);
  for (size_t i = 0; i < num_tables; ++i) {
    maps->add_child(bpf_table_name(bpf_module_, i),
                    make_unique<MapDir>(mode_, bpf_table_fd_id(bpf_module_, i)));
  }
  add_child("maps", move(maps));
  return 0;
}

void ProgramDir::unload() {
  if (StatFile *validf = dynamic_cast<StatFile *>(&*children_["valid"]))
    validf->set_data("0\n");
  if (bpf_module_)
    bpf_module_destroy(bpf_module_);
  remove_child("functions");
  remove_child("maps");
  bpf_module_ = nullptr;
}

FunctionDir::FunctionDir(mode_t mode, void *bpf_module, int id)
    : Dir(mode), bpf_module_(bpf_module), id_(id) {
  add_child("type", make_unique<FunctionTypeFile>());
}

int FunctionDir::load(const string &type) {
  bpf_prog_type prog_type = BPF_PROG_TYPE_UNSPEC;
  if (type == "filter")
    prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
  else if (type == "kprobe")
    prog_type = BPF_PROG_TYPE_KPROBE;
  else if (type == "sched_cls")
    prog_type = BPF_PROG_TYPE_SCHED_CLS;
  else if (type == "sched_act")
    prog_type = BPF_PROG_TYPE_SCHED_ACT;
  else
    return -1;
  char log_buf[64 * 1024];
  int fd = bpf_prog_load(prog_type, (const bpf_insn *)bpf_function_start_id(bpf_module_, id_),
                         bpf_function_size_id(bpf_module_, id_), bpf_module_license(bpf_module_),
                         bpf_module_kern_version(bpf_module_), log_buf, sizeof(log_buf));
  if (fd < 0) {
    add_child("error", make_unique<StatFile>(log_buf));
    return -1;
  }
  add_child("fd", make_unique<FunctionSocket>(mode_, 0, fd));
  return 0;
}

void FunctionDir::unload() {
  remove_child("fd");
}

MapDir::MapDir(mode_t mode, int fd)
    : Dir(mode), fd_(fd) {
  add_child("fd", make_unique<StatFile>(std::to_string(fd_) + "\n"));
  add_child("link", make_unique<Link>(mode_, "/tmp/bcc-fd-" + std::to_string(fd_)));
}

}  // namespace bcc
