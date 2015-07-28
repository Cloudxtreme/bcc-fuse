#!/bin/bash

function fail() {
  echo "$1"
  exit 1
}

D=/tmp/bcc

sudo mkdir -p $D/foo
echo -e 'BPF_TABLE("array", int, int, bar, 10);\nint hello(void *ctx) { return 0; }' | sudo tee $D/foo/source
[[ $(sudo cat $D/foo/valid) = "1" ]] || fail "foo/valid != 1"
[[ $(sudo cat $D/foo/maps/bar/fd) -ge 0 ]] || fail "foo/maps/bar/fd < 0"

sudo mkdir -p $D/fuz
echo -e 'BPF_TABLE("array", int, int, baz, 10);\nint hello(void *ctx) { return 0; }' | sudo tee $D/fuz/source
