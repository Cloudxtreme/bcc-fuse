# BCC Fuse Filesystem

## Requirements

Compile and install [BCC](https://github.com/iovisor/bcc) and all of its
requirements.

## Examples

Currently, all that can be done with this filesystem is mount and compile a
BPF program. Use cases and explanation are TBD.

```
git checkout https://github.com/iovisor/bcc-fuse
cd bcc-fuse
mkdir build
cd build
cmake ..
make
mkdir tmp
sudo ./src/bcc-fuser -s tmp
mkdir tmp/foo
echo "int hello(void *ctx) { return 0; }" | sudo tee tmp/foo/source
cat tmp/foo/valid
# output should be "1"
sudo fusermount -u tmp/foo
```
