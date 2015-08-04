# BCC Fuse Filesystem

This project contains code to mount a filesystem style interface to control
[BCC][1].  A user will be able to write C code into files inside of the mounted
directory, and the Fuse process will compile and load the code on behalf of the
file owner.  The fuse agent will also keep the BPF programs loaded and active,
so that the maps contained therein can be kept persistent and/or shared amonst
multiple programs.

## Requirements

### Compile and make install [BCC][1] and all of its requirements.

### Install fuse development library

```
yum install fuse-devel
```
or
```
apt-get install libfuse-dev
```

## Setup

```
git clone https://github.com/iovisor/bcc-fuse
mkdir bcc-fuse/build
cd bcc-fuse/build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr
make
sudo make install
make test
```

[1]: https://github.com/iovisor/bcc
