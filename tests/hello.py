#!/usr/bin/env python

import ctypes
from builtins import input
from bpf import BPF
import os
from subprocess import call
import sys

bcc = ctypes.CDLL("libbccclient.so")
bcc.bcc_recv_fd.restype = int
bcc.bcc_recv_fd.argtypes = [ctypes.c_char_p]

if not os.path.exists("/tmp/bcc/foo"):
    os.mkdir("/tmp/bcc/foo")

# First, create a valid C but invalid BPF program, check the error message
with open("/tmp/bcc/foo/source", "w") as f:
    f.write("""
int hello(void *ctx) {
    for (;;) bpf_trace_printk("Hello, World %d\\n");
    return 0;
}
""")
try:
    with open("/tmp/bcc/foo/functions/hello/type", "w") as f:
        f.write('kprobe')
except:
    with open("/tmp/bcc/foo/functions/hello/error") as f:
        print("Verifier error:")
        print(f.read())
        print("Retrying...")

# Correct the error
with open("/tmp/bcc/foo/source", "w") as f:
    f.write("""
int hello(void *ctx) {
    bpf_trace_printk("Hello, World %d\\n");
    return 0;
}
""")

with open("/tmp/bcc/foo/functions/hello/type", "w") as f:
    f.write('kprobe')

# Pause here due to fuse race condition, TBD soon
input("Begin: ")
fd = bcc.bcc_recv_fd(b"/tmp/bcc/foo/functions/hello/fd")

if fd < 0: raise Exception("invalid fd %d" % fd)

hello = BPF.Function(None, "hello", fd)
BPF.attach_kprobe(hello, "sys_clone")
try:
    call(["cat", "/sys/kernel/debug/tracing/trace_pipe"])
except KeyboardInterrupt:
    pass
