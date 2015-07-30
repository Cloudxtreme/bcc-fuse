#!/usr/bin/env python

import ctypes
from builtins import input
from bpf import BPF
import os
from subprocess import call

bcc = ctypes.CDLL("libbccclient.so")
bcc.bcc_recv_fd.restype = int
bcc.bcc_recv_fd.argtypes = [ctypes.c_char_p]

os.mkdir("/tmp/bcc/foo")
with open("/tmp/bcc/foo/source", "w") as f:
    f.write('int hello(void *ctx) { bpf_trace_printk("Hello, World\\n"); return 0; }')
with open("/tmp/bcc/foo/functions/hello/type", "w") as f:
    f.write('kprobe')

input("> ")
fd = bcc.bcc_recv_fd(b"/tmp/bcc/foo/functions/hello/fd")

print("fd =", fd)
if fd < 0:
    raise Exception("invalid fd %d" % fd)
hello = BPF.Function(None, "hello", fd)
BPF.attach_kprobe(hello, "sys_clone")
try:
    call(["cat", "/sys/kernel/debug/tracing/trace_pipe"])
except KeyboardInterrupt:
    pass
