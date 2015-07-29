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

#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "client.h"

int bcc_recv_fd(const char *path) {
  ssize_t size;
  int fd = -1, sock = -1;
  union {
    struct cmsghdr cmsghdr;
    char control[CMSG_SPACE(sizeof(int))];
  } cmsgu;
  struct cmsghdr *cmsg;

  char buf[8];
  struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };

  struct msghdr msg = {
    .msg_iov = &iov,
    .msg_iovlen = 1,
    .msg_control = cmsgu.control,
    .msg_controllen = sizeof(cmsgu.control),
    .msg_name = NULL,
    .msg_namelen = 0,
  };

  sock = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (sock < 0) {
    perror("socket");
    goto cleanup;
  }
  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, path, sizeof(addr.sun_path));

  if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("connect");
    goto cleanup;
  }

  size = recvmsg(sock, &msg, 0);
  if (size < 0) {
    perror("recvmsg");
    goto cleanup;
  }
  cmsg = CMSG_FIRSTHDR(&msg);
  if (!cmsg || cmsg->cmsg_len != CMSG_LEN(sizeof(int))) {
    fprintf(stderr, "recvmsg: invalid control response\n");
    goto cleanup;
  }
  if (cmsg->cmsg_level != SOL_SOCKET) {
    fprintf(stderr, "recvmsg: invalid cmsg_level %d\n", cmsg->cmsg_level);
    goto cleanup;
  }
  if (cmsg->cmsg_type != SCM_RIGHTS) {
    fprintf(stderr, "recvmsg: invalid cmsg_type %d\n", cmsg->cmsg_type);
    goto cleanup;
  }

  fd = *((int *)CMSG_DATA(cmsg));

cleanup:
  if (sock >= 0)
    close(sock);

  return fd;
}
