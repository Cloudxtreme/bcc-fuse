# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

add_executable(bcc-fuser main.cc fuser.cc)
target_link_libraries(bcc-fuser ${FUSE_LIBRARIES})