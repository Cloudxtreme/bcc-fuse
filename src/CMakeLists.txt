# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set(CMAKE_SHARED_LINKER_FLAGS "-Wl,--exclude-libs=ALL")

add_library(bccclient SHARED client.c)
set_source_files_properties(client.c PROPERTIES COMPILE_FLAGS -Wno-strict-aliasing)

add_executable(bcc-fuser main.cc fs/mount.cc fs/inode.cc fs/dir.cc fs/file.cc fs/link.cc fs/socket.cc client.c)
target_link_libraries(bcc-fuser ${FUSE_LIBRARIES} ${LIBBPF} pthread)

# if gcc 4.9 or higher is used, static libstdc++ is a good option
if (CMAKE_COMPILER_IS_GNUCC)
  execute_process(COMMAND ${CMAKE_C_COMPILER} -dumpversion OUTPUT_VARIABLE GCC_VERSION)
  if (GCC_VERSION VERSION_GREATER 4.9 OR GCC_VERSION VERSION_EQUAL 4.9)
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -static-libstdc++")
  endif()
endif()

install(TARGETS bcc-fuser RUNTIME DESTINATION bin)
install(TARGETS bccclient LIBRARY DESTINATION lib${LIBSUFFIX})
install(FILES client.h DESTINATION include/bcc)
