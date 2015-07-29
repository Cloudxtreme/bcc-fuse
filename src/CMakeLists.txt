# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

set(CMAKE_SHARED_LINKER_FLAGS "-Wl,--exclude-libs=ALL")

add_library(bccclient SHARED client.c)

add_executable(bcc-fuser main.cc mount.cc dir.cc file.cc link.cc socket.cc)
target_link_libraries(bcc-fuser ${FUSE_LIBRARIES} ${LIBBPF} bccclient pthread)

# if gcc 4.9 or higher is used, static libstdc++ is a good option
if (CMAKE_COMPILER_IS_GNUCC)
  execute_process(COMMAND ${CMAKE_C_COMPILER} -dumpversion OUTPUT_VARIABLE GCC_VERSION)
  if (GCC_VERSION VERSION_GREATER 4.9 OR GCC_VERSION VERSION_EQUAL 4.9)
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -static-libstdc++")
  endif()
endif()

install(TARGETS bccclient LIBRARY DESTINATION lib${LIBSUFFIX})
install(FILES client.h DESTINATION include/bcc)
