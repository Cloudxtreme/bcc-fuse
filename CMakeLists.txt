# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
cmake_minimum_required(VERSION 2.8.7)

project(bcc-fuse)

set(PROJECT_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
set(PROJECT_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}")
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake/Modules/")

enable_testing()

include(cmake/GetGitRevisionDescription.cmake)
get_git_head_revision(GIT_REFSPEC GIT_SHA1)
string(SUBSTRING "${GIT_SHA1}" 0 8 GIT_SHA1_SHORT)
git_describe(GIT_DESCRIPTION)
git_describe(GIT_TAG_LAST "--abbrev=0")
git_get_exact_tag(GIT_TAG_EXACT)
if(NOT REVISION)
  string(SUBSTRING "${GIT_TAG_LAST}-${GIT_SHA1_SHORT}" 1 -1 REVISION)
  if(GIT_TAG_EXACT)
    string(SUBSTRING "${GIT_TAG_EXACT}" 1 -1 REVISION)
    message(STATUS "Currently on Git tag ${GIT_TAG_EXACT}")
  else ()
    message(STATUS "Latest recognized Git tag is ${GIT_TAG_LAST}")
    set(GIT_TAG_EXACT "")
  endif()
  message(STATUS "Git HEAD is ${GIT_SHA1}")
endif()

# strip leading 'v', and make unique for the tag
message(STATUS "Revision is ${REVISION}")

find_package(PkgConfig)
find_library(LIBBCC NAMES bcc)
pkg_search_module(LIBBCC REQUIRED libbcc)
message(STATUS "Found libbcc ${LIBBCC_LIBRARIES}")

find_package(fuse REQUIRED)
set(CMAKE_C_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -Werror")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${FUSE_DEFINITIONS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DFUSE_USE_VERSION=30")

include_directories(${LIBBPF_INCLUDE_DIRS})

#include(scripts/GetGitRevisionDescription.cmake)
get_property(LIB64 GLOBAL PROPERTY FIND_LIBRARY_USE_LIB64_PATHS)
if(LIB64)
  set(LIBSUFFIX 64)
endif()

add_subdirectory(src)
add_subdirectory(tests)

set(CPACK_PACKAGE_NAME "bcc-fuse")
set(CPACK_PACKAGE_VERSION "${REVISION}")
set(CPACK_PACKAGE_CONTACT "Brenden Blanco <bblanco@plumgrid.com")
if(EXISTS "/etc/redhat-release")
  set(CPACK_GENERATOR "RPM")
else()
  set(CPACK_GENERATOR "DEB")
endif()
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}")
set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6, libstdc++6, libbcc, libfuse2")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Fuse filesystem for BPF Compiler Collection (BCC)")
include(CPack)
