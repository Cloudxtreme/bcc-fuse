add_executable(test_clone clone.c)
target_link_libraries(test_clone bccclient)
include_directories(${CMAKE_SOURCE_DIR}/src)

add_test(NAME test_hello WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND sudo ${CMAKE_CURRENT_SOURCE_DIR}/hello.py)
