project(midgetpack C)

if (BSD OR SOLARIS OR OSX)
    find_package(Argp)
endif (BSD OR SOLARIS OR OSX)


set(MPACK_INCLUDE_DIRS
  ${CMAKE_SOURCE_DIR}/src/include
  ${CMAKE_BINARY_DIR}
  ${ARGP_INCLUDE_DIR}
  CACHE INTERNAL "include directory"
)

include_directories(
  ${MPACK_INCLUDE_DIRS}
)

SET(CMAKE_REQUIRED_FLAGS ${CMAKE_REQUIRED_FLAGS} "-g")
add_subdirectory(shared)
add_subdirectory(stub)
add_subdirectory(packer)
add_subdirectory(tests)

