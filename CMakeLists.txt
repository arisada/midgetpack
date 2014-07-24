project(midgetpack C)

# Required cmake version
cmake_minimum_required(VERSION 2.6.0)

# global needed variables
set(APPLICATION_NAME ${PROJECT_NAME})

set(APPLICATION_VERSION_MAJOR "0")
set(APPLICATION_VERSION_MINOR "1")
set(APPLICATION_VERSION_PATCH "0")

set(APPLICATION_VERSION "${APPLICATION_VERSION_MAJOR}.${APPLICATION_VERSION_MINOR}.${APPLICATION_VERSION_PATCH}")

# where to look first for cmake modules, before ${CMAKE_ROOT}/Modules/ is checked
set(CMAKE_MODULE_PATH
  ${CMAKE_SOURCE_DIR}/cmake/Modules
)

# add definitions
include(DefineCMakeDefaults)
include(DefinePlatformDefaults)
include(DefineCompilerFlags)
include(DefineOptions.cmake)

# disallow in-source build
include(MacroEnsureOutOfSourceBuild)
macro_ensure_out_of_source_build("${PROJECT_NAME} requires an out of source build. Please create a separate build directory and run 'cmake /path/to/${PROJECT_NAME} [options]' there.")

# Test for presence of 64 bits/32 bits compiler
#include(CheckCCompilerFlagSSP)
include(CheckCCompilerFlag)
SET(SAFE_CMAKE_REQUIRED_FLAGS ${CMAKE_REQUIRED_FLAGS})
SET(CMAKE_REQUIRED_FLAGS "-m64")
check_c_compiler_flag("-m64" CCOMPILER_64)
SET(CMAKE_REQUIRED_FLAGS "-m32")
check_c_compiler_flag("-m32" CCOMPILER_32)
SET(CMAKE_REQUIRED_FLAGS "-march=armv6")
check_c_compiler_flag("-march=armv6" CCOMPILER_ARMV6)
SET(CMAKE_REQUIRED_FLAGS ${SAFE_CMAKE_REQUIRED_FLAGS})

if(CCOMPILER_32 OR WITH_PRECOMPILED_STUBS)
	set(HAVE_LINUX_X86 1)
	set(HAVE_FREEBSD_X86 1)
endif(CCOMPILER_32 OR WITH_PRECOMPILED_STUBS)

if(CCOMPILER_64 OR WITH_PRECOMPILED_STUBS)
	set(HAVE_LINUX_AMD64 1)
	set(HAVE_FREEBSD_AMD64 1)
endif(CCOMPILER_64 OR WITH_PRECOMPILED_STUBS)

if(CCOMPILER_ARMV6 OR WITH_PRECOMPILED_STUBS)
	set(HAVE_LINUX_ARMV6 1)
endif(CCOMPILER_ARMV6 OR WITH_PRECOMPILED_STUBS)

# config.h checks
include(ConfigureChecks.cmake)
configure_file(config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h)

# check subdirectories
add_subdirectory(src)

# cmake config files
#set(LIBSSH_LIBRARY_NAME @CMAKE_SHARED_LIBRARY_PREFIX@ssh@CMAKE_SHARED_LIBRARY_SUFFIX@)
#set(LIBSSH_THREADS_LIBRARY_NAME @CMAKE_SHARED_LIBRARY_PREFIX@ssh@CMAKE_SHARED_LIBRARY_SUFFIX@)

#configure_file(${PROJECT_NAME}-config.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake @ONLY)
#configure_file(${PROJECT_NAME}-config-version.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config-version.cmake @ONLY)

# in tree build settings
#configure_file(libssh-build-tree-settings.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/libssh-build-tree-settings.cmake @ONLY)

