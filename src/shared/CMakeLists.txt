project(mpack-shared C)

set(MP_SHARED_STATIC_LIBRARY
	mp_shared_static
	CACHE INTERNAL "midgetpack-shared static library"
)

set(mp_shared_SRCS
	aes.c
	crypto.c
	curve25519_ref.c
	sha256.c
)

include_directories(
	${MPACK_INCLUDE_DIRS}
)

add_library(${MP_SHARED_STATIC_LIBRARY} STATIC ${mp_shared_SRCS})
set_target_properties(
	${MP_SHARED_STATIC_LIBRARY}
	PROPERTIES
	OUTPUT_NAME
	shared
	ARCHIVE_OUTPUT_DIRECTORY
	${CMAKE_CURRENT_BINARY_DIR}/${OUTPUT_SUFFIX}
	COMPILE_FLAGS
	"-O2 -g"
)

if(WITH_STUB_DEBUG)
	set (FLAGS "-O0 -g -fno-stack-protector")
else(WITH_STUB_DEBUG)
	set (FLAGS "-Os -fno-stack-protector")
endif(WITH_STUB_DEBUG)
If(CCOMPILER_64)

set(MP_SHARED_STATIC_LIBRARY_AMD64
	mp_shared_static_amd64
	CACHE INTERNAL "midgetpack-shared_amd64 static library"
)

add_library(${MP_SHARED_STATIC_LIBRARY_AMD64} STATIC ${mp_shared_SRCS})
set_target_properties(
	${MP_SHARED_STATIC_LIBRARY_AMD64}
	PROPERTIES
	OUTPUT_NAME
	shared_amd64
	ARCHIVE_OUTPUT_DIRECTORY
	${CMAKE_CURRENT_BINARY_DIR}/${OUTPUT_SUFFIX}
	COMPILE_FLAGS
	"${FLAGS} -m64"
)

Endif(CCOMPILER_64)

If(CCOMPILER_32)

set(MP_SHARED_STATIC_LIBRARY_X86
	mp_shared_static_x86
	CACHE INTERNAL "midgetpack-shared_x86 static library"
)

add_library(${MP_SHARED_STATIC_LIBRARY_X86} STATIC ${mp_shared_SRCS})
set_target_properties(
	${MP_SHARED_STATIC_LIBRARY_X86}
	PROPERTIES
	OUTPUT_NAME
	shared_x86
	ARCHIVE_OUTPUT_DIRECTORY
	${CMAKE_CURRENT_BINARY_DIR}/${OUTPUT_SUFFIX}
	COMPILE_FLAGS
	"${FLAGS} -m32"
)

Endif(CCOMPILER_32)

If(CCOMPILER_ARMV6)

set(MP_SHARED_STATIC_LIBRARY_ARMV6
	mp_shared_static_armv6
	CACHE INTERNAL "midgetpack-shared_armv6 static library"
)

add_library(${MP_SHARED_STATIC_LIBRARY_ARMV6} STATIC ${mp_shared_SRCS})
set_target_properties(
	${MP_SHARED_STATIC_LIBRARY_ARMV6}
	PROPERTIES
	OUTPUT_NAME
	shared_armv6
	ARCHIVE_OUTPUT_DIRECTORY
	${CMAKE_CURRENT_BINARY_DIR}/${OUTPUT_SUFFIX}
	COMPILE_FLAGS
	"${FLAGS} -march=armv6"
)

Endif(CCOMPILER_ARMV6)

