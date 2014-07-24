project(tests C)

set(tests_SRCS
	test.c
)

include_directories(
	${MPACK_INCLUDE_DIRS}
)

If(CCOMPILER_64)

add_executable(test-amd64-static ${tests_SRCS})
add_executable(test-amd64-dynamic ${tests_SRCS})

set_target_properties(
	test-amd64-static
	PROPERTIES
	COMPILE_FLAGS
	"-static -m64"
	LINK_FLAGS "-static -m64"
)

set_target_properties(
	test-amd64-dynamic
	PROPERTIES
	COMPILE_FLAGS
	"-m64"
	LINK_FLAGS "-m64"
)

Endif(CCOMPILER_64)

If(CCOMPILER_32)

add_executable(test-x86-static ${tests_SRCS})
add_executable(test-x86-dynamic ${tests_SRCS})

set_target_properties(
	test-x86-static
	PROPERTIES
	COMPILE_FLAGS
	"-static -m32"
	LINK_FLAGS "-static -m32"
)

set_target_properties(
	test-x86-dynamic
	PROPERTIES
	COMPILE_FLAGS
	"-m32"
	LINK_FLAGS "-m32"
)

Endif(CCOMPILER_32)

If(CCOMPILER_ARMV6)

add_executable(test-arm-static ${tests_SRCS})
add_executable(test-arm-dynamic ${tests_SRCS})

set_target_properties(
	test-arm-static
	PROPERTIES
	COMPILE_FLAGS
	"-static -march=armv6"
	LINK_FLAGS "-static -march=armv6"
)

set_target_properties(
	test-arm-dynamic
	PROPERTIES
	COMPILE_FLAGS
	"-march=armv6"
	LINK_FLAGS "-march=armv6"
)

Endif(CCOMPILER_ARMV6)
