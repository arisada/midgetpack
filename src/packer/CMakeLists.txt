project(midgetpack C)

set(midgetpack_SRCS
	crypto.c
	elf.c
	midgetpack.c
)

set(mpkex_SRCS
	crypto.c
	mpkex.c
)

include_directories(
	${MPACK_INCLUDE_DIRS}
)

add_executable(midgetpack ${midgetpack_SRCS})
target_link_libraries(midgetpack ${MP_SHARED_STATIC_LIBRARY} ${MP_STUBS} ${ARGP_LIBRARY})

add_executable(mpkex ${mpkex_SRCS})
target_link_libraries(mpkex ${MP_SHARED_STATIC_LIBRARY} ${ARGP_LIBRARY})

