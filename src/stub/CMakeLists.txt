project(mpack-stub C ASM-ATT)

set(mp_stub_SRCS
	pack_common.c
)
include(DefinePlatformDefaults)

include_directories(
	${MPACK_INCLUDE_DIRS}
)

# list of compiled stubs to link in the lib
set (mp_stubs_BINS)

if(WITH_STUB_DEBUG)
	set (FLAGS "-O0 -g -fno-stack-protector")
	set (LDFLAGS "")
else(WITH_STUB_DEBUG)
	set (FLAGS "-Os -fno-stack-protector")
	set (LDFLAGS "--strip-all")
endif(WITH_STUB_DEBUG)

if(FREEBSD)
	set(MACHINE_X86 "elf_i386_fbsd")
	set(MACHINE_AMD64 "elf_x86_64_fbsd")
else(FREEBSD)
	set(MACHINE_X86 "elf_i386")
	set(MACHINE_AMD64 "elf_x86_64")
	set(MACHINE_ARMV6 "armelf_linux_eabi")
endif(FREEBSD)

# Compile the C sources for one architecture and generate
# a libstub_static_${ARCH} library
function(COMPILE_ARCH_LIB _ARCH _FLAGS)
	set(_MP_LIBSTUB
		mp_libstub_static_${_ARCH}
		CACHE INTERNAL "libstub${_ARCH} static library"
	)

	add_library(${_MP_LIBSTUB} STATIC ${mp_stub_SRCS})
	set_target_properties(
		${_MP_LIBSTUB}
		PROPERTIES
		OUTPUT_NAME
		stub${_ARCH}
		ARCHIVE_OUTPUT_DIRECTORY
		${CMAKE_CURRENT_BINARY_DIR}/${OUTPUT_SUFFIX}
		COMPILE_FLAGS
		"${FLAGS} ${_FLAGS}"
	)
endfunction(COMPILE_ARCH_LIB)

set(CMAKE_C_LINK_EXECUTABLE 
	"/usr/bin/ld <CMAKE_C_LINK_FLAGS> <LINK_FLAGS> <OBJECTS> -o <TARGET>  <LINK_LIBRARIES>"
)

# compile for an ARCH,OS pair
function(COMPILE_ARCH_OS _OS _ARCH _CFLAGS _LDFLAGS _ASFLAGS _LIBS)
	set(_SOURCES pack_${_ARCH}.s ${_OS}_${_ARCH}.s)
#	message("sources: ${_SOURCES}")
	set(_EXECUTABLE stub_${_OS}_${_ARCH}) 
	add_executable(${_EXECUTABLE} ${_SOURCES})
	set_source_files_properties(${_SOURCES} PROPERTIES COMPILE_FLAGS "${_ASFLAGS}")

	SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
	target_link_libraries(
		${_EXECUTABLE} 
		mp_libstub_static_${_ARCH}
		"mp_shared_static_${_ARCH}"
		${_LIBS}
	)
	message("Exec: ${_EXECUTABLE}")	
	set_target_properties(
		${_EXECUTABLE}
		PROPERTIES
		LINK_FLAGS
		"${LDFLAGS} -static ${_LDFLAGS}"
	)
	
	add_custom_command(
		OUTPUT "${_EXECUTABLE}.o"
		COMMAND "ld" "-r" "-b" "binary" "-o" "${_EXECUTABLE}.o" "${_EXECUTABLE}"
		DEPENDS "${_EXECUTABLE}"
	)

	set (mp_stubs_BINS 
		"${_EXECUTABLE}.o"
		${mp_stubs_BINS}
		PARENT_SCOPE
	)
endfunction(COMPILE_ARCH_OS) 

function(ADD_PRECOMPILED _OS _ARCH)
	set(_EXECUTABLE "stub_${_OS}_${_ARCH}")
	add_custom_command(
		OUTPUT "${_EXECUTABLE}"
		COMMAND "cp" "${CMAKE_SOURCE_DIR}/src/stub/precompiled/${_EXECUTABLE}" "${_EXECUTABLE}"
	)
	add_custom_command(
		OUTPUT "${_EXECUTABLE}.o"
		COMMAND "ld" "-r" "-b" "binary" "-o" "${_EXECUTABLE}.o" "${_EXECUTABLE}"
		DEPENDS "${_EXECUTABLE}"
	)
	set (mp_stubs_BINS 
		"${_EXECUTABLE}.o"
		${mp_stubs_BINS}
		PARENT_SCOPE
	)
endfunction(ADD_PRECOMPILED)

If(CCOMPILER_32)
	compile_arch_lib("x86" "-m32 -DARCH_X86")
	compile_arch_os("linux" "x86" "-m32 -DARCH_X86" 
		"-Ai386:intel --oformat elf32-i386 -m ${MACHINE_X86} -Ttext=0xbadc0f4 -Tdata=0xbafb450"
		"--32"
		""
	)
	compile_arch_os("freebsd" "x86" "-m32 -DARCH_X86" 
		"-Ai386:intel --oformat elf32-i386 -m ${MACHINE_X86} -Ttext=0xbadc0f4 -Tdata=0xbafb450"
		"--32"
		""
	)
else(CCOMPILER_32)
	if(WITH_PRECOMPILED_STUBS)
		message("Using precompiled x86")
		add_precompiled("linux" "x86")
		add_precompiled("freebsd" "x86")
	endif(WITH_PRECOMPILED_STUBS)
endif(CCOMPILER_32)

If(CCOMPILER_64)
	compile_arch_lib("amd64" "-m64 -DARCH_AMD64")
	compile_arch_os("linux" "amd64" "-m64 -DARCH_AMD64"
		" -Ai386:x86-64 --oformat elf64-x86-64 -m ${MACHINE_AMD64} -Ttext=0xba000f0 -Tdata=0xba10000"
		"--64"
		""
	)	
	compile_arch_os("freebsd" "amd64" "-m64 -DARCH_AMD64"
		" -Ai386:x86-64 --oformat elf64-x86-64 -m ${MACHINE_AMD64} -Ttext=0xba000f0 -Tdata=0xba10000"
		"--64"
		""
	)
else(CCOMPILER_64)
	if(WITH_PRECOMPILED_STUBS)
		message("Using precompiled amd64")
		add_precompiled("linux" "amd64")
		add_precompiled("freebsd" "amd64")
	endif(WITH_PRECOMPILED_STUBS)
endif(CCOMPILER_64)

If(CCOMPILER_ARMV6)
	compile_arch_lib("armv6" "-march=armv6 -DARCH_ARM")
	compile_arch_os("linux" "armv6" "-march=armv6 -DARCH_ARM" 
		"-Aarmv6 -m ${MACHINE_ARMV6} -Ttext=0xbadc0e4 -Tdata=0xbafb450 -lgcc -lc"
		"-march=armv6"
		"gcc"		#libgcc needed for ARMv6
	)
else(CCOMPILER_ARMV6)
	if(WITH_PRECOMPILED_STUBS)
		message("Using precompiled arm")
		add_precompiled("linux" "armv6")
	endif(WITH_PRECOMPILED_STUBS)
endif(CCOMPILER_ARMV6)


set(MP_STUBS stubs
	CACHE INTERNAL "midgetpack stubs static library"
)

set_source_files_properties(
	${MP_STUBS}
	PROPERTIES
	GENERATED On
)

add_library(${MP_STUBS} STATIC ${mp_stubs_BINS})
set_target_properties(
	${MP_STUBS}
	PROPERTIES
	OUTPUT_NAME stubs
	ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${OUTPUT_SUFFIX}
	LINKER_LANGUAGE C
)


