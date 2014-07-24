option(WITH_STUB_DEBUG "Build with STUB debug support" OFF)
option(WITH_PACKER_DEBUG "Build with PACKER debug support" OFF)
option(WITH_CRYPTO_DEBUG "Build with CRYPTO debug support" OFF)
option(WITH_PRECOMPILED_STUBS "Build with the available precompiled stubs" ON)

if(WITH_STUB_DEBUG)
	set(LOADER_DEBUG ON)
ENDIF(WITH_STUB_DEBUG)

if(WITH_PACKER_DEBUG)
	set(PACKER_DEBUG ON)
ENDIF(WITH_PACKER_DEBUG)

if(WITH_CRYPTO_DEBUG)
	set(CRYPTO_DEBUG ON)
ENDIF(WITH_CRYPTO_DEBUG)


