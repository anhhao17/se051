set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

# Root of the toolchain (use $ENV{HOME} instead of ~)
set(TOOLCHAIN_ROOT $ENV{HOME}/work/iritech26tpro/tools/gcc-11.1.0-20210608-sigmastar-glibc-x86_64_arm-linux-gnueabihf)

# The cross prefix used by all the tools
set(TOOLCHAIN_PREFIX arm-linux-gnueabihf-)

set(CMAKE_C_COMPILER   ${TOOLCHAIN_ROOT}/bin/${TOOLCHAIN_PREFIX}gcc)
set(CMAKE_CXX_COMPILER ${TOOLCHAIN_ROOT}/bin/${TOOLCHAIN_PREFIX}g++)
set(CMAKE_STRIP        ${TOOLCHAIN_ROOT}/bin/${TOOLCHAIN_PREFIX}strip)

# Where to look for the target environment (sysroot)
set(CMAKE_FIND_ROOT_PATH ${TOOLCHAIN_ROOT}/arm-linux-gnueabihf/libc)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)