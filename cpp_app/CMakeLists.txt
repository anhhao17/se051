cmake_minimum_required(VERSION 3.10)
project(se05x_crypto_app CXX C)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# plug-and-trust submodule relative to this directory.
set(SIMW_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../ext/plug-and-trust)

# Force mbedTLS 2.x API surface before simw_lib.cmake regenerates fsl_sss_ftr.h.
set(SSS_HAVE_MBEDTLS_2_X ON)

# Populates SIMW_SE_SOURCES / SIMW_SE_AUTH_SOURCES / SIMW_INC_DIR and writes
# fsl_sss_ftr.h into the submodule (expected side-effect, mirrors app/).
include(${SIMW_LIB_DIR}/simw_lib.cmake)

# Swap the OpenSSL backend for the mbedTLS one.
list(REMOVE_ITEM SIMW_SE_SOURCES
    ${SIMW_LIB_DIR}/sss/src/openssl/fsl_sss_openssl_apis.c
    ${SIMW_LIB_DIR}/sss/src/keystore/keystore_openssl.c)
list(APPEND SIMW_SE_SOURCES
    ${SIMW_LIB_DIR}/sss/src/mbedtls/fsl_sss_mbedtls_apis.c)

# simw_lib.cmake leaves FLOW_VERBOSE commented out and NX_LOG_ENABLE_DEFAULT_DEBUG
# defaults to 0 — translate the top-level SE05X_DEBUG_LOG option into the actual
# compiler macros the P&T sources check (must precede add_executable).
if(SE05X_DEBUG_LOG)
    add_compile_definitions(FLOW_VERBOSE NX_LOG_ENABLE_DEFAULT_DEBUG=1)
endif()
if(MBEDTLS_USER_CONFIG_FILE)
    add_compile_definitions(MBEDTLS_USER_CONFIG_FILE="${MBEDTLS_USER_CONFIG_FILE}")
endif()

if("${PTMW_SE05X_Auth}" STREQUAL "None")
    add_executable(${PROJECT_NAME}
        ${SIMW_SE_SOURCES}
        main.cpp
        se05x_crypto.cpp
        csr.cpp)
else()
    add_executable(${PROJECT_NAME}
        ${SIMW_SE_SOURCES}
        ${SIMW_SE_AUTH_SOURCES}
        main.cpp
        se05x_crypto.cpp
        csr.cpp)
endif()

target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${SIMW_LIB_DIR}
    ${SIMW_INC_DIR}
    ${MBEDTLS_PREFIX}/include
)

# Static mbedTLS from the superbuild. Link order: tls -> x509 -> crypto.
target_link_libraries(${PROJECT_NAME}
    ${MBEDTLS_PREFIX}/lib/libmbedtls.a
    ${MBEDTLS_PREFIX}/lib/libmbedx509.a
    ${MBEDTLS_PREFIX}/lib/libmbedcrypto.a
)

include(GNUInstallDirs)
install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
