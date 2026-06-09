cmake_minimum_required(VERSION 3.10)
project(se05x_crypto_app CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SIMW_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../ext/plug-and-trust)

if(NOT SE05X_PKCS11_DIR)
    set(SE05X_PKCS11_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../ext/se05x-pkcs11)
endif()
set(PKCS11_INCLUDES
    ${SE05X_PKCS11_DIR}/se_pkcs11
    ${SE05X_PKCS11_DIR}/pkcs11/published/2-40-errata-1)

set(SSS_HAVE_MBEDTLS_2_X ON)

include(${SIMW_LIB_DIR}/simw_lib.cmake)

list(REMOVE_ITEM SIMW_SE_SOURCES
    ${SIMW_LIB_DIR}/sss/src/openssl/fsl_sss_openssl_apis.c
    ${SIMW_LIB_DIR}/sss/src/keystore/keystore_openssl.c)
list(APPEND SIMW_SE_SOURCES
    ${SIMW_LIB_DIR}/sss/src/mbedtls/fsl_sss_mbedtls_apis.c)

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
        cli.cpp
        crypto_backend.cpp
        se05x_crypto.cpp
        se05x_provision.cpp
        pkcs11_ctx.cpp
        csr.cpp)
else()
    add_executable(${PROJECT_NAME}
        ${SIMW_SE_SOURCES}
        ${SIMW_SE_AUTH_SOURCES}
        main.cpp
        cli.cpp
        crypto_backend.cpp
        se05x_crypto.cpp
        se05x_provision.cpp
        pkcs11_ctx.cpp
        csr.cpp)
endif()

target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${SIMW_LIB_DIR}
    ${SIMW_INC_DIR}
    ${MBEDTLS_PREFIX}/include
    ${PKCS11_INCLUDES}
)

target_link_libraries(${PROJECT_NAME}
    ${MBEDTLS_PREFIX}/lib/libmbedtls.a
    ${MBEDTLS_PREFIX}/lib/libmbedx509.a
    ${MBEDTLS_PREFIX}/lib/libmbedcrypto.a
    dl
)

include(GNUInstallDirs)
install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
