cmake_minimum_required(VERSION 3.20)
project(pkcs11_demo C)

set(SE05X_PKCS11_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../ext/se05x-pkcs11)

# se_pkcs11/cryptoki.h sets the platform macros and includes pkcs11.h.
# pkcs11/published/2-40-errata-1/ provides pkcs11.h itself.
set(PKCS11_INCLUDES
    ${SE05X_PKCS11_DIR}/se_pkcs11/
    ${SE05X_PKCS11_DIR}/pkcs11/published/2-40-errata-1/)

add_executable(${PROJECT_NAME}
    pkcs11_demo.c
    demo_module_info.c
    demo_random_gen.c
    demo_digest.c
    demo_sym_key_gen.c
    demo_import_object.c
    demo_ecc.c
    demo_rsa.c
    demo_ecdh_derive.c
    demo_hmac.c
    demo_encrypt_decrypt.c)

target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${PKCS11_INCLUDES})

# dlopen/dlsym to load libsss_pkcs11.so at runtime — no link-time dependency.
target_link_libraries(${PROJECT_NAME} dl)

include(GNUInstallDirs)
install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
