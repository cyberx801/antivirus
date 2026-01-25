cmake_minimum_required(VERSION 4.0)
project(antivirus C)
set(VCPKG_LINKAGE_OPTIONS "static")
set(CMAKE_C_STANDARD 11)
set(CMAKE_TOOLCHAIN_FILE "C:/vcpkg/scripts/buildsystems/vcpkg.cmake")

include_directories(include)


add_executable(antivirus
        src/main.c
        src/logger.c
        src/hash.c
        src/sigdb.c
        src/scanner.c
        src/report.c
        src/quarantine.c
        src/update.c
)


# Paketleri bul
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
if(NOT TARGET CURL::curl)
    add_library(CURL::curl SHARED IMPORTED)

    set_target_properties(CURL::curl PROPERTIES
            IMPORTED_LOCATION "C:/vcpkg/installed/x64-windows/bin/libcurl.dll"
            IMPORTED_IMPLIB   "C:/vcpkg/installed/x64-windows/lib/libcurl.lib"
            INTERFACE_INCLUDE_DIRECTORIES "C:/vcpkg/installed/x64-windows/include"
    )
endif()
target_link_libraries(antivirus PRIVATE OpenSSL::Crypto OpenSSL::SSL CURL::curl ws2_32 wldap32 crypt32)