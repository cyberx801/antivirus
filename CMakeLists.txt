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
        src/ai.c
        src/threadutil.c
        src/watcher.c
        src/yrscan.c
        src/config.c
)

if(MSVC)
    target_compile_options(antivirus PRIVATE /utf-8)
endif()

find_package(unofficial-libyara QUIET)
if(unofficial-libyara_FOUND)
    target_compile_definitions(antivirus PRIVATE HAVE_YARA=1)
    target_link_libraries(antivirus PRIVATE unofficial::libyara::libyara)
endif()


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
find_package(Threads REQUIRED)
target_link_libraries(antivirus PRIVATE OpenSSL::Crypto OpenSSL::SSL CURL::curl ws2_32 wldap32 crypt32 Threads::Threads)

# ------------------------- Unit tests -------------------------
enable_testing()
add_executable(unit_tests
        tests/test_tests.c
        src/hash.c
        src/sigdb.c
        src/config.c
        src/logger.c
)
if(MSVC)
    target_compile_options(unit_tests PRIVATE /utf-8)
endif()
target_link_libraries(unit_tests PRIVATE OpenSSL::Crypto Threads::Threads)
add_test(NAME unit_tests COMMAND unit_tests)