cmake_minimum_required(VERSION 3.20)
project(stonegate VERSION 0.1.0 LANGUAGES CXX)

include(CTest)

# eventloop comes from, in order: a source checkout (EVENTLOOP_SOURCE_DIR), an
# installed package exporting eventloop::eventloop, or a download of
# EVENTLOOP_GIT_TAG, the eventloop release Stonegate is tested with.
set(EVENTLOOP_SOURCE_DIR "" CACHE PATH "eventloop source checkout to build with Stonegate")
set(EVENTLOOP_GIT_REPOSITORY "https://github.com/ArdaKemal/eventloop.git" CACHE STRING
    "eventloop repository downloaded when no checkout or package is found")
set(EVENTLOOP_GIT_TAG "v0.1.0" CACHE STRING "eventloop tag or commit to download")

if(NOT EVENTLOOP_SOURCE_DIR)
    find_package(eventloop CONFIG QUIET)
    if(NOT eventloop_FOUND)
        include(FetchContent)
        set(eventloop_download "${CMAKE_CURRENT_BINARY_DIR}/_deps")
        FetchContent_Populate(eventloop
            GIT_REPOSITORY "${EVENTLOOP_GIT_REPOSITORY}"
            GIT_TAG "${EVENTLOOP_GIT_TAG}"
            GIT_SHALLOW TRUE
            SOURCE_DIR "${eventloop_download}/eventloop-src"
            SUBBUILD_DIR "${eventloop_download}/eventloop-subbuild"
            BINARY_DIR "${eventloop_download}/eventloop-build")
        set(EVENTLOOP_SOURCE_DIR "${eventloop_download}/eventloop-src")
    endif()
endif()
if(EVENTLOOP_SOURCE_DIR)
    # Build only the library, without eventloop's examples or tests.
    set(stonegate_build_testing ${BUILD_TESTING})
    set(BUILD_TESTING OFF)
    add_subdirectory("${EVENTLOOP_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/eventloop"
        EXCLUDE_FROM_ALL)
    set(BUILD_TESTING ${stonegate_build_testing})
endif()

if(WIN32)
    message(FATAL_ERROR "Stonegate serves files through POSIX APIs; build it on Linux, macOS, or a BSD")
endif()

add_executable(stonegate
    src/access_log.cc
    src/configuration.cc
    src/credentials.cc
    src/file_response.cc
    src/listeners.cc
    src/main.cc
    src/privileges.cc
    src/static_files.cc
    src/toml.cc
    src/workers.cc)
find_package(OpenSSL 3.5 REQUIRED COMPONENTS Crypto)
target_link_libraries(stonegate PRIVATE eventloop::eventloop OpenSSL::Crypto)
target_compile_features(stonegate PRIVATE cxx_std_23)

# On-the-fly gzip needs zlib; without it, gzip = true is a configuration error.
find_package(ZLIB)
if(ZLIB_FOUND)
    target_link_libraries(stonegate PRIVATE ZLIB::ZLIB)
    target_compile_definitions(stonegate PRIVATE STONEGATE_ZLIB=1)
endif()

target_compile_options(stonegate PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(stonegate PRIVATE -Wno-mismatched-new-delete)
endif()

install(TARGETS stonegate RUNTIME DESTINATION bin)

if(BUILD_TESTING AND NOT WIN32)
    # Both harnesses send POSIX signals to the server process.
    find_package(Python3 QUIET COMPONENTS Interpreter)
    if(Python3_Interpreter_FOUND)
        add_test(NAME stonegate_configuration
            COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/configuration_test.py"
                $<TARGET_FILE:stonegate>)
        set_tests_properties(stonegate_configuration PROPERTIES TIMEOUT 45)
    endif()
    # Also needs the openssl CLI; HTTP/3 checks use curl from PATH when it has HTTP/3.
    if(Python3_Interpreter_FOUND AND ZLIB_FOUND)
        add_test(NAME stonegate_features
            COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/features_test.py"
                $<TARGET_FILE:stonegate>)
        set_tests_properties(stonegate_features PROPERTIES TIMEOUT 120)
    endif()
    # The smoke test runs curl and openssl from PATH; HTTP/2 and HTTP/3
    # checks are skipped when that curl lacks them.
    find_program(BASH_EXECUTABLE bash)
    find_program(CURL_EXECUTABLE curl)
    find_program(OPENSSL_EXECUTABLE openssl)
    if(BASH_EXECUTABLE AND CURL_EXECUTABLE AND OPENSSL_EXECUTABLE)
        add_test(NAME stonegate_smoke
            COMMAND "${BASH_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/smoke.sh"
                $<TARGET_FILE:stonegate>)
        set_tests_properties(stonegate_smoke PROPERTIES TIMEOUT 120)
    endif()
endif()
