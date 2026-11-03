cmake_minimum_required(VERSION 3.20)
project(stonegate VERSION 0.1.0 LANGUAGES CXX)

include(CTest)

# eventloop comes from, in order: a source checkout (EVENTLOOP_SOURCE_DIR), an
# installed package exporting eventloop::eventloop, or a download of
# EVENTLOOP_GIT_TAG, the eventloop release Stonegate is tested with. The
# reverse proxy needs eventloop 0.2 for tcp_stream_hold.
set(EVENTLOOP_SOURCE_DIR "" CACHE PATH "eventloop source checkout to build with Stonegate")
set(EVENTLOOP_GIT_REPOSITORY "https://github.com/ArdaKemal/eventloop.git" CACHE STRING
    "eventloop repository downloaded when no checkout or package is found")
set(EVENTLOOP_GIT_TAG "v0.2.0" CACHE STRING "eventloop tag or commit to download")

if(NOT EVENTLOOP_SOURCE_DIR)
    find_package(eventloop 0.2 CONFIG QUIET)
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
    src/proxy.cc
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

# libFuzzer harnesses (Clang): see fuzz/README.md. They compile the source
# file whose internals they reach, so each links the remaining sources.
option(STONEGATE_FUZZERS "Build libFuzzer harnesses with ASan and UBSan (Clang only)" OFF)
if(STONEGATE_FUZZERS)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "STONEGATE_FUZZERS needs Clang for libFuzzer")
    endif()
    if(NOT EVENTLOOP_SOURCE_DIR)
        message(FATAL_ERROR "STONEGATE_FUZZERS needs an eventloop source checkout")
    endif()
    get_target_property(stonegate_sources stonegate SOURCES)
    list(REMOVE_ITEM stonegate_sources src/main.cc)
    foreach(harness request_parsing:src/static_files.cc proxy_head:src/proxy.cc toml:)
        string(REPLACE ":" ";" parts "${harness}")
        list(GET parts 0 name)
        set(sources ${stonegate_sources})
        list(LENGTH parts count)
        if(name STREQUAL "toml")
            set(sources src/toml.cc)
        elseif(count EQUAL 2)
            list(GET parts 1 included)
            list(REMOVE_ITEM sources ${included})
        endif()
        add_executable(fuzz_${name} fuzz/${name}.cc ${sources})
        target_link_libraries(fuzz_${name} PRIVATE eventloop::eventloop OpenSSL::Crypto)
        target_include_directories(fuzz_${name} PRIVATE "${EVENTLOOP_SOURCE_DIR}/src")
        target_compile_features(fuzz_${name} PRIVATE cxx_std_23)
        target_compile_options(fuzz_${name} PRIVATE -fsanitize=fuzzer,address,undefined
            -fno-sanitize-recover=undefined -g)
        target_link_options(fuzz_${name} PRIVATE -fsanitize=fuzzer,address,undefined)
        if(ZLIB_FOUND)
            target_link_libraries(fuzz_${name} PRIVATE ZLIB::ZLIB)
            target_compile_definitions(fuzz_${name} PRIVATE STONEGATE_ZLIB=1)
        endif()
    endforeach()
endif()

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
