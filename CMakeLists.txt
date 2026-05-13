cmake_minimum_required(VERSION 3.16)
project(mifare_emission LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(MIFARE_BUILD_TESTS "Build the unit tests" ON)
option(MIFARE_BUILD_APP   "Build the SKUD application (requires PC/SC)" ON)
option(MIFARE_BUILD_TOOLS "Build supporting tools (card emission)"      ON)

if(MSVC)
    add_compile_options(/W4 /permissive- /Zc:__cplusplus)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

include(FetchContent)
FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        v3.11.3
)
FetchContent_MakeAvailable(nlohmann_json)

set(BELT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/BELT_STD/BELT")
if(NOT EXISTS "${BELT_DIR}/belt.cpp")
    message(FATAL_ERROR
        "BELT_STD submodule missing. Run: git submodule update --init --recursive")
endif()

add_library(belt STATIC
    "${BELT_DIR}/belt.cpp"
    "${BELT_DIR}/belt.h"
)
target_include_directories(belt PUBLIC "${BELT_DIR}")
if(MSVC)
    target_compile_options(belt PRIVATE /W3 /wd4244 /wd4267)
else()
    target_compile_options(belt PRIVATE -Wno-unused-result -Wno-sign-compare)
endif()

set(MIFARE_CORE_SOURCES
    src/types.cpp
    src/time_policy.cpp
    src/crypto.cpp
    src/json_state.cpp
    src/rfid_reader.cpp
    src/access_engine.cpp
    src/logger.cpp
)

add_library(mifare_emission_core STATIC ${MIFARE_CORE_SOURCES})
target_include_directories(mifare_emission_core PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
target_link_libraries(mifare_emission_core
    PUBLIC
        belt
        nlohmann_json::nlohmann_json
)

add_library(mifare_emission_vault STATIC
    src/master_key_vault.cpp
)
target_link_libraries(mifare_emission_vault PUBLIC mifare_emission_core)
if(WIN32)
    target_link_libraries(mifare_emission_vault PUBLIC crypt32)
endif()

if(MIFARE_BUILD_APP AND WIN32)
    add_library(mifare_emission_reader STATIC
        src/pcsc_reader.cpp
    )
    target_link_libraries(mifare_emission_reader
        PUBLIC mifare_emission_core
        PRIVATE winscard)

    add_executable(mifare_emission_app src/main.cpp)
    target_link_libraries(mifare_emission_app
        PRIVATE
            mifare_emission_core
            mifare_emission_vault
            mifare_emission_reader
            nlohmann_json::nlohmann_json
    )
endif()

if(MIFARE_BUILD_TOOLS AND WIN32)
    add_executable(mifare_emission_tool tools/emission_tool.cpp)
    target_link_libraries(mifare_emission_tool
        PRIVATE
            mifare_emission_core
            mifare_emission_vault
            mifare_emission_reader
            nlohmann_json::nlohmann_json
    )
endif()

if(MIFARE_BUILD_TESTS)
    enable_testing()
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        v1.14.0
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    add_executable(mifare_emission_tests
        tests/test_main.cpp
        tests/test_types.cpp
        tests/test_time_policy.cpp
        tests/test_crypto.cpp
        tests/test_json_state.cpp
        tests/test_access_engine.cpp
        tests/test_rfid_reader.cpp
        tests/test_master_key_vault.cpp
        tests/mock_rfid_reader.cpp
    )
    target_include_directories(mifare_emission_tests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/tests"
    )
    target_link_libraries(mifare_emission_tests
        PRIVATE
            mifare_emission_core
            mifare_emission_vault
            GTest::gtest
            GTest::gtest_main
    )

    include(GoogleTest)
    gtest_discover_tests(mifare_emission_tests)
endif()
