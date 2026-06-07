cmake_minimum_required(VERSION 3.16)

project(belt
    VERSION 1.0.0
    DESCRIPTION "STB 34.101.31 (BelT) cryptographic algorithms in C++"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

option(BELT_BUILD_TESTS "Build the BelT test suite" ON)
option(BELT_BUILD_CLI "Build the BelT command-line tool" ON)
option(BELT_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)

# ---------------------------------------------------------------- library ----

add_library(belt
    src/tables.cpp
    src/block.cpp
    src/modes.cpp
    src/mac.cpp
    src/aead.cpp
    src/keywrap.cpp
    src/hash.cpp
    src/keyrep.cpp
    src/hex.cpp)

target_include_directories(belt PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)
target_include_directories(belt PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_library(belt::belt ALIAS belt)

if(MSVC)
    target_compile_options(belt PRIVATE /W4)
else()
    target_compile_options(belt PRIVATE -Wall -Wextra -Wpedantic)
endif()
if(BELT_WARNINGS_AS_ERRORS)
    if(MSVC)
        target_compile_options(belt PRIVATE /WX)
    else()
        target_compile_options(belt PRIVATE -Werror)
    endif()
endif()

# ------------------------------------------------------------------- cli -----

if(BELT_BUILD_CLI)
    add_executable(belt-cli tools/belt_cli.cpp)
    target_link_libraries(belt-cli PRIVATE belt)
    set_target_properties(belt-cli PROPERTIES OUTPUT_NAME belt)
endif()

# ----------------------------------------------------------------- tests -----

if(BELT_BUILD_TESTS)
    enable_testing()
    add_executable(belt-tests tests/test_vectors.cpp)
    target_link_libraries(belt-tests PRIVATE belt)
    add_test(NAME known-answer-tests COMMAND belt-tests)
endif()

# --------------------------------------------------------------- install -----

include(GNUInstallDirs)
install(TARGETS belt
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
