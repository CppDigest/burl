#
# Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
#
# Distributed under the Boost Software License, Version 1.0. (See accompanying
# file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
#
# Official repository: https://github.com/cppalliance/burl
#

cmake_minimum_required(VERSION 3.20)

project(boost_burl
    VERSION 1.0.0
    LANGUAGES CXX
    DESCRIPTION "Boost.Burl - HTTP client library with coroutine support"
)

#==============================================================
# Options
#==============================================================

option(BURL_BUILD_TESTS "Build unit tests" ON)
option(BURL_BUILD_EXAMPLES "Build examples" ON)

#==============================================================
# C++ Standard
#==============================================================

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

#==============================================================
# Dependencies
#==============================================================

# Find Boost components
find_package(Boost REQUIRED COMPONENTS system url json)

# Find corosio (assumed to be available via Boost or local path)
# find_package(corosio REQUIRED)

# Find capy (assumed to be available via Boost or local path)
# find_package(capy REQUIRED)

# Find http (assumed to be available via Boost or local path)
# find_package(http REQUIRED)

# OpenSSL for TLS support
find_package(OpenSSL REQUIRED)

#==============================================================
# Library
#==============================================================

add_library(boost_burl
    src/session.cpp
    src/auth.cpp
    src/cookies.cpp
)

target_include_directories(boost_burl
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(boost_burl
    PUBLIC
        Boost::system
        Boost::url
        Boost::json
        # boost_corosio
        # boost_capy
        # boost_http
        OpenSSL::SSL
        OpenSSL::Crypto
)

target_compile_features(boost_burl PUBLIC cxx_std_20)

# Header-only interface library (for header-only usage)
add_library(boost_burl_headers INTERFACE)

target_include_directories(boost_burl_headers
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

#==============================================================
# Tests
#==============================================================

if(BURL_BUILD_TESTS)
    enable_testing()

    # Test executables
    set(BURL_TESTS
        session
        response
        options
        auth
        cookies
        error
    )

    foreach(test ${BURL_TESTS})
        add_executable(burl_test_${test} test/${test}.cpp)
        target_link_libraries(burl_test_${test} PRIVATE boost_burl)
        add_test(NAME burl_${test} COMMAND burl_test_${test})
    endforeach()
endif()

#==============================================================
# Examples
#==============================================================

if(BURL_BUILD_EXAMPLES)
    add_executable(burl_example_usage example/usage.cpp)
    target_link_libraries(burl_example_usage PRIVATE boost_burl)
endif()

#==============================================================
# Installation
#==============================================================

include(GNUInstallDirs)

install(TARGETS boost_burl boost_burl_headers
    EXPORT boost_burl_targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(EXPORT boost_burl_targets
    FILE boost_burl-targets.cmake
    NAMESPACE Boost::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/boost_burl
)

#==============================================================
# Package Config
#==============================================================

include(CMakePackageConfigHelpers)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/boost_burl-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/boost_burl-config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/boost_burl
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/boost_burl-config-version.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/boost_burl-config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/boost_burl-config-version.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/boost_burl
)
