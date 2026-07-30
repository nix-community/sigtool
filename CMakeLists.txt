cmake_minimum_required(VERSION 3.17)
project(sigtool)

option(BUILD_SHARED_LIBS "Build libsigtool as a shared library" ON)

IF(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(CMAKE_CXX_FLAGS "-g")
ENDIF()

find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBPLIST REQUIRED IMPORTED_TARGET libplist-2.0)

set(CMAKE_CXX_STANDARD 11)

add_library(libsigtool macho.cpp signature.cpp hash.cpp commands.cpp der.cpp)
target_include_directories(libsigtool PUBLIC vendor)
target_link_libraries(libsigtool PRIVATE OpenSSL::Crypto PkgConfig::LIBPLIST)
set_property(TARGET libsigtool PROPERTY OUTPUT_NAME sigtool)

add_executable(sigtool main.cpp)
target_link_libraries(sigtool PRIVATE libsigtool)

add_executable(codesign codesign.cpp)
target_link_libraries(codesign PRIVATE libsigtool)

install(TARGETS sigtool codesign libsigtool)

install(
  FILES
    commands.h
    emit.h
    hash.h
    macho.h
    signature.h
  DESTINATION
    include/sigtool
)
