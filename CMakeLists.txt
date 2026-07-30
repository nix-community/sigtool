cmake_minimum_required(VERSION 3.17)
project(sigtool)

option(BUILD_SHARED_LIBS "Build libsigtool as a shared library" ON)

IF(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(CMAKE_CXX_FLAGS "-g")
ENDIF()

if(NOT BUILD_SHARED_LIBS)
  set(OPENSSL_USE_STATIC_LIBS TRUE)
endif()
find_package(OpenSSL REQUIRED)

set(CMAKE_CXX_STANDARD 11)

add_library(libsigtool macho.cpp signature.cpp hash.cpp commands.cpp)
target_include_directories(libsigtool PUBLIC vendor)
target_link_libraries(libsigtool PRIVATE OpenSSL::Crypto)
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
