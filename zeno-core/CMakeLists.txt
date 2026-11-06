cmake_minimum_required(VERSION 3.20)
project(zeno_inject LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# ---------------------------------------------------------------- Luau
include(FetchContent)

if(DEFINED ENV{LUAU_SRC_DIR} AND EXISTS "$ENV{LUAU_SRC_DIR}/CMakeLists.txt")
  message(STATUS "Using local Luau at $ENV{LUAU_SRC_DIR}")
  add_subdirectory("$ENV{LUAU_SRC_DIR}" "${CMAKE_BINARY_DIR}/luau")
else()
  FetchContent_Declare(
    luau
    GIT_REPOSITORY https://github.com/luau-lang/luau.git
    GIT_TAG        0.653
    GIT_SHALLOW    TRUE
    PATCH_COMMAND  ${CMAKE_COMMAND} -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/patch_luau_policy.cmake"
  )
  set(LUAU_BUILD_TESTS OFF CACHE BOOL "" FORCE)
  set(LUAU_BUILD_CLI OFF CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(luau)
endif()

# ---------------------------------------------------------------- target
file(GLOB ZENO_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")

add_library(zeno_inject SHARED ${ZENO_SOURCES})

target_include_directories(zeno_inject PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/third_party"
)

target_compile_definitions(zeno_inject PRIVATE
  WIN32_LEAN_AND_MEAN
  NOMINMAX
  _CRT_SECURE_NO_WARNINGS
  ZENO_VERSION="1.0.0"
)

target_link_libraries(zeno_inject PRIVATE
  Luau.VM
  Luau.Compiler
  Luau.Ast
  psapi
)

set_target_properties(zeno_inject PROPERTIES
  PREFIX ""
  SUFFIX ".dll"
  OUTPUT_NAME "zeno_inject"
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}"
  RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}"
)

if(MSVC)
  target_compile_options(zeno_inject PRIVATE /W3 /permissive- /EHsc /Gy)
endif()

# copy offsets next to the dll
add_custom_command(TARGET zeno_inject POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "${CMAKE_CURRENT_SOURCE_DIR}/config/zeno_offsets.json"
    "$<TARGET_FILE_DIR:zeno_inject>/zeno_offsets.json"
)
