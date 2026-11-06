# FetchContent PATCH_COMMAND runs with cwd = the fetched source tree.
# Luau 0.653 still declares `cmake_minimum_required(VERSION 3.0)`, which
# CMake 4+ rejects outright. Bump every list in the tree to 3.5.
# Idempotent: a second configure is a no-op.

file(GLOB_RECURSE _luau_lists "CMakeLists.txt")
foreach(_list IN LISTS _luau_lists)
  file(READ "${_list}" _text)
  if(_text MATCHES "cmake_minimum_required\\(VERSION 3\\.0\\)")
    string(REPLACE "cmake_minimum_required(VERSION 3.0)"
                   "cmake_minimum_required(VERSION 3.5)" _text "${_text}")
    file(WRITE "${_list}" "${_text}")
    message(STATUS "luau: bumped policy floor in ${_list}")
  endif()
endforeach()
