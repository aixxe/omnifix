cmake_minimum_required(VERSION 3.31)

project(omnifix VERSION 0.3.0 LANGUAGES CXX)

find_package(Zydis CONFIG REQUIRED)
find_package(safetyhook CONFIG REQUIRED)

find_path(PICOSHA2_INCLUDE_DIRS "picosha2.h")

add_library(omnifix SHARED
    src/omnifix.cc
    src/memory.cc
    src/modules.cc
)

target_compile_features(omnifix PRIVATE cxx_std_23)

target_include_directories(omnifix PRIVATE
    ${PICOSHA2_INCLUDE_DIRS}
)

target_link_directories(omnifix PRIVATE
    ${CMAKE_SOURCE_DIR}/lib
)

target_link_libraries(omnifix PRIVATE
    avs2-core
    safetyhook::safetyhook
)

if (CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    target_link_libraries(omnifix PRIVATE stdc++exp)
endif ()

if (MINGW)
    set_target_properties(omnifix PROPERTIES PREFIX "")
endif ()

include(cmake/version.cmake)

target_compile_definitions(omnifix PRIVATE
    "META_PROJECT_VERSION=\"${PROJECT_VERSION}\""
    "META_GIT_BRANCH=\"${META_GIT_BRANCH}\""
    "META_GIT_COMMIT_SHORT=\"${META_GIT_COMMIT_SHORT}\""
    "META_COMPILER_ID=\"${CMAKE_CXX_COMPILER_ID}\""
    "META_COMPILER_VERSION=\"${CMAKE_CXX_COMPILER_VERSION}\""
)