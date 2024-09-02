cmake_minimum_required(VERSION 3.16...3.26)

include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/common/bootstrap.cmake" NO_POLICY_SCOPE)

project(${_name} VERSION ${_version})

# C++ 標準の設定
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# 静的リンクを使用するための設定
# set(BUILD_SHARED_LIBS OFF)
# set(CMAKE_FIND_LIBRARY_SUFFIXES .a)

option(ENABLE_FRONTEND_API "Use obs-frontend-api for UI functionality" ON)
option(ENABLE_QT "Use Qt functionality" OFF)

include(compilerconfig)
include(defaults)
include(helpers)

add_library(${CMAKE_PROJECT_NAME} MODULE)

find_package(libobs REQUIRED)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE OBS::libobs)

if(ENABLE_FRONTEND_API)
  find_package(obs-frontend-api REQUIRED)
  target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE OBS::obs-frontend-api)
endif()

if(ENABLE_QT)
  find_package(Qt6 COMPONENTS Widgets Core)
  target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE Qt6::Core Qt6::Widgets)
  target_compile_options(
    ${CMAKE_PROJECT_NAME} PRIVATE $<$<C_COMPILER_ID:Clang,AppleClang>:-Wno-quoted-include-in-framework-header
                                  -Wno-comma>)
  set_target_properties(
    ${CMAKE_PROJECT_NAME}
    PROPERTIES AUTOMOC ON
               AUTOUIC ON
               AUTORCC ON)
endif()

# Plugins config
add_subdirectory( src/UxPlay/lib/llhttp )
add_subdirectory( src/UxPlay/lib/playfair )
add_subdirectory( src/UxPlay/lib )


target_include_directories(${CMAKE_PROJECT_NAME} PUBLIC src/UxPlay/lib)
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE 
  src
  lib
)

target_sources(${CMAKE_PROJECT_NAME} PRIVATE
  src/plugin-main.cpp
  src/airplay.cpp
  src/airplay.hpp
  src/audio-decoder.cpp
  src/audio-decoder.hpp
  src/h264-decoder.cpp
  src/h264-decoder.hpp
)

set_target_properties_plugin(${CMAKE_PROJECT_NAME} PROPERTIES OUTPUT_NAME ${_name})

target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE -Wno-error -w )
target_compile_features(${CMAKE_PROJECT_NAME} PRIVATE cxx_std_20)

target_link_libraries( ${CMAKE_PROJECT_NAME} PUBLIC airplay )
target_link_libraries(${CMAKE_PROJECT_NAME} PUBLIC 
  fdk-aac
  dns_sd
)