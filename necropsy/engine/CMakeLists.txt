cmake_minimum_required(VERSION 3.15)
project(necropsy_engine CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (MSVC)
    add_compile_options(/W4 /O2 /EHsc)
else()
    add_compile_options(-Wall -Wextra -O2)
endif()

add_executable(necropsy-engine
    src/minidump.cpp
    src/triage.cpp
    src/main.cpp
)

target_include_directories(necropsy-engine PRIVATE include)

install(TARGETS necropsy-engine RUNTIME DESTINATION bin)