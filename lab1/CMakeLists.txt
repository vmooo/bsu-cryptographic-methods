cmake_minimum_required(VERSION 3.31)
project(lab1)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(lab1 STATIC
        src/lab1.cpp
        include/lab1.h
)

include(FetchContent)
FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/5376968f6948923e2411081fd9372e71a59d8e77.zip
)
FetchContent_MakeAvailable(googletest)

enable_testing()

add_executable(lab1_tests tests/lab1_tests.cpp)

target_compile_options(lab1_tests PRIVATE -Wall -Wextra -Wunused-result -O2 -pthread)

target_link_libraries(lab1_tests
        PRIVATE
        gtest_main
        lab1
)

include(GoogleTest)
gtest_discover_tests(lab1_tests)