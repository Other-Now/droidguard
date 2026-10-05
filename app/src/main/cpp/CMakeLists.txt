cmake_minimum_required(VERSION 3.22.1)
project(droidguard CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# The matcher core is the same source the host build (native-host/) tests.
add_library(droidguard SHARED jni_bridge.cpp matcher.cpp vercmp.cpp)
target_compile_options(droidguard PRIVATE -Wall -Wextra -Werror -O2)
# Frame pointers make simpleperf --call-graph fp usable on x86_64 and arm64.
target_compile_options(droidguard PRIVATE -fno-omit-frame-pointer)
