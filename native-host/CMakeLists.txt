# Host build of the NDK matcher sources: unit tests + the precision/recall
# evaluation, runnable without a device or emulator. Same .cpp files the app's
# libdroidguard.so is built from; only the JNI bridge is left out.
cmake_minimum_required(VERSION 3.20)
project(droidguard_host CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CORE ${CMAKE_CURRENT_SOURCE_DIR}/../app/src/main/cpp)
add_library(dgcore STATIC ${CORE}/vercmp.cpp ${CORE}/matcher.cpp)
target_include_directories(dgcore PUBLIC ${CORE})

if(MSVC)
  target_compile_options(dgcore PUBLIC /W4 /permissive- /EHsc)
else()
  target_compile_options(dgcore PUBLIC -Wall -Wextra -Wpedantic -Werror)
endif()

add_executable(dg_unit tests.cpp)
target_link_libraries(dg_unit dgcore)

add_executable(dg_eval eval.cpp)
target_link_libraries(dg_eval dgcore)

enable_testing()
add_test(NAME unit COMMAND dg_unit ${CMAKE_CURRENT_SOURCE_DIR}/../app/src/main/assets/rules.tsv)
add_test(NAME eval COMMAND dg_eval
         ${CMAKE_CURRENT_SOURCE_DIR}/../app/src/main/assets/rules.tsv
         ${CMAKE_CURRENT_SOURCE_DIR}/../data/labels.tsv --min-f1 1.0)
