cmake_minimum_required(VERSION 3.20)
project(compiler_security_analyzer CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(LLVM REQUIRED CONFIG)
message(STATUS "Using LLVM ${LLVM_PACKAGE_VERSION} from ${LLVM_DIR}")

include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})
separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
add_definitions(${LLVM_DEFINITIONS_LIST})

add_executable(taint_analyzer src/taint_analyzer.cpp)

if(NOT LLVM_ENABLE_RTTI)
  target_compile_options(taint_analyzer PRIVATE -fno-rtti)
endif()

llvm_map_components_to_libnames(LLVM_LIBS core irreader support)
target_link_libraries(taint_analyzer PRIVATE ${LLVM_LIBS})
