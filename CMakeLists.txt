project(securememory)

cmake_minimum_required(VERSION 3.19)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set_property(GLOBAL PROPERTY USE_FOLDERS ON)
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/MP>")
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/bigobj>")
add_link_options("$<$<CXX_COMPILER_ID:MSVC>:LINKER:/DEBUG:FASTLINK>")
enable_testing()

add_library(securememory INTERFACE)
target_include_directories(securememory INTERFACE include)

target_sources(securememory INTERFACE
    include/securememory/win32/exception.h
    include/securememory/win32/heap.h
    include/securememory/win32/page_table.h
    include/securememory/allocator.h
    readme.md
)

macro(group_sources path)
    file(GLOB children RELATIVE ${PROJECT_SOURCE_DIR}/${path} ${PROJECT_SOURCE_DIR}/${path}/*)
    foreach(child ${children})
        if(IS_DIRECTORY ${PROJECT_SOURCE_DIR}/${path}/${child})
            group_sources(${path}/${child})
        else()
            string(REPLACE "/" "\\" groupname ${path})
            source_group(${groupname} FILES ${PROJECT_SOURCE_DIR}/${path}/${child})
        endif()
    endforeach()
endmacro()

find_package(Boost)
if(Boost_FOUND)
    add_executable(securememorytest
        test/pch.h
        test/securememory.cpp
        test/testmodule.cpp
    )

    add_test(securememorytest COMMAND securememorytest)
    target_link_libraries(securememorytest securememory Boost::boost)
    target_include_directories(securememorytest PRIVATE test)
    target_precompile_headers(securememorytest PRIVATE test/pch.h)

    if(WIN32)
        group_sources(include)
        group_sources(test)
    endif()
endif()
