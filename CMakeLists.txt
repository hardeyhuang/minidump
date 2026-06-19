cmake_minimum_required(VERSION 3.15)
project(MiniDumpInproc LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "MiniDumpInproc targets Windows only.")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(MiniDumpInproc
    src/minidump_inproc.cpp
    src/minidump_inproc_globals.cpp
    src/minidump_inproc_memory.cpp
    src/minidump_inproc_modules.cpp
    src/minidump_inproc_streams.cpp
    src/minidump_inproc_threads.cpp
    src/minidump_inproc_util.cpp
    src/minidump_inproc_internal.h
    include/minidump_inproc.h
)


target_include_directories(MiniDumpInproc
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

target_compile_definitions(MiniDumpInproc PUBLIC WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE)


get_target_property(MINIDUMP_INPROC_TARGET_TYPE MiniDumpInproc TYPE)
if(MINIDUMP_INPROC_TARGET_TYPE STREQUAL "SHARED_LIBRARY" OR
   MINIDUMP_INPROC_TARGET_TYPE STREQUAL "MODULE_LIBRARY")
    target_compile_definitions(MiniDumpInproc PRIVATE MINIDUMP_INPROC_EXPORTS)
else()
    target_compile_definitions(MiniDumpInproc PUBLIC MINIDUMP_INPROC_STATIC)
endif()

if(MSVC)
    target_compile_options(MiniDumpInproc PRIVATE /W4 /permissive-)
endif()

option(MINIDUMP_INPROC_BUILD_SAMPLE "Build the in-process minidump sample executable" ON)
if(MINIDUMP_INPROC_BUILD_SAMPLE)
    add_executable(MiniDumpInprocSample examples/crash_dump_sample.cpp)
    target_link_libraries(MiniDumpInprocSample PRIVATE MiniDumpInproc)
    if(MSVC)
        target_compile_options(MiniDumpInprocSample PRIVATE /W4 /permissive-)
        set_target_properties(MiniDumpInprocSample PROPERTIES LINK_FLAGS "/ENTRY:wmainCRTStartup")
    endif()

    add_executable(MiniDumpInprocStressTest examples/inproc_stress_test.cpp)
    target_link_libraries(MiniDumpInprocStressTest PRIVATE MiniDumpInproc)

    # Behavioral test for the SetMiniDumpInprocComment A/W setters. It links the static library and
    # inspects the internal comment buffer directly, so it needs the private src/ include directory.
    add_executable(MiniDumpCommentApiTest examples/comment_api_test.cpp)
    target_link_libraries(MiniDumpCommentApiTest PRIVATE MiniDumpInproc)
    target_include_directories(MiniDumpCommentApiTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

    add_executable(Ue4LikeLargeAppCrash examples/ue4_like_large_app_crash.cpp)
    target_link_libraries(Ue4LikeLargeAppCrash PRIVATE MiniDumpInproc)

    add_executable(MiniDumpInspect examples/minidump_inspect.cpp)
    target_link_libraries(MiniDumpInspect PRIVATE Dbghelp)

    add_library(MiniDumpOverflowStackExt SHARED examples/windbg_show_overflow_stack.cpp)
    target_link_libraries(MiniDumpOverflowStackExt PRIVATE Dbgeng)
    target_compile_definitions(MiniDumpOverflowStackExt PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)

    if(MSVC)
        # The stress test is a debugging/validation demo: build it WITHOUT optimization in every
        # config so WinDbg's `dv` can show stack locals (e.g. when validating indirect_object_graph
        # in a Release/RelWithDebInfo dump). /Od disables optimization, /Ob0 disables inlining and
        # /Oy- keeps frame pointers; these override the inherited /O2 /Ob (the D9025 "overriding"
        # notice is expected and harmless for this demo target only).
        target_compile_options(MiniDumpInprocStressTest PRIVATE /W4 /permissive- /Od /Ob0 /Oy-)
        set_target_properties(MiniDumpInprocStressTest PROPERTIES LINK_FLAGS "/ENTRY:wmainCRTStartup")
        target_compile_options(MiniDumpCommentApiTest PRIVATE /W4 /permissive-)
        set_target_properties(MiniDumpCommentApiTest PROPERTIES LINK_FLAGS "/ENTRY:wmainCRTStartup")
        target_compile_options(MiniDumpInspect PRIVATE /W4 /permissive-)
        set_target_properties(MiniDumpInspect PROPERTIES LINK_FLAGS "/ENTRY:wmainCRTStartup")
        # Disable optimization for the overflow recursion so the stack actually grows (the recursive
        # tail-call would otherwise be turned into a loop / optimized away).
        target_compile_options(Ue4LikeLargeAppCrash PRIVATE /W4 /permissive- /Od /Ob0 /Oy-)
        set_target_properties(Ue4LikeLargeAppCrash PROPERTIES LINK_FLAGS "/ENTRY:wmainCRTStartup")
        target_compile_options(MiniDumpOverflowStackExt PRIVATE /W4 /permissive-)
    endif()
endif()

set(DETOURS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/third_party/Detours" CACHE PATH "Path to Microsoft Detours source tree")
option(MINIDUMP_INPROC_BUILD_DETOURS_DEMO "Build MiniDumpWriteDump allocation tracing demo with Detours" OFF)
if(MINIDUMP_INPROC_BUILD_DETOURS_DEMO)
    if(NOT EXISTS "${DETOURS_ROOT}/src/detours.h")
        message(FATAL_ERROR "Detours source tree not found: ${DETOURS_ROOT}")
    endif()

    add_library(DetoursLocal STATIC
        "${DETOURS_ROOT}/src/detours.cpp"
        "${DETOURS_ROOT}/src/modules.cpp"
        "${DETOURS_ROOT}/src/disasm.cpp"
        "${DETOURS_ROOT}/src/image.cpp"
        "${DETOURS_ROOT}/src/creatwth.cpp"
        "${DETOURS_ROOT}/src/disolx86.cpp"
        "${DETOURS_ROOT}/src/disolx64.cpp"
        "${DETOURS_ROOT}/src/disolia64.cpp"
        "${DETOURS_ROOT}/src/disolarm.cpp"
        "${DETOURS_ROOT}/src/disolarm64.cpp"
    )
    target_include_directories(DetoursLocal PUBLIC "${DETOURS_ROOT}/src")
    target_compile_definitions(DetoursLocal PUBLIC WIN32_LEAN_AND_MEAN NOMINMAX)
    if(MSVC)
        target_compile_options(DetoursLocal PRIVATE /W3 /permissive- /wd4458 /wd4459 /wd4702)
    endif()

    add_executable(MiniDumpWriteDumpAllocTrace examples/minidumpwritedump_alloc_trace.cpp)
    target_link_libraries(MiniDumpWriteDumpAllocTrace PRIVATE DetoursLocal Dbghelp)
    target_compile_definitions(MiniDumpWriteDumpAllocTrace PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE)

    add_executable(MiniDumpInprocHeapFailTest examples/inproc_heap_fail_test.cpp)
    target_link_libraries(MiniDumpInprocHeapFailTest PRIVATE MiniDumpInproc DetoursLocal Dbghelp)
    target_compile_definitions(MiniDumpInprocHeapFailTest PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE)

    add_executable(GdiUserHandleAllocTrace examples/gdi_user_handle_alloc_trace.cpp)
    target_link_libraries(GdiUserHandleAllocTrace PRIVATE DetoursLocal user32 gdi32)
    target_compile_definitions(GdiUserHandleAllocTrace PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE)

    if(MSVC)
        target_compile_options(MiniDumpWriteDumpAllocTrace PRIVATE /W4 /permissive-)
        set_target_properties(MiniDumpWriteDumpAllocTrace PROPERTIES LINK_FLAGS "/ENTRY:wmainCRTStartup")
        target_compile_options(MiniDumpInprocHeapFailTest PRIVATE /W4 /permissive-)
        set_target_properties(MiniDumpInprocHeapFailTest PROPERTIES LINK_FLAGS "/ENTRY:wmainCRTStartup")
        target_compile_options(GdiUserHandleAllocTrace PRIVATE /W4 /permissive-)
        set_target_properties(GdiUserHandleAllocTrace PROPERTIES LINK_FLAGS "/ENTRY:wmainCRTStartup")
    endif()

endif()

