cmake_minimum_required(VERSION 3.4.1)
set(CMAKE_CXX_STANDARD 14)


message("Building ${LIB_NAME} for Android(${CMAKE_SYSTEM_PROCESSOR})...")
ENABLE_LANGUAGE(ASM)

set(LIBRARY_NAME ${LIB_NAME})


set(RATEL_NATIVE_SOURCE
        Jni/VAJni.cpp
        Jni/Helper.cpp
        Jni/IOController.cpp
        Foundation/syscall/BinarySyscallFinder.cpp
        Foundation/dlfcn_nougat.cpp
        Foundation/canonicalize_md.c
        Foundation/MapsRedirector.cpp
        Foundation/IORelocator.cpp
        Foundation/Symbol.cpp
        Foundation/SandboxFs.cpp
        Foundation/SandboxProperties.cpp
        Foundation/RatelPatch.cpp
        Foundation/elf_util.cpp
        Foundation/ExecveHandler.cpp
        Foundation/MacAddressFake.cpp
        Foundation/NativeStackTracer.cpp
        Foundation/VMHook.cpp
        Substrate/hde64.c
        Substrate/SubstrateDebug.cpp
        Substrate/SubstrateHook.cpp
        Substrate/SubstratePosixMemory.cpp
        Substrate/And64InlineHook.cpp
        arthook/sandhook.cpp
        arthook/trampoline.cpp
        arthook/cast.cpp
        arthook/art.cpp
        arthook/native_api.cpp
        arthook/inst.cpp
        arthook/offset.cpp
        arthook/arch/arm32.S
        arthook/arch/arm64.S
        # xhook from https://github.com/iqiyi/xHook
        xhook/xhook.c
        xhook/xh_core.c
        xhook/xh_elf.c
        xhook/xh_jni.c
        xhook/xh_log.c
        xhook/xh_util.c
        xhook/xh_version.c

        # 脱壳
        unpack/Unpacker.cpp
        unpack/MyMd5.cpp
        unpack/elf_image.cpp
        unpack/process_map.cpp

        # maps文件隐藏
        MapHide/hide.cpp
        MapHide/wrap.cpp
        MapHide/pmparser.c
        MapHide/MapsHideHandler.cpp


        )
include_directories(Foundation)
include_directories(Jni)
include_directories(arthook)
include_directories(xhook)
include_directories(unpack)
include_directories(MapHide)
include_directories(./)

# add_definitions(-std=c++11)

add_definitions(-DCORE_SO_NAME="${LIBRARY_NAME}")
set(CXX_APPEND_FLAGS "-funwind-tables -g -Wgcc-compat")

IF (CMAKE_BUILD_TYPE STREQUAL Release)
    # 开源以前，我们需要做ollvm混淆，但是现在开源了，所以我们关闭ollvm混淆
    # 如果您公司需要自行做保护，那么可以根据下面资料进行ollvm环境搭建
    # https://www.jianshu.com/p/e0637f3169a3
    # set(CXX_APPEND_FLAGS "${CXX_APPEND_FLAGS} -fvisibility=hidden -mllvm -sub -mllvm -bcf_prob=5 -mllvm -fla ")

    set(CXX_APPEND_FLAGS "${CXX_APPEND_FLAGS} -fvisibility=hidden ")
    #include_directories(env/release)
    add_definitions(-DRATEL_BUILD_TYPE_RELEASE)
ELSE ()
    add_definitions(-DRATEL_BUILD_TYPE_DEBUG)
    #include_directories(env/debug)
ENDIF ()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CXX_APPEND_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x ${CXX_APPEND_FLAGS}")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -s -Wl,--gc-sections")

set(RATEL_SOURCE ${RATEL_NATIVE_SOURCE})

add_library(${LIBRARY_NAME} SHARED ${RATEL_SOURCE})

target_link_libraries(${LIBRARY_NAME} log)


## anrdetector
add_executable(libratelanr.so
        anr/anrDetector.cpp)
target_link_libraries(libratelanr.so log)

set(HIDDEN_NATIVE_SOURCE
        MapHide/hide.cpp
        MapHide/wrap.cpp
        MapHide/pmparser.c
        MapHide/MapsHideHandler.cpp
        MapHide/nativeHideJni.cpp
        #        Jni/Helper.cpp
        )
add_library("ratelhide" SHARED ${HIDDEN_NATIVE_SOURCE})

target_link_libraries("ratelhide" log)

include_directories(zipalign)
include_directories(zipalign/base/include)
set(ZIP_ALIGN_SOURCE
        zipalign/ZipAlign.cpp
        zipalign/ZipEntry.cpp
        zipalign/ZipFile.cpp
        zipalign/utils/Errors.cpp
        zipalign/utils/VectorImpl.cpp
        zipalign/utils/SharedBuffer.cpp

        zipalign/zopfli/deflate.c
        zipalign/zopfli/util.c


        zipalign/base/abi_compatibility.cpp
        zipalign/base/chrono_utils.cpp
        zipalign/base/cmsg.cpp
        zipalign/base/errors_unix.cpp
        zipalign/base/file.cpp
        zipalign/base/liblog_symbols.cpp
        zipalign/base/logging.cpp
        zipalign/base/mapped_file.cpp
        zipalign/base/parsebool.cpp
        zipalign/base/parsenetaddress.cpp
        zipalign/base/process.cpp
        zipalign/base/properties.cpp
        zipalign/base/stringprintf.cpp
        zipalign/base/strings.cpp
        zipalign/base/threads.cpp
        # 这应该是为了适配windows的
        #  zipalign/base/utf8.cpp

        zipalign/ziparchive/zip_archive.cc
#        zipalign/ziparchive/zip_archive_benchmark.cpp
        zipalign/ziparchive/zip_archive_stream_entry.cc
        zipalign/ziparchive/zip_writer.cc
        zipalign/ziparchive/ziptool.cpp


        )

add_executable("zipalign" ${ZIP_ALIGN_SOURCE})
target_link_libraries("zipalign" log)