cmake_minimum_required(VERSION 3.5.1)

project(alert_msgpack CXX C)

include(FindPkgConfig)
pkg_search_module(SNORT3 REQUIRED snort)
pkg_search_module(MSGPACK REQUIRED msgpack)

add_library(alert_msgpack SHARED alert_msgpack.cc)
set_property(TARGET alert_msgpack PROPERTY CXX_STANDARD 11)

target_include_directories(alert_msgpack PUBLIC
    ${SNORT3_INCLUDE_DIRS}
    ${MSGPACK_INCLUDE_DIRS}
)

if ( APPLE )
    set(CMAKE_SHARED_LINKER_FLAGS
        "${CMAKE_SHARED_LINKER_FLAGS} -undefined dynamic_lookup")
endif ( APPLE )
