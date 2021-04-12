cmake_minimum_required (VERSION 3.8)

project ("sBid" CXX)

SET(CMAKE_BINARY_DIR ${sBid_SOURCE_DIR}/build)
MESSAGE(STATUS "This is BINARY dir " ${sBid_BINARY_DIR})
MESSAGE(STATUS "This is SOURCE dir "${sBid_SOURCE_DIR})
# 将源代码添加到此项目的可执行文件。
ADD_SUBDIRECTORY(src bin)

# TODO: 如有需要，请添加测试并安装目标。
