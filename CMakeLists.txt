cmake_minimum_required (VERSION 3.8)

project ("sBid" CXX)

SET(CMAKE_CXX_FLAGS "-std=c++17 -g")
SET(CMAKE_BINARY_DIR ${sBid_SOURCE_DIR}/build)


ADD_SUBDIRECTORY(src bin)

# TODO: 如有需要，请添加测试并安装目标。
