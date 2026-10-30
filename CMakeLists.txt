cmake_minimum_required(VERSION 3.20)
project(sshmon VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 6.4 REQUIRED COMPONENTS Core Widgets)
find_package(KF6StatusNotifierItem CONFIG REQUIRED)

add_library(sshmon-core STATIC src/monitor.cpp src/monitor.h)
target_link_libraries(sshmon-core PUBLIC Qt6::Core)
target_include_directories(sshmon-core PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")

add_executable(sshmon src/tray.cpp)
target_link_libraries(sshmon PRIVATE sshmon-core Qt6::Widgets KF6::StatusNotifierItem)

include(CTest)
if(BUILD_TESTING)
    add_executable(sshmon-tests tests/monitor_tests.cpp)
    target_link_libraries(sshmon-tests PRIVATE sshmon-core)
    add_test(NAME monitor-parser-and-rates COMMAND sshmon-tests)
endif()

install(TARGETS sshmon RUNTIME DESTINATION bin)
