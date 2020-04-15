cmake_minimum_required(VERSION 3.15)
project(uSniffer)

set(CMAKE_CXX_STANDARD 14)

## Boost
#find_package(Boost REQUIRED PATHS C:/boost)
#include_directories(${Boost_INCLUDE_DIRS})


# Qt
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)
find_package(Qt5 COMPONENTS Widgets Core REQUIRED PATHS C:/Qt/Qt5.14.1/5.14.1/mingw73_64)
set(CMAKE_INCLUDE_CURRENT_DIR ON)
include_directories(${Qt5Widgets_INCLUDE_DIRS} ${Qt5Core_INCLUDE_DIRS})


include_directories(WpdPack/Include)
link_directories(WpdPack/Lib/x64)

#target_link_libraries(uSniffer wpcap ws2_32 ${Boost_LIBRARIES} ${Qt5Widgets_LIBRARIES} ${Qt5Core_LIBRARIES})
add_executable(uSniffer main.cpp view.cpp view.h packets.cpp packets.h controller.cpp controller.h DeviceWindow.cpp DeviceWindow.h)

target_link_libraries(uSniffer wpcap ws2_32 ${Qt5Widgets_LIBRARIES} ${Qt5Core_LIBRARIES})