cmake_minimum_required(VERSION 3.20)
project(audit_reporter_qt6_import LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC OFF)
set(CMAKE_AUTORCC OFF)

find_package(Qt6 REQUIRED COMPONENTS Core Widgets)

set(CORE_SRC
  src/ini.cpp
  src/report.cpp
  src/ports_txt.cpp
  src/alerts_txt.cpp
  src/import_qt.cpp
)

add_executable(audit_reporter_cli
  ${CORE_SRC}
  src/main_cli.cpp
)
target_include_directories(audit_reporter_cli PRIVATE src)
target_link_libraries(audit_reporter_cli PRIVATE Qt6::Core)

add_executable(audit_reporter_gui
  ${CORE_SRC}
  src/gui_main.cpp
  src/MainWindow.cpp
  src/MainWindow.h
)
target_include_directories(audit_reporter_gui PRIVATE src)
target_link_libraries(audit_reporter_gui PRIVATE Qt6::Core Qt6::Widgets)

if (WIN32)
  set_target_properties(audit_reporter_gui PROPERTIES WIN32_EXECUTABLE ON)
endif()
