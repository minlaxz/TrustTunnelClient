cmake_minimum_required(VERSION 3.24)

set(ROOT_DIR ../..)

if(NOT CMAKE_INSTALL_PREFIX MATCHES "conan2")
    set(CMAKE_PROJECT_TOP_LEVEL_INCLUDES "${ROOT_DIR}/cmake/conan_bootstrap.cmake")
endif()

project(trusttunnel_windows)

set(CMAKE_C_STANDARD 20)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY MultiThreaded)
    add_compile_options(/W4)
    add_link_options(/W4)
else ()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif ()

if (NOT TARGET vpnlibs_trusttunnel)
    add_subdirectory(${ROOT_DIR} ${CMAKE_BINARY_DIR}/trusttunnel)
endif ()

add_library(trusttunnel_windows_a STATIC src/trusttunnel.cpp src/trusttunnel_pipe.cpp)
target_include_directories(trusttunnel_windows_a PUBLIC include)
target_link_libraries(trusttunnel_windows_a vpnlibs_trusttunnel)

add_library(trusttunnel_windows SHARED src/trusttunnel.cpp)
target_link_libraries(trusttunnel_windows trusttunnel_windows_a)
set_target_properties(trusttunnel_windows PROPERTIES OUTPUT_NAME trusttunnel)

add_executable(trusttunnel_test test/trusttunnel_test.cpp)
target_link_libraries(trusttunnel_test trusttunnel_windows_a)

add_executable(trusttunnel_service src/trusttunnel_service.cpp)
target_link_libraries(trusttunnel_service trusttunnel_windows_a)

add_executable(trusttunnel_service_installer src/trusttunnel_service_installer.cpp)
target_link_libraries(trusttunnel_service_installer trusttunnel_windows_a)

add_executable(trusttunnel_service_test test/trusttunnel_service_test.cpp)
target_link_libraries(trusttunnel_service_test trusttunnel_windows_a)
add_dependencies(trusttunnel_service_test trusttunnel_service)

enable_testing()
include(${ROOT_DIR}/cmake/add_unit_test.cmake)
set(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/test)

link_libraries(trusttunnel_windows_a)

add_unit_test(trusttunnel_pipe_test "${TEST_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/src" TRUE TRUE)
add_unit_test(trusttunnel_ring_buffer_test "${TEST_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/src" TRUE TRUE)
add_unit_test(trusttunnel_log_test "${TEST_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/src" TRUE TRUE)

# Install the shared library (DLL + import lib).  The shared library contains
# all transitive static dependencies linked in — no third-party .lib files
# needed by the consumer.  The import lib (trusttunnel.lib) is used at link
# time; the DLL (trusttunnel.dll) is needed at runtime.
install(TARGETS trusttunnel_windows
    RUNTIME DESTINATION bin
    ARCHIVE DESTINATION lib
    COMPONENT Runtime
)

# Install the service executable
install(TARGETS trusttunnel_service
    RUNTIME DESTINATION bin
    COMPONENT Runtime
)

# Install the service installer helper executable
install(TARGETS trusttunnel_service_installer
    RUNTIME DESTINATION bin
    COMPONENT Runtime
)

# Install public headers
install(DIRECTORY include/vpn
    DESTINATION include
    COMPONENT Runtime
)

# Install the platform.h header (needed by trusttunnel.h and trusttunnel_service.h)
install(FILES ${ROOT_DIR}/common/include/vpn/platform.h
    DESTINATION include/vpn
    COMPONENT Runtime
)

# Install the CMake package config file
install(
    FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/TrustTunnelClientWindowsConfig.cmake
    DESTINATION lib/cmake/TrustTunnelClientWindows
    COMPONENT Runtime
)
