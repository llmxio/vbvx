cmake_minimum_required(VERSION 3.16)
project(VBVX LANGUAGES CXX VERSION 0.1.0)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# Header-only interface library
add_library(vbvx INTERFACE)
add_library(vbvx::vbvx ALIAS vbvx)

target_include_directories(vbvx INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/vbvx>
  $<INSTALL_INTERFACE:include/vbvx>
)

# Require C++23 for consumers when using this target
target_compile_features(vbvx INTERFACE cxx_std_23)

# Install headers
# - install the `vbvx/` directory to preserve layout (and any future subdirs)
install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/vbvx"
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# Also install any top-level public headers if present
file(GLOB VBVX_PUBLIC_HDRS_TOP
  "${CMAKE_CURRENT_SOURCE_DIR}/*.hxx"
)
if(VBVX_PUBLIC_HDRS_TOP)
  install(FILES ${VBVX_PUBLIC_HDRS_TOP} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/vbvx)
endif()

# install the license for packagers/users
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR})

# Export target for use by find_package
install(TARGETS vbvx
        EXPORT VBVXTargets
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/vbvx)

# Create and install the export file and package config
set(CONFIG_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}/cmake/VBVX")

# Configure a Config file that will find the exported targets
configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/VBVXConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/VBVXConfig.cmake
  INSTALL_DESTINATION ${CONFIG_INSTALL_DIR}
)

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/VBVXConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY AnyNewerVersion
)

install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/VBVXConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/VBVXConfigVersion.cmake
  DESTINATION ${CONFIG_INSTALL_DIR})

# Install the export targets (this generates VBVXTargets.cmake)
install(EXPORT VBVXTargets
  FILE VBVXTargets.cmake
  NAMESPACE vbvx::
  DESTINATION ${CONFIG_INSTALL_DIR})

# Make this project easy to use via FetchContent / add_subdirectory.
# When added via add_subdirectory(), the target vbvx::vbvx is available thanks to the ALIAS above.

# Optional: add an "export" target for packaging
add_custom_target(export-vbvx DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/VBVXConfig.cmake")

# Provide an easy option to build tests if the project ever gets them
option(BUILD_TESTING "Enable tests" OFF)
if(BUILD_TESTING)
  include(CTest)
  enable_testing()
  add_subdirectory(tests)
endif()

# Option to build API documentation using Doxygen
option(BUILD_DOCS "Enable generating API documentation (Doxygen)" OFF)
if(BUILD_DOCS)
  find_package(Doxygen)
  if(NOT DOXYGEN_FOUND)
    message(FATAL_ERROR "Doxygen is required to build docs. Install Doxygen or set BUILD_DOCS=OFF.")
  endif()

  set(DOXYFILE_IN ${CMAKE_CURRENT_SOURCE_DIR}/docs/Doxyfile.in)
  set(DOXYFILE_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
  configure_file(${DOXYFILE_IN} ${DOXYFILE_OUT} @ONLY)

  add_custom_target(docs
    COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYFILE_OUT}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Generating API documentation with Doxygen"
    VERBATIM)

  # Optional: install generated HTML
  install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/docs/html
          DESTINATION ${CMAKE_INSTALL_DOCDIR}
          OPTIONAL)
endif()
