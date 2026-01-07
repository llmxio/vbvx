cmake_minimum_required(VERSION 3.16)

include(FetchContent)

# Fetch GoogleTest via FetchContent
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        v1.15.2
)
# Prevent gtest from overriding our compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# Tests
add_executable(vbvx_tests
  test_buffer_view.cxx
  test_arp.cxx
  test_icmp4.cxx
  test_icmp6.cxx
  test_ip4_header.cxx
  test_ip6_header.cxx
  test_srv6_header.cxx
  test_srv6_tlv.cxx
  test_tcp_header.cxx
  test_header_view.cxx
  test_flags_view.cxx
)

target_link_libraries(vbvx_tests PRIVATE vbvx::vbvx GTest::gtest_main)

enable_testing()
include(GoogleTest)

gtest_discover_tests(vbvx_tests)
