# VBVX - VPP Buffer View eXtensions

[![Build and Test](https://github.com/llmxio/vbvx/actions/workflows/test.yml/badge.svg)](https://github.com/llmxio/vbvx/actions/workflows/test.yml)
[![Build Documentation](https://github.com/llmxio/vbvx/actions/workflows/docs.yml/badge.svg)](https://github.com/llmxio/vbvx/actions/workflows/docs.yml)

VBVX (VPP Buffer View eXtensions) is a small, header-only C++23 library for **zero-copy** parsing of packet buffers. It provides views over common on-wire headers (Ethernet, VLAN, ARP, IPv4/v6, TCP/UDP, ICMP, SRv6) without copying.

## About

- **Purpose:** Safe, zero-copy access to common wire-protocol headers for packet parsing/inspection.
- **Core abstractions:**
  - `BufferView` - parses offsets and exposes header views and helper accessors (e.g., `ether_type()`, `l3_offset()`, `l4_offset()`).
  - `HeaderView<H>` - lightweight wrapper around `const H*` with a `.copy()` helper when a local value is needed.
  - `FlagsView` / `ConstFlagsView` - zero-copy, chainable views for bitmask enums; enable operators by specializing `vbvx::enable_bitmask_operators<YourEnum>`.
  - `vbvx/*` - packed POD header structs with compile-time checks for layout and alignment.

Design notes: headers are `[[gnu::packed]]` with `alignof == 1`. On-wire fields are network byte order; use helpers like `autoswap` to convert to host order.

## Features

- Zero-copy, bounds-checked views for L2/L3/L4 headers (Ethernet/VLAN/ARP, IPv4/IPv6, TCP/UDP, ICMP)
- SRv6 (Segment Routing over IPv6): SRH segment list + TLV parsing
- Header-only C++23 library (easy to vendor)
- Endianness agnostic (e.g., `autoswap`) and sane accessors for on-wire fields
- GoogleTest-based unit tests that cover parsing branches

## Using VBVX from CMake

You can consume VBVX from your CMake-based project in two common ways: vendoring it with `add_subdirectory`, or fetching it at configure time with `FetchContent`.

### 1) Via `add_subdirectory` (vendored or submodule)

Add the VBVX source tree into your project (e.g., as a submodule or copied directory) and call:

```cmake
# From your top-level CMakeLists.txt
add_subdirectory(path/to/vbvx)

# Link the provided target into your executable/library
target_link_libraries(my_app PRIVATE vbvx::vbvx)
```

This is simple and keeps control in your project's tree.

### 2) Via `FetchContent` (recommended for external deps)

Use CMake's `FetchContent` to declare and make VBVX available at configure time. Pin a tag or commit for reproducible builds:

```cmake
include(FetchContent)

FetchContent_Declare(vbvx
  GIT_REPOSITORY https://github.com/llmxio/vbvx.git
  GIT_TAG        vX.Y.Z  # pin to a release tag or commit
)
FetchContent_MakeAvailable(vbvx)

target_link_libraries(my_app PRIVATE vbvx::vbvx)
```

Notes:

- Prefer pinning a tag or commit with `FetchContent` for reproducible builds.
- If you installed (see below) VBVX system-wide via `cmake --install`, you can also use `find_package(VBVX CONFIG REQUIRED)` and link `vbvx::vbvx`.

## Install

Requirements:

- A C++23-capable compiler (GCC/Clang) and CMake (Ninja recommended).

Quick build and test:

```bash
# Configure (enable tests)
cmake -G Ninja -B build -S . -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
# Build
cmake --build build
# Run tests (verbose)
ctest --test-dir build -V
# Or run a specific test binary
build/tests/vbvx_tests --gtest_filter=TestSuite.TestName
```

Optional install:

```bash
cmake --install build --prefix /some/install/prefix
```

## Documentation

Build the HTML API docs using Doxygen (requires Doxygen to be installed):

```bash
# Configure with docs enabled
cmake -S . -B build -DBUILD_DOCS=ON
# Build docs target
cmake --build build --target docs
# HTML output: build/docs/html
```

## Usage

Include the main header and construct a `BufferView` over your packet data:

```cpp
#include "vbvx/buffer_view.hxx"

vbvx::BufferView buf(data, len);
if (auto ip = buf.ipv4_header()) {
  if (auto proto = buf.ip_protocol(); proto == vbvx::IpProtocol::TCP) {
    if (auto tcp = buf.tcp_header()) {
      auto src_port = tcp->src_port();
      auto dst_port = tcp->dst_port();
      // use src/dst
    }
  }
}
```

Notes:

- Use `hv.copy()` on a `HeaderView` when you need a local copy to mutate or hold beyond the original buffer lifetime.
- Expect on-wire fields in network byte order; use `autoswap` or provided helpers to get host-order values.

## SRv6

- SRv6 header definitions live in `vbvx/srv6_header.hxx`.
- Tests: `tests/test_srv6_header.cxx`, `tests/test_srv6_tlv.cxx`.
- Example - obtain an SRv6 header and inspect segments/TLVs:

```cpp
#include "vbvx/buffer_view.hxx"

vbvx::BufferView buf(packet_data, packet_len);
if (auto srh = buf.srv6_header()) {
  if (!srh->is_valid_routing_type()) {
    // Not an SRH (routing type mismatch)
  } else {
    // Number of 128-bit SIDs in the segment list
    auto n = srh->segments_count();

    // Access the first SID (returns std::span<const uint8_t, 16>)
    auto first_sid = srh->segment_at(0);

    // Iterate TLVs without allocation
    vbvx::SRv6TlvIterator it(srh->tlv_first_ptr(), srh->tlv_bytes_len());
    vbvx::SRv6Tlv t;
    while (it.next(t)) {
      // handle t.type, t.length and t.value
    }
  }
}
```

- Note: `BufferView::srv6_header()` returns an SRH only when the IPv6 Next Header is Routing (43) and the SRH is the first extension header.
- When adding SRv6 features/tests, follow the existing pattern: raw byte arrays in wire order + `HeaderView`/`BufferView` assertions.

## FlagsView

Use this when you’ve got a bitmask enum (usually a field inside a header struct) and you want a small view to flip bits without copying.

- `FlagsView<Enum>`: mutable, chainable (set/clear/toggle/reset)
- `ConstFlagsView<Enum>`: read-only (has/has_all)
- To enable `|`, `&`, `^`, `~`, and shifts on your enum, specialize `vbvx::enable_bitmask_operators<Enum>` to `std::true_type`

Example:

```cpp
#include "vbvx/flags_view.hxx"

enum class FooFlags : uint8_t {
  None = 0,
  A = 1 << 0,
  B = 1 << 1,
  C = 1 << 2,
};

template<> struct vbvx::enable_bitmask_operators<FooFlags> : std::true_type {};

FooFlags flags = FooFlags::None;

vbvx::FlagsView fv(flags);
fv.set(FooFlags::A).set(FooFlags::B);
fv.clear(FooFlags::A);
fv.toggle(FooFlags::C);

if (fv.has(FooFlags::B)) {
  // ...
}

vbvx::ConstFlagsView cfv = fv;
auto current = cfv.value();
```

Notes: No allocation, no indirection: it just operates on the underlying enum value you pass in.

## License & Acknowledgements

This project is licensed under MIT license. Full terms are in the `LICENSE` file.
