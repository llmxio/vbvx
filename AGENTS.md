# Repository Guidelines

## Project Structure & Module Organization

VBVX is a header-only C++23 library for zero-copy packet header views. Public
headers live in `vbvx/`; keep protocol-specific definitions there and preserve
the include style used by existing `.hxx` files. Unit tests live in `tests/` and
are built into the single `vbvx_tests` GoogleTest executable. CMake package
support is under `cmake/`. Doxygen configuration and documentation helpers live
in `docs/`.

## Build, Test, and Development Commands

Configure a debug build with tests:

```bash
cmake -G Ninja -B build -S . -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
```

Build everything configured in `build/`:

```bash
cmake --build build
```

Run all tests through CTest:

```bash
ctest --test-dir build -V
```

Run one GoogleTest case directly:

```bash
build/tests/vbvx_tests --gtest_filter=TestSuite.TestName
```

Build API docs when Doxygen is available:

```bash
cmake -S . -B build -DBUILD_DOCS=ON
cmake --build build --target docs
```

## Coding Style & Naming Conventions

Use the repository `.clang-format` for C++ formatting: two-space indentation,
attached braces, and an 80-column limit. Keep files ASCII unless existing text
requires otherwise. Header files use `.hxx`; tests use `test_*.cxx`. Put public
API in namespace `vbvx`. Preserve packed wire-header layout and related
`static_assert`s. Treat on-wire numeric fields as network byte order; use
`autoswap`, helper accessors, and `std::to_underlying` for enum conversions.

## Testing Guidelines

Tests use GoogleTest via CMake `FetchContent`. Add new test files to
`tests/CMakeLists.txt`. Prefer focused tests that construct raw byte arrays in
wire order, then assert `BufferView` or `HeaderView` behavior. Follow the
existing naming pattern: `TEST(ComponentTest, ScenarioName)`. Cover truncated
buffers, invalid protocol combinations, and successful parsing paths for changed
packet logic.

## Commit & Pull Request Guidelines

Recent history uses short conventional-style subjects such as `fix: ...` and
`refactor: ...`; keep commit messages imperative and scoped. Pull requests
should describe the behavior change, list test commands run, link related
issues, and mention layout or ABI-impacting header changes. Include generated
documentation updates only when docs output is intentionally part of the change.

## Agent-Specific Instructions

Do not run Git commands that modify history, the index, or branches unless the
user explicitly requests them. Before changing header layout, verify size,
alignment, byte order, and tests for the affected wire format.
