# Coding Harness

## C++ Style

- Use the repository `.clang-format`.
- Keep two-space indentation, attached braces, and the 80-column limit.
- Keep files ASCII unless existing text requires another character set.
- Put public API in namespace `vbvx`.

## Packet Header Rules

- Preserve packed wire-header layout and related `static_assert`s.
- Treat on-wire numeric fields as network byte order.
- Use `autoswap`, helper accessors, and `std::to_underlying` for enum
  conversions.
- Before changing header layout, verify size, alignment, byte order, and tests
  for the affected wire format.

## Test Rules

- Tests use GoogleTest through CMake `FetchContent`.
- Add new test files to `tests/CMakeLists.txt`.
- Prefer focused tests that construct raw byte arrays in wire order, then
  assert `BufferView` or `HeaderView` behavior.
- Follow `TEST(ComponentTest, ScenarioName)`.
- Cover truncated buffers, invalid protocol combinations, and successful
  parsing paths for changed packet logic.
