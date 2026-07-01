# Project Harness

VBVX is a header-only C++23 library for zero-copy packet header views.

## Repository Layout

- `vbvx/` contains public headers. Keep protocol-specific definitions here and
  preserve the include style already used by existing `.hxx` files.
- `tests/` contains GoogleTest unit tests. All tests build into the single
  `vbvx_tests` executable.
- `cmake/` contains CMake package support.
- `docs/` contains Doxygen configuration, documentation helpers, generated-doc
  notes, and these harness instruction files.

## Ownership Rules

- Public API belongs in namespace `vbvx`.
- Header files use the `.hxx` extension.
- Test files use the `test_*.cxx` naming pattern.
- Generated documentation output should not be committed unless it is
  intentionally part of the change.
