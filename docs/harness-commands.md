# Command Harness

Run commands from the repository root unless a command explicitly says
otherwise.

## Configure

Configure a debug build with tests:

```bash
cmake -G Ninja -B build -S . -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
```

## Build

Build everything configured in `build/`:

```bash
cmake --build build
```

## Test

Run all tests through CTest:

```bash
ctest --test-dir build -V
```

Run one GoogleTest case directly:

```bash
build/tests/vbvx_tests --gtest_filter=TestSuite.TestName
```

## Documentation

Build API docs when Doxygen is available:

```bash
cmake -S . -B build -DBUILD_DOCS=ON
cmake --build build --target docs
```

HTML output is written to `build/docs/html`.
