# Documentation

This directory contains the Doxygen template used to generate the API docs for the project.

To build the docs locally:

1. Configure with docs enabled:

   cmake -S . -B build -DBUILD_DOCS=ON

2. Build the `docs` target:

   cmake --build build --target docs

The HTML output will be in `build/docs/html`.
