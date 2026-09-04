# Contributing

The project favors small, auditable changes over broad host inspection. Every
new collected field needs a documented SOC 2 evidence purpose, a privacy review,
a schema test, and platform-specific tests. Do not add analytics, command
execution, shell interpolation, or opaque binary dependencies.

Before opening a pull request, run `go test ./...`, `go vet ./...`, and format
changed Go files with `gofmt -w`. Keep changes accessible and explain platform
permissions in the pull request description.
