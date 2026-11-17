# Contributing to SentinelFlow

Thank you for your interest in contributing to SentinelFlow! This document provides
guidelines and instructions for contributing to this C++17 Network Intrusion Detection
System.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)
- [Development Setup](#development-setup)
- [Building the Project](#building-the-project)
- [Running Tests](#running-tests)
- [Code Style](#code-style)
- [Commit Message Format](#commit-message-format)
- [Branch Naming Convention](#branch-naming-convention)
- [Pull Request Process](#pull-request-process)
- [Code Review Checklist](#code-review-checklist)

---

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
By participating, you are expected to uphold this code. Please report unacceptable
behaviour to the project maintainer.

## Reporting Bugs

If you find a bug in SentinelFlow, please open an issue using the
[Bug Report template](.github/ISSUE_TEMPLATE/bug_report.md). A good bug report includes:

- A clear, descriptive title prefixed with `[BUG]`.
- Steps to reproduce the issue.
- Expected versus actual behaviour.
- Your environment details (OS, compiler version, libpcap version).
- Any relevant log output, packet captures, or screenshots.

> **Security vulnerabilities** should **not** be reported via public issues.
> See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## Suggesting Features

Feature ideas are welcome! Please open an issue using the
[Feature Request template](.github/ISSUE_TEMPLATE/feature_request.md). Describe the
problem you are trying to solve, your proposed solution, and any alternatives you
have considered.

## Development Setup

### Prerequisites

| Dependency | Minimum Version |
|---|---|
| CMake | 3.18+ |
| C++ compiler | C++17 support (GCC 9+, Clang 10+, MSVC 19.14+) |
| libpcap | libpcap-dev / libpcap-devel |

#### Installing prerequisites

**Debian / Ubuntu:**

```bash
sudo apt update
sudo apt install build-essential cmake libpcap-dev
```

**Fedora / RHEL:**

```bash
sudo dnf install gcc-c++ cmake libpcap-devel
```

**macOS (Homebrew):**

```bash
brew install cmake
# libpcap is included with macOS by default
```

### Cloning the Repository

```bash
git clone https://github.com/Raoof128/SentinelFlow.git
cd SentinelFlow
```

## Building the Project

SentinelFlow uses CMake as its build system. To build with tests and benchmarks enabled:

```bash
cmake -B build -DBUILD_TESTING=ON -DBUILD_BENCH=ON
cmake --build build
```

For a release build:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON -DBUILD_BENCH=ON
cmake --build build
```

## Running Tests

After building, run the test suite with:

```bash
cd build && ctest --output-on-failure
```

All tests must pass before submitting a pull request. If you add new functionality,
include corresponding tests.

## Code Style

SentinelFlow follows a consistent code style enforced by `.clang-format`. Please adhere
to the following conventions:

### General Rules

- **Formatting:** Run `clang-format` on all changed files before committing. The
  repository root contains a `.clang-format` configuration file.

  ```bash
  clang-format -i src/**/*.cpp include/**/*.hpp
  ```

- **Namespace:** All project code lives in the `sf::` namespace.

  ```cpp
  namespace sf {
  // ...
  } // namespace sf
  ```

- **Include guards:** Use `#pragma once` at the top of every header file.

  ```cpp
  #pragma once

  #include <cstdint>
  // ...
  ```

- **Buffer-safe parsing:** When parsing network packets or any raw byte buffers, always
  validate lengths and boundaries before accessing data. Never assume buffer contents
  are well-formed. Prefer `std::span`, `std::string_view`, or explicit size parameters
  over raw pointer arithmetic.

- **Modern C++:** Prefer C++17 features (structured bindings, `std::optional`,
  `std::variant`, `if constexpr`, etc.) where they improve clarity.

- **Naming conventions:**
  - Classes and structs: `PascalCase`
  - Functions and methods: `camelCase`
  - Variables: `camelCase`
  - Constants and enum values: `UPPER_SNAKE_CASE`
  - File names: `snake_case.cpp`, `snake_case.hpp`

## Commit Message Format

This project uses **Conventional Commits**. Every commit message must follow this format:

```
<type>: <short summary>

[optional body]

[optional footer(s)]
```

### Types

| Type | Description |
|---|---|
| `feat` | A new feature |
| `fix` | A bug fix |
| `docs` | Documentation changes only |
| `test` | Adding or updating tests |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `ci` | Changes to CI configuration or scripts |
| `style` | Formatting, white-space, or other non-functional changes |
| `perf` | A performance improvement |
| `chore` | Maintenance tasks (dependencies, tooling, etc.) |

### Examples

```
feat: add TCP reassembly module

Implements stream tracking and segment reordering for TCP flows.
Handles out-of-order packets and overlapping segments.
```

```
fix: prevent buffer overread in IPv4 header parser
```

```
test: add unit tests for rule engine pattern matching
```

## Branch Naming Convention

Use the following prefixes for branch names:

| Prefix | Purpose |
|---|---|
| `feature/` | New features (e.g., `feature/tcp-reassembly`) |
| `fix/` | Bug fixes (e.g., `fix/ipv4-header-overread`) |
| `docs/` | Documentation updates (e.g., `docs/update-readme`) |

Keep branch names short, lowercase, and hyphen-separated.

## Pull Request Process

1. **Fork** the repository and clone your fork locally.
2. **Create a branch** from `main` using the naming convention above.
3. **Make your changes**, keeping commits atomic and well-described.
4. **Run the full test suite** and ensure all tests pass.
5. **Run `clang-format`** on all modified files.
6. **Push** your branch to your fork.
7. **Open a Pull Request** against the `main` branch of the upstream repository.
8. **Fill out the PR template** completely.
9. **Respond to review feedback** promptly.

A maintainer will review your PR. Small, focused PRs are reviewed faster than large,
sweeping changes. If your change is large, consider splitting it into multiple PRs.

## Code Review Checklist

Reviewers (and contributors performing self-review) should verify the following:

- [ ] The code compiles without warnings (`-Wall -Wextra -Wpedantic`).
- [ ] All existing tests pass.
- [ ] New functionality includes appropriate tests.
- [ ] Code follows the project's style guide and passes `clang-format`.
- [ ] Buffer and packet parsing is bounds-checked and safe.
- [ ] No new compiler warnings are introduced.
- [ ] Public API changes are documented.
- [ ] Commit messages follow the conventional commits format.
- [ ] The PR description clearly explains what the change does and why.
- [ ] No sensitive data (credentials, private keys, PCAPs with real traffic) is included.

---

Thank you for helping improve SentinelFlow! If you have any questions, feel free to open
a discussion or reach out to the maintainer.
