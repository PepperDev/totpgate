# Contributing to totpgate

## Getting Started

1. Fork the repository.
2. Create a feature branch from `main`.
3. Make changes following the project conventions.
4. Run the full quality gate locally.
5. Submit a pull request.

## Code Style

- Use `make style` to auto-format: `indent -linux -l120 -i2 -nut`.
- Always wrap blocks with braces, even for single-line `if`/`for`/`while`/`do`.
- No trailing whitespace.
- Run `make style` before every commit; the CI pipeline also checks that
  `git diff --exit-code` passes after formatting.

## Coding Conventions

### General

- Write for **human comprehension**.  Prefer clear names over clever tricks.
- **Avoid code duplication**.  Extract shared logic into static helpers.
- Apply **SOLID** principles — especially Single Responsibility and
  Dependency Inversion.
- Follow the Transformation Priority Premise and Object Calisthenics.
- To make unit tests easy, keep code decoupled and context-agnostic.  Write
  independent functions that receive arguments, process, and return, without
  relying on global, static, or shared variables.  Use interface segregation
  and dependency inversion.
- Return `int` error codes (0 = success, negative = errno-style).
- Assert pre-conditions with `assert()` from `<assert.h>`.

### Naming

| Element | Convention | Example |
|---|---|---|
| Functions | `snake_case` | `totp_validate` |
| Globals | `g_` prefix | `g_config` |
| Macros / enums | `UPPER_SNAKE` | `TOTP_DIGITS` |
| Types | `snake_case_t` | `totp_ctx_t` |
| File-local | `static` | |

### Error handling

- Check every syscall / function return.
- On failure, set `errno` and return negative.
- Top-level `main()` prints `strerror(errno)` before exiting.

### Memory

- Prefer stack allocation.
- When heap is required, `calloc` + paired `free`, no `malloc`/`realloc`
  without zeroing.
- No variable-length arrays (VLAs are problematic in C99 in practice).

## Testing

Create unit tests without relying on a third-party testing library/framework.
The test runner lives in `test/test_runner.c` and provides:

- `TEST_GROUP(name)` / `TEST(name)` / `END_TEST`
- `ASSERT_INT_EQ`, `ASSERT_PTR_EQ`, `ASSERT_STREQ`, `ASSERT_TRUE`,
  `ASSERT_FALSE`
- `RUN_TEST(group, name)`
- `RUN_GROUP(group)` — runs all tests in a group

Use dummies, stubs, fakes, mocks, and spies where appropriate.  Mocks live in
`test/mock_*.c` and replace real implementations at link time.

## Quality Gate

No commit may bypass any quality gate item.  All thresholds are mandatory.

| Tool | Threshold |
|---|---|
| **Compiler** | Zero warnings (`-Wall -Wextra -pedantic -pedantic-errors`) |
| **cppcheck** | `--enable=all --check-level=exhaustive` must succeed |
| **gcov** | At least 80 % line coverage |
| **lizard — LOC per file** | Max 600 (non-comment, non-blank; `src/` only, excludes tests) |
| **lizard — LOC per function** | Max 80 (non-comment, non-blank; `src/` only, excludes tests) |
| **lizard — cyclomatic complexity** | Max 10 |
| **lizard — tokens per function** | Max 500 |
| **lizard — nested control depth** | Max 3 |
| **lizard — function parameters** | Max 5 |
| **lizard — cohesion & coupling** | Max 1 public abstraction per file |

lizard exceptions: avoid at all costs by refactoring.  Only when impossible to
meet a gate, add a justification to [QA.md §Code Quality Exceptions](./QA.md#code-quality-exceptions),
before Past Incidents.

## Definition of Done

All items below are mandatory.  A change is not complete until every item
passes.

- [ ] Code builds with zero warnings
- [ ] All tests succeed
- [ ] Code style is applied (`make style`) and `git diff --exit-code` passes
- [ ] All quality gate thresholds are met (`make cppcheck`, `make lizard`)
- [ ] Bug prevention has been reviewed — see [QA.md §Bug Prevention](./QA.md#bug-prevention)
- [ ] TODO housekeeping is applied — bullets ticked, completed sections removed
- [ ] All documents and man pages are consistent with the code and vice-versa

## TODO Housekeeping

Organise [TODO.md](./TODO.md) into meaningful sections, each with checkable
bullet items.  Tick bullets as tasks are completed.  When all bullets in a
section are ticked, remove the entire section.

## Domain Knowledge

Refer to [DOMAIN.md](./DOMAIN.md) for business rules, CLI arguments, entities,
flow/lifecycle, retry landscape, memory management strategies, threading
architecture, and glossary.

## Task Lifecycle

A task is considered completed only when it fulfils all conditions in the
Definition of Done.

## Pull Request Process

1. Ensure the complete Definition of Done is met (see §Definition of Done
   above).
2. Ensure all quality gate checks pass.
3. Update [DOMAIN.md](./DOMAIN.md) if architecture, CLI, or business rules
   change.
4. Update [TODO.md](./TODO.md) following the TODO housekeeping rules.
5. Follow the bug prevention process — see [QA.md §Bug Prevention](./QA.md#bug-prevention).
