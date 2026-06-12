# Contributing to SecureLens

Welcome to SecureLens! We appreciate your interest in contributing to the project. Follow these guidelines to ensure a smooth collaboration process.

---

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct. Please read [CODE_OF_CONDUCT.md](file:///home/Krishna-Singh/securelens-backend/CODE_OF_CONDUCT.md) to understand the expectations we have for community members.

---

## Where to Start?

If you are a first-time contributor or looking for a quick way to get involved, head over to our GitHub Issues tab. We actively maintain labels like:
* **`good first issue`** - Small, isolated tasks perfect for getting familiar with the repository layout.
* **`help wanted`** - Features, bugs, or refactoring tasks that are high priority for our current roadmap.

---

## How to Contribute

### 1. Report Issues and Propose Features

Before writing code, search our issue tracker to ensure the topic has not been discussed or resolved. If you find a new bug or have a feature request:
* Create a detailed issue explaining the bug, with steps to reproduce it.
* Describe the expected behavior and system details (OS, Python version, configuration).
* If proposing a new feature, explain the use case and how it benefits developers.

### 2. The Pull Request Process

To submit code changes:
1. Fork the repository on GitHub.
2. Clone your fork locally.
3. Create a descriptive feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
4. Write your code, update relevant documentation, and write unit tests.
5. Run the test suite and verify all checks pass.
6. Commit your changes with clear, structured messages.
7. Push to your fork and submit a Pull Request (PR) to our `main` branch.

---

## Local Development and Style Standards

### 1. Code Style

We enforce standard Python formatting to keep the codebase maintainable and readable:
* Use standard line length limits (88 characters).
* Use explicit type hinting for function arguments and return values where possible.
* Document modules, classes, and public functions with clear docstrings.

### 2. Linting, Formatting & Pre-Commit

Run linting checks before committing. We recommend installing our pre-commit hook framework to automate these checks natively from your git environment:

```bash
# Install the hooks locally
pre-commit install

# Manually run checks against all files
pre-commit run --all-files
```

If you prefer to run individual formatters and linters manually (or via our project shortcuts):
```bash
# Run via Makefile automation
make lint

# Or run manually
black app/ cli/ tests/
ruff check app/ cli/ tests/
```

### 3. Running the Test Suite

We use `pytest` for unit and integration testing. All tests are located under the `tests/` directory.

Run the entire test suite locally:
```bash
# Run via Makefile automation
make test

# Or run manually
pytest tests/ -v
```

If you are modifying the local CLI scanner, run specific tests:
```bash
pytest tests/test_cli_patterns.py -v
pytest tests/test_cli_sync.py -v
pytest tests/test_cli_pdf.py -v
```

Refer to [test_cli_patterns.py](file:///home/Krishna-Singh/securelens-backend/tests/test_cli_patterns.py), [test_cli_sync.py](file:///home/Krishna-Singh/securelens-backend/tests/test_cli_sync.py), and [test_cli_pdf.py](file:///home/Krishna-Singh/securelens-backend/tests/test_cli_pdf.py) for examples of testing our offline scanner, sync clients, and PDF exporters.

Ensure all tests pass and write new tests covering any logic changes or new features you introduce.

---

## Pull Request Guidelines

To help maintainers review your PR efficiently:
* **Keep PRs focused.** Do not combine multiple unrelated changes into one pull request.
* **Provide context.** Write a clear title and description explaining what was changed and why.
* **Link your issues.** Reference any related issues (e.g., `Closes #123`) so they close automatically upon merge.
* **Stay updated.** Verify that your branch is rebased on top of the latest upstream `main` branch.
* **CI Validation:** Every PR triggers an automated workflow running our formatting and test suites. PRs cannot be merged until these checks pass.
