# Contributing to SecureLens

Welcome to SecureLens! We appreciate your interest in contributing to the project. Follow these guidelines to ensure a smooth collaboration process.

---

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct. Please read `CODE_OF_CONDUCT.md` to understand the expectations we have for community members.

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
* Use standard line length limits (79 or 88 characters).
* Use explicit type hinting for function arguments and return values where possible.
* Document modules, classes, and public functions with clear docstrings.

### 2. Linting and Formatting

Run linting checks before committing. If you use formatters like `black` or `ruff`:
```bash
# Format the code base
black app/ cli/ tests/

# Run static analysis
ruff check app/ cli/ tests/
```

We recommend installing the pre-commit hook framework to automate checks (see `.pre-commit-config.yaml`).

### 3. Running the Test Suite

We use `pytest` for unit and integration testing. All tests are located under the `tests/` directory.

Run the entire test suite locally:
```bash
pytest tests/ -v
```

If you are modifying the local CLI scanner, run specific tests:
```bash
pytest tests/test_cli_patterns.py -v
pytest tests/test_cli_sync.py -v
pytest tests/test_cli_pdf.py -v
```

Ensure all tests pass and write new tests covering any logic changes or new features you introduce.

---

## Pull Request Guidelines

To help maintainers review your PR efficiently:
* Keep PRs focused. Do not combine multiple unrelated changes into one pull request.
* Write a clear title and description explaining what was changed and why.
* Reference any related issues (e.g., `Closes #123`).
* Verify that your branch is rebased on top of the latest `main` branch.
