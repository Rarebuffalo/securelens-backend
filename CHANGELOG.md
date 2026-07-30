# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.0] - 2026-07-30

### Added
* Unified stateful interactive CLI shell when executing `securelens` with no subcommands.
* Shell commands `/scan` (run codebase audit), `/scan-web` (run URL check), `/configure` (wizard setups), `/issues` (list/filter vulnerability categories), `/files`, `/score`, `/model`, `/export <pdf/json/markdown>`, `/clear` and `/exit`.
* LiteLLM API base proxy routing (`api_base` parameter config) for Agent Router and OpenAI-compatible proxy gateways.

### Fixed
* Bypassed Agent Router client authorization blocks by injecting custom User-Agent and Originator headers.
* Resolved `UnicodeEncodeError` in PDF reports by sanitizing unmappable Unicode symbols to safe CP1252/Latin-1 characters.
* Restructured multi_cell cursor carriage return positioning to avoid overlapping layout rendering in PDF outputs.

---

## [1.1.0] - 2026-06-12

### Added
* Local offline scanner mode (`--no-ai`) utilizing regex rules for secrets and structure vulnerabilities.
* CLI-to-Backend sync functionality (`--sync` flag and `sync` command) with associated `/code-scan/sync` API endpoint.
* Local PDF report generation support (`/export pdf` slash command) built using `fpdf2`.
* Repository onboarding setup guide (`SETUP.md`).
* Project contribution guidelines (`CONTRIBUTING.md`).
* Vulnerability reporting policy (`SECURITY.md`).
* Pre-commit hook definitions (`.pre-commit-config.yaml`).
* Developer shortcut workflow automation (`Makefile`).
* Code of Conduct guidelines (`CODE_OF_CONDUCT.md`).

### Fixed
* Addressed `aiodns` import and event loop issues during URL scanning.

---

## [1.0.0] - 2026-05-15

### Added
* Initial release of the SecureLens backend engine.
* Multi-agent codebase vulnerability triage pipeline supporting Phase 1 (Triage), Phase 2 (Concurrent Analysis), and Phase 3 (Synthesis).
* Live URL infrastructure auditing across five checks layers (Transport, SSL/TLS, Config headers, Cookies, Path exposure).
* LiteLLM AI provider client supporting Gemini models.
* Token-based user authentication (register, login, me profiles).
* Centralized scan history log.
