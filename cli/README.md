# SecureLens AI — CLI

> Scan codebases and URLs for security vulnerabilities, right in your terminal.  
> Powered by AI. Works like Gemini CLI.

---

## Install

```bash
# From the project root
chmod +x cli/install.sh
./cli/install.sh

# Then activate the venv
source venv/bin/activate
```

Or manually:
```bash
pip install click rich litellm httpx pyyaml pathspec questionary
pip install -e cli/ --no-build-isolation
```

---

## Quick Start

```bash
# 1. Set up your API key
securelens configure

# 2. Scan your current project
securelens scan .

# 3. Scan a URL
securelens web https://example.com
```

---

## Commands

### `securelens configure`
Interactive setup wizard. Saves config to `~/.securelens/config.yaml`.
```
securelens configure
```

### `securelens scan <path>`
Scan a local codebase. The AI triages files, analyzes them for OWASP vulnerabilities,
and gives you an executive summary. Then you drop into a Q&A chat.

```bash
securelens scan .                              # scan current directory
securelens scan ./my-project                   # scan a specific folder
securelens scan . --output markdown            # save report as .md file
securelens scan . --model gpt-4o               # use a different AI model
securelens scan . --max-files 30               # analyze more files
securelens scan . --no-ai                      # pattern-based only (no AI, fast)
securelens scan . --ci --fail-on high          # CI mode — exits with code 1
```

### `securelens web <url>`
Scan a URL for HTTP security issues (HTTPS, headers, cookies, exposed paths, SSL).

```bash
securelens web https://example.com
securelens web https://my-app.com --output markdown
securelens web https://api.example.com --no-ai   # skip AI summary
```

### `securelens version`
Print version and config info.

---

## Interactive REPL

After every scan, you drop into an interactive Q&A session (like Gemini CLI):

```
💬 Ask a follow-up (or press Ctrl+C to exit)
Type /help for available commands

> What's the most critical issue?
> How do I fix the SQL injection in auth.py?
> Show me all high severity issues
> /export markdown
> /files
> /model gpt-4o-mini
> /exit
```

### Slash Commands

| Command | Description |
|---|---|
| `/help` | Show available commands |
| `/files` | List files that were analyzed |
| `/score` | Show the security score |
| `/export markdown` | Save report as Markdown |
| `/export json` | Save report as JSON |
| `/model <name>` | Switch AI model mid-session |
| `/clear` | Clear the terminal |
| `/exit` | Exit the REPL |

---

## Config File

`~/.securelens/config.yaml`:

```yaml
default_model: gemini/gemini-2.0-flash
api_key: YOUR_API_KEY
output_format: terminal    # terminal | json | markdown | all
max_files_to_scan: 20
max_file_size_kb: 200
scan_timeout: 10
ignore_patterns:
  - "*.lock"
  - "node_modules/**"
  - ".git/**"
  - "venv/**"
```

### Environment Variable Overrides

```bash
export SECURELENS_API_KEY=your-key
export SECURELENS_MODEL=gpt-4o-mini
```

---

## Supported AI Providers

| Provider | Model string |
|---|---|
| Google Gemini (default) | `gemini/gemini-2.0-flash` |
| OpenAI | `gpt-4o-mini`, `gpt-4o` |
| Anthropic | `claude-3-5-haiku-20241022` |
| OpenRouter | `openrouter/google/gemini-flash` |
| Ollama (local, no key) | `ollama/llama3.1` |

---

## CI/CD Usage

```bash
# GitHub Actions — fail the build if any high or critical issues found
securelens scan . --ci --fail-on high

# Pre-commit hook
# Add to .pre-commit-config.yaml:
# - id: securelens
#   name: SecureLens Security Scan
#   entry: securelens scan
#   args: [".", "--ci", "--fail-on", "critical"]
#   language: python
#   pass_filenames: false
```

---

## Output Formats

| Format | Flag | Description |
|---|---|---|
| Terminal (default) | `--output terminal` | Rich colored display |
| Markdown | `--output markdown` | Saves `securelens-report-{timestamp}.md` |
| JSON | `--output json` | Machine-readable, good for CI |
| All | `--output all` | Terminal display + saves markdown |
