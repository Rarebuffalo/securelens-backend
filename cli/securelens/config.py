"""
Config Manager
==============
Reads and writes ~/.securelens/config.yaml.
Falls back to environment variables so the CLI works in CI/CD
without a config file.
"""

import os
import yaml
from pathlib import Path
from dataclasses import dataclass, field

CONFIG_DIR = Path.home() / ".securelens"
CONFIG_FILE = CONFIG_DIR / "config.yaml"


@dataclass
class CLIConfig:
    # AI backend
    default_model: str = "gemini/gemini-2.0-flash"
    api_key: str = ""

    # Scan behaviour
    output_format: str = "terminal"          # terminal | json | markdown | all
    max_files_to_scan: int = 20
    max_file_size_kb: int = 200
    scan_timeout: int = 10                   # seconds — for web scans

    # File exclusions (gitignore-style globs)
    ignore_patterns: list = field(default_factory=lambda: [
        "*.lock",
        "node_modules/**",
        ".git/**",
        "venv/**",
        ".venv/**",
        "__pycache__/**",
        "*.pyc",
        "dist/**",
        "build/**",
        ".next/**",
        "*.min.js",
        "*.min.css",
        "*.map",
    ])


def load_config() -> CLIConfig:
    """
    Load config from ~/.securelens/config.yaml,
    then overlay any env-var overrides.
    """
    cfg = CLIConfig()

    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            data = yaml.safe_load(f) or {}
        cfg.default_model = data.get("default_model", cfg.default_model)
        cfg.api_key = data.get("api_key", cfg.api_key)
        cfg.output_format = data.get("output_format", cfg.output_format)
        cfg.max_files_to_scan = data.get("max_files_to_scan", cfg.max_files_to_scan)
        cfg.max_file_size_kb = data.get("max_file_size_kb", cfg.max_file_size_kb)
        cfg.scan_timeout = data.get("scan_timeout", cfg.scan_timeout)
        cfg.ignore_patterns = data.get("ignore_patterns", cfg.ignore_patterns)

    # Env-var overrides (for CI/CD)
    cfg.api_key = (
        os.environ.get("SECURELENS_API_KEY")
        or os.environ.get("AI_API_KEY")
        or os.environ.get("GEMINI_API_KEY")
        or os.environ.get("OPENAI_API_KEY")
        or cfg.api_key
    )
    cfg.default_model = (
        os.environ.get("SECURELENS_MODEL")
        or os.environ.get("AI_MODEL")
        or cfg.default_model
    )

    return cfg


def save_config(cfg: CLIConfig) -> None:
    """Persist the config object to ~/.securelens/config.yaml."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    data = {
        "default_model": cfg.default_model,
        "api_key": cfg.api_key,
        "output_format": cfg.output_format,
        "max_files_to_scan": cfg.max_files_to_scan,
        "max_file_size_kb": cfg.max_file_size_kb,
        "scan_timeout": cfg.scan_timeout,
        "ignore_patterns": cfg.ignore_patterns,
    }
    with open(CONFIG_FILE, "w") as f:
        yaml.safe_dump(data, f, default_flow_style=False)


def config_exists() -> bool:
    return CONFIG_FILE.exists() and bool(load_config().api_key)
