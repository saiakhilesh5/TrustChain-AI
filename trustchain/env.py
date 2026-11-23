"""Minimal .env loader: populates os.environ for keys that are not already set.

Keeps secrets out of git (.env is gitignored); only an .env.example template
with placeholder values is committed.
"""

import os
from pathlib import Path


def load_env(path: str | Path | None = None) -> Path:
    env_path = Path(path) if path else Path.cwd() / ".env"
    if not env_path.exists():
        return env_path
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value
    return env_path
