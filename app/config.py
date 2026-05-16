import os
from pathlib import Path

from dotenv import load_dotenv

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_ENV_PATH = _PROJECT_ROOT / ".env"

# .env in project root wins over empty shell variables
load_dotenv(_ENV_PATH, override=True)


def _env(name: str, default: str | None = None) -> str:
    value = os.getenv(name)
    if value is None:
        return default if default is not None else ""
    return value.strip()


def _env_float(name: str, default: float) -> float:
    raw = _env(name)
    if not raw:
        return default
    return float(raw)


def _env_int(name: str, default: int) -> int:
    raw = _env(name)
    if not raw:
        return default
    return int(raw)


OPENAI_API_KEY = _env("OPENAI_API_KEY")
OPENAI_API_BASE = _env("OPENAI_API_BASE", "https://openrouter.ai/api/v1")
MODEL_NAME = _env("MODEL_NAME", "gpt-3.5-turbo")
TEMPERATURE = _env_float("TEMPERATURE", 0.2)
MAX_TOKENS = _env_int("MAX_TOKENS", 4096)
