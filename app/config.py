import os
from pathlib import Path

from dotenv import load_dotenv

_ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(_ENV_PATH, override=True)


def _env(name: str, default: str = "") -> str:
    value = os.getenv(name)
    return default if value is None else value.strip()


def _env_number(name: str, default: float, cast):
    raw = _env(name)
    return cast(raw) if raw else default


OPENAI_API_KEY = _env("OPENAI_API_KEY")
OPENAI_API_BASE = _env("OPENAI_API_BASE", "https://openrouter.ai/api/v1")
MODEL_NAME = _env("MODEL_NAME", "gpt-3.5-turbo")
TEMPERATURE = _env_number("TEMPERATURE", 0.2, float)
MAX_TOKENS = int(_env_number("MAX_TOKENS", 4096, float))
