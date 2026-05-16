from typing import TypedDict

from langchain_openai import ChatOpenAI
from langchain_core.output_parsers import StrOutputParser

from .config import MODEL_NAME, OPENAI_API_BASE, OPENAI_API_KEY, TEMPERATURE
from .prompts import PROMPTS

_llm = ChatOpenAI(
    model=MODEL_NAME,
    temperature=TEMPERATURE,
    api_key=OPENAI_API_KEY,  # pyright: ignore[reportArgumentType]
    base_url=OPENAI_API_BASE,  # pyright: ignore[reportCallIssue]
)
_parser = StrOutputParser()

CHAINS = {name: prompt | _llm | _parser for name, prompt in PROMPTS.items()}

LLM_CONTEXT_LIMIT = 4000
SUMMARY_CONTEXT_LIMIT = 3000


class LlmResult(TypedDict):
    actors: list[str]
    malware: list[str]
    summary: str


def clean_llm_output(output: str) -> list[str]:
    if not output or output.strip().upper() == "NONE":
        return []
    return sorted({x.strip() for x in output.split(",") if x.strip()})


def run_llm_analysis(src: str) -> LlmResult:
    ctx = {"context": src[:LLM_CONTEXT_LIMIT]}
    summary_ctx = {"context": src[:SUMMARY_CONTEXT_LIMIT]}

    return {
        "actors": clean_llm_output(CHAINS["actor"].invoke(ctx)),
        "malware": clean_llm_output(CHAINS["malware"].invoke(ctx)),
        "summary": CHAINS["summary"].invoke(summary_ctx),
    }
