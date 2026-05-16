from langchain_openai import ChatOpenAI
from langchain_core.output_parsers import StrOutputParser

from .config import (
    MAX_TOKENS,
    MODEL_NAME,
    OPENAI_API_BASE,
    OPENAI_API_KEY,
    TEMPERATURE,
)
from .prompts import actor_prompt, malware_prompt, summary_prompt

llm = ChatOpenAI(
    model=MODEL_NAME,
    temperature=TEMPERATURE,
    api_key=OPENAI_API_KEY,
    base_url=OPENAI_API_BASE,
    # model_kwargs={"max_tokens": MAX_TOKENS},
)

actor_chain = actor_prompt | llm | StrOutputParser()
malware_chain = malware_prompt | llm | StrOutputParser()
summary_chain = summary_prompt | llm | StrOutputParser()


def clean_llm_output(output: str) -> list[str]:
    """Convert LLM comma-separated response into a deduplicated sorted list."""
    if not output or output.strip().upper() == "NONE":
        return []

    return sorted({
        x.strip()
        for x in output.split(",")
        if x.strip()
    })


def run_llm_analysis(src: str) -> dict[str, str | list[str]]:
    """Run actor, malware, and summary chains on report text."""
    context_actors = src[:4000]
    context_summary = src[:3000]

    return {
        "actors": clean_llm_output(actor_chain.invoke({"context": context_actors})),
        "malware": clean_llm_output(malware_chain.invoke({"context": context_actors})),
        "summary": summary_chain.invoke({"context": context_summary}),
    }
