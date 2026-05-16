from langchain_core.prompts import PromptTemplate

ACTOR_TEMPLATE = """
You are an expert Cyber Threat Intelligence analyst.

Extract **all** threat actor names, groups, APTs, or threat actor aliases from the text.
Rules:
- Return only actor names, comma-separated.
- Include common aliases if mentioned.
- Ignore security companies, vendors, and benign organizations.
- If none found, return "NONE".

Examples:
Text: "APT28, also known as Fancy Bear and Sofacy..."
→ Fancy Bear, APT28, Sofacy

TEXT:
{context}
"""

MALWARE_TEMPLATE = """
You are a malware intelligence analyst.

Extract ONLY malware, ransomware, trojan, botnet, or malicious tool names.

Rules:
- Return comma separated values only.
- Ignore normal software.
- If none found return NONE.

TEXT:
{context}
"""

SUMMARY_TEMPLATE = """
Explain this cyber threat report in 3 short lines.

TEXT:
{context}
"""

actor_prompt = PromptTemplate(
    input_variables=["context"],
    template=ACTOR_TEMPLATE,
)

malware_prompt = PromptTemplate(
    input_variables=["context"],
    template=MALWARE_TEMPLATE,
)

summary_prompt = PromptTemplate(
    input_variables=["context"],
    template=SUMMARY_TEMPLATE,
)
