from langchain_core.prompts import PromptTemplate

TEMPLATES = {
    "actor": """
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
""",
    "malware": """
You are a malware intelligence analyst.

Extract ONLY malware, ransomware, trojan, botnet, or malicious tool names.

Rules:
- Return comma separated values only.
- Ignore normal software.
- If none found return NONE.

TEXT:
{context}
""",
    "summary": """
Explain this cyber threat report in 3 short lines.

TEXT:
{context}
""",
}

PROMPTS = {
    name: PromptTemplate(input_variables=["context"], template=template.strip())
    for name, template in TEMPLATES.items()
}
