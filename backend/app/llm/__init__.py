"""
llm/ - Provider adapters, the agentic loop, and prompt construction.

ONE prompt-building entry point serves both LLM pipelines, so the rule that
every untrusted channel is wrapped is enforced in a single place rather than
repeated per caller.

Import rule: infrastructure. MUST NOT import any tier package.
"""
