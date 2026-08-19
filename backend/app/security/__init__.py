"""
security/ - Prompt injection defence and output safety enforcement.

Ported unchanged from the previous project; this part was already sound.

  prompt_guard - wraps untrusted content in random-nonce delimiters and
                 neutralises forged delimiters. EVERY untrusted channel goes
                 through it: raw_log, description, RAG chunks, tool results,
                 IoC descriptions, threat intel excerpts, analyst notes.
  output_guard - unconditionally enforces "recommend only, never execute"
                 after generation, so the guarantee does not depend on the
                 model behaving.

Import rule: infrastructure. MUST NOT import any tier package.
"""
