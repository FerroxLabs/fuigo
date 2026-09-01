#!/usr/bin/env python3
"""Regenerate crates/codegen/fuigo-agent/src/prompt/prompt_encrypted.rs.

The prompt templates ship XOR-obfuscated so they are not obvious plaintext in
`strings` output. This is obfuscation, not security -- the seeds are right here
in the repo, and the Rust side says so too.

WHY THIS FILE EXISTS AGAIN
--------------------------
It is referenced by `prompt/template.rs` (both the module doc and the panic
message that tells you to run it) but was NOT in xAI's public snapshot -- the
same sync that stripped the internal test helpers and `docs/internal/`.

Its absence was not cosmetic. The rebrand rewrote the plaintext templates but
nothing could regenerate the encrypted blob, and the blob is what actually runs:
`base_template()` decrypts `BASE_PROMPT_ENC`, never reading templates/*.md. So
Fuigo shipped a system prompt that still opened with "You are ... released by
xAI" and "You are a Grok Build subagent".

A text scan for brand residue cannot find that -- the tokens are XOR'd bytes.
The only thing that catches it is decrypting and looking, which is what
`test_encrypted_templates_not_stale` does. Keep that test.

Usage:  python3 scripts/encrypt_templates.py
"""

from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TEMPLATES = REPO / "crates/codegen/fuigo-agent/templates"
OUT = REPO / "crates/codegen/fuigo-agent/src/prompt/prompt_encrypted.rs"

# (constant name, template filename, seed). Order and seeds must match
# PROMPT_SEEDS and the decrypt() calls in prompt/template.rs.
TEMPLATE_SPECS = [
    ("BASE_PROMPT_ENC", "prompt.md", 0x5A),
    ("CODEX_PROMPT_ENC", "apply_patch_prompt.md", 0x7B),
    ("SUBAGENT_PROMPT_ENC", "subagent_prompt.md", 0x3D),
]


def xor_encrypt(data: bytes, seed: int) -> bytes:
    """Mirror of `decrypt` in prompt/template.rs.

    Position-dependent key: byte i is XORed with (seed + i) mod 256. XOR is its
    own inverse, so the same function encrypts and decrypts.
    """
    return bytes(b ^ ((seed + i) & 0xFF) for i, b in enumerate(data))


def main() -> None:
    lines = [
        "// Auto-generated -- do not edit.",
        "// Regenerate: python3 scripts/encrypt_templates.py",
        "// XOR-encrypted prompt templates (key = position-dependent seed).",
        "",
    ]

    seeds = []
    for const_name, filename, seed in TEMPLATE_SPECS:
        raw = (TEMPLATES / filename).read_bytes()
        encrypted = xor_encrypt(raw, seed)
        body = ", ".join(str(b) for b in encrypted)
        lines.append("#[rustfmt::skip]")
        lines.append(f"pub(crate) const {const_name}: &[u8] = &[{body}];")
        lines.append("")
        seeds.append(seed)
        print(f"{filename}: {len(raw)} bytes -> {const_name}")

    seed_list = ", ".join(f"0x{s:02X}" for s in seeds)
    lines.append(
        f"pub(crate) const PROMPT_SEEDS: [u8; {len(seeds)}] = [{seed_list}];"
    )
    lines.append("")

    OUT.write_text("\n".join(lines))
    print(f"wrote {OUT.relative_to(REPO)}")


if __name__ == "__main__":
    main()
