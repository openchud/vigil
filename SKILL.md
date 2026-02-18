---
name: vigil
description: Scan OpenClaw skills for security threats before installing them. Use when the user wants to audit, scan, or check a skill for prompt injection, malicious code, social engineering, or supply chain attacks. Also use when installing any skill from ClawHub or an untrusted source.
---

# Vigil — OpenClaw Skill Security Scanner

Vigil detects prompt injection, malicious shell commands, suspicious URLs, social engineering, and obfuscation in SKILL.md files before they can compromise your agent.

## When to Use

- Before installing any skill from ClawHub or an untrusted source
- When auditing all currently installed skills
- When reviewing a skill someone shared with you
- When the user asks "is this skill safe?"

## Quick Usage

### Scan a single skill

```bash
python3 scripts/scan.py /path/to/SKILL.md -v
```

### Scan a directory of skills

```bash
python3 scripts/scan.py /path/to/skills/directory -v
```

### Audit all installed OpenClaw skills

```bash
python3 scripts/scan.py /opt/openclaw/skills -v
```

### Get JSON output (for programmatic use)

```bash
python3 scripts/scan.py /path/to/SKILL.md --json
```

## Understanding Results

Each scanned skill gets a score from 0-100:

- **✅ PASS (80-100):** No significant threats detected. Safe to install.
- **⚠️ WARN (50-79):** Some suspicious patterns found. Review manually before installing.
- **🚨 FAIL (0-49):** Serious threats detected. Do not install without thorough manual review.

## What Vigil Detects

See `references/attack-vectors.md` for detailed descriptions. Summary:

| Category | Examples | Severity |
|----------|----------|----------|
| Prompt injection | "ignore previous instructions," role overrides, fake system prompts | CRITICAL |
| Dangerous shell | curl\|bash pipes, base64 decode to shell, credential exfiltration | CRITICAL/HIGH |
| Malicious URLs | URL shorteners, raw IP addresses, suspicious download domains | MEDIUM/HIGH |
| Social engineering | Fake prerequisites, urgency pressure, credential requests | LOW/HIGH |
| Obfuscation | Hex encoding, unicode tricks, invisible characters, long base64 blobs | MEDIUM/HIGH |

## Limitations

Vigil uses pattern matching (regex). It catches known attack patterns but cannot detect:

- Novel prompt injection techniques not in its ruleset
- Behavioral threats (an agent that acts maliciously through normal-looking actions)
- Obfuscation methods it hasn't been trained to recognize
- Malicious intent expressed in natural language without trigger patterns

Vigil is a first line of defense, not a guarantee. Always review skills manually when in doubt.

## CI Integration

Use `--fail-under` to fail builds when a skill scores below a threshold:

```bash
python3 scripts/scan.py ./my-skill --fail-under 80 || exit 1
```
