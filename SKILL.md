---
name: vigil
description: Scan OpenClaw skills for security threats before installing them. Use when evaluating, auditing, or installing skills from ClawHub or third-party sources. Detects prompt injection, malicious shell commands, credential theft, social engineering, and obfuscation.
---

# Vigil — OpenClaw Skill Security Scanner 🦞

## When to Use

- Before installing any skill from ClawHub or a third party
- When auditing currently installed skills
- When reviewing a SKILL.md file for security issues
- When a user asks "is this skill safe?"

## Quick Start

```bash
# Scan a single skill file
python3 scripts/vigil.py /path/to/SKILL.md -v

# Scan a directory of skills
python3 scripts/vigil.py /opt/openclaw/skills/

# Audit all installed skills
python3 scripts/vigil.py --audit

# JSON output for programmatic use
python3 scripts/vigil.py /path/to/SKILL.md --json
```

## How It Works

Vigil performs static analysis on SKILL.md files, scanning for five categories of threats:

1. **Prompt Injection** — Hidden instructions that override agent behavior (role overrides, "ignore previous instructions", stealth commands)
2. **Dangerous Shell Commands** — curl|bash pipes, base64-encoded payloads, privilege escalation, credential file access, data exfiltration
3. **Malicious URLs** — URL shorteners, raw IP addresses, suspicious download domains, pastebin staging
4. **Social Engineering** — Fake prerequisites, urgency/pressure tactics, credential requests, terminal paste instructions
5. **Obfuscation** — Hex-encoded strings, unicode escapes, long base64 payloads, invisible characters, HTML entity chains

Each finding has a severity (CRITICAL, HIGH, MEDIUM, LOW, INFO) and reduces the skill's score from 100. Skills scoring below 50 are flagged as FAIL.

## Interpreting Results

- **PASS (80-100):** Safe to install. Minor findings are informational.
- **WARN (50-79):** Review findings manually before installing.
- **FAIL (0-49):** Do not install. Contains likely malicious content.

## Known Limitations

- Static analysis only. Cannot detect behavioral threats (an agent that acts maliciously through normal-looking actions).
- May flag legitimate urgency language ("immediately", "required") as low-severity findings. Review context.
- Does not execute or sandbox skills. Does not check referenced URLs for actual malware.

## References

See `references/attack-patterns.md` for detailed documentation on known ClawHub attack vectors and real-world incidents.
