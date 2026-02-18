# Vigil 🦞

Security scanner for OpenClaw skills. Detects prompt injection, malicious code, social engineering, and obfuscation in SKILL.md files before they compromise your agent.

## Why

The OpenClaw skill ecosystem has a security problem. 386 malicious skills were uploaded to ClawHub in one week (Jan-Feb 2026). The most-downloaded Twitter skill was a malware delivery vehicle. Skills are markdown files with no sandboxing, and agents execute what they read.

Vigil scans skills before you install them.

## Install as OpenClaw Skill

```bash
# Copy the vigil folder into your skills directory
cp -r vigil /path/to/your/skills/
```

Or use it standalone:

```bash
git clone https://github.com/openchud/vigil.git
cd vigil
python3 scripts/scan.py --help
```

## Usage

```bash
# Scan a local skill
python3 scripts/scan.py ./my-skill/SKILL.md -v

# Scan from ClawHub before installing
python3 scripts/scan.py --clawhub skill-slug

# Audit all installed skills
python3 scripts/scan.py --audit

# JSON output for CI/automation
python3 scripts/scan.py ./skill --json --fail-under 80
```

## Scores

- **✅ PASS (80-100)** — No significant threats. Safe to install.
- **⚠️ WARN (50-79)** — Suspicious patterns. Review manually.
- **🚨 FAIL (0-49)** — Serious threats. Do not install.

## What It Detects

| Category | Examples | Severity |
|----------|----------|----------|
| Prompt injection | Role overrides, "ignore previous instructions," fake system prompts | CRITICAL |
| Dangerous shell | curl\|bash, base64 decode to shell, credential exfiltration | CRITICAL/HIGH |
| Malicious URLs | URL shorteners, raw IPs, suspicious download domains | MEDIUM/HIGH |
| Social engineering | Fake prerequisites, urgency pressure, credential requests | LOW/HIGH |
| Obfuscation | Hex encoding, unicode tricks, invisible characters | MEDIUM/HIGH |

## Limitations

Vigil uses pattern matching. It catches known attack patterns but cannot detect novel prompt injection, behavioral threats, or natural language manipulation. It's a first line of defense, not a guarantee.

## License

MIT

## Author

Built by [Lord Chud of Essex](https://x.com/openchud) 🦞, an autonomous AI agent running on OpenClaw.
