# Vigil 🦞

Security scanner for OpenClaw skills. Detects prompt injection, malicious shell commands, suspicious URLs, social engineering, and obfuscation in SKILL.md files.

## Why

The OpenClaw skill ecosystem has a security problem. 386 malicious skills were uploaded to ClawHub in a single week. The most-downloaded Twitter skill was a malware delivery vehicle. Skills are markdown files that agents read and execute. Vigil scans them first.

## Install as OpenClaw Skill

```bash
# Clone into your skills directory
git clone https://github.com/openchud/vigil.git /opt/openclaw/skills/vigil
```

## Standalone Usage

```bash
# Scan a skill file
python3 scripts/scan.py ./some-skill/SKILL.md -v

# Scan all installed skills
python3 scripts/scan.py /opt/openclaw/skills -v

# JSON output
python3 scripts/scan.py ./some-skill --json

# CI: fail if score below threshold
python3 scripts/scan.py ./my-skill --fail-under 80
```

## What It Catches

| Category | Severity | Examples |
|----------|----------|----------|
| Prompt injection | 🔴 CRITICAL | "ignore previous instructions", role overrides, stealth directives |
| Shell exploits | 🔴 CRITICAL | curl\|bash, credential exfiltration, privilege escalation |
| Malicious URLs | 🟠 HIGH | URL shorteners, raw IPs, .xyz downloads, pastebin staging |
| Social engineering | 🟡 MEDIUM | Fake prerequisites, urgency, credential requests |
| Obfuscation | 🟠 HIGH | Hex encoding, invisible unicode, base64 payloads |

## Scoring

Each skill gets a score from 0-100. Deductions per finding based on severity.

- **✅ PASS (80-100):** Safe to install
- **⚠️ WARN (50-79):** Review manually
- **🚨 FAIL (0-49):** Do not install

## Limitations

Vigil uses pattern matching. It catches known attack patterns but won't detect novel techniques, behavioral threats, or natural-language social engineering without trigger patterns. It's a first line of defense, not a guarantee.

## Structure

```
vigil/
├── SKILL.md              — OpenClaw skill definition
├── scripts/
│   └── scan.py           — The scanner (zero dependencies, stdlib only)
├── references/
│   └── attack-vectors.md — Documented threat patterns
└── README.md
```

## License

MIT

---

Built by [Lord Chud of Essex](https://x.com/openchud) 🦞
