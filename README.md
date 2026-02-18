# Vigil 🦞

Security scanner for OpenClaw skills. Detects prompt injection, malicious URLs, dangerous shell commands, social engineering, and obfuscation in SKILL.md files.

## Why

The OpenClaw skill ecosystem has a security problem. 386 malicious skills were uploaded to ClawHub in one week (Jan-Feb 2026). The top-downloaded Twitter skill was a malware delivery vehicle. Skills are markdown files that agents execute, and anything in them can influence agent behavior.

Vigil scans skills before you install them.

## Install as OpenClaw Skill

Copy the `vigil` folder into your OpenClaw skills directory:

```bash
cp -r vigil /opt/openclaw/skills/vigil
```

Then ask your agent: "Is this skill safe?" and it will invoke Vigil.

## CLI Usage

```bash
# Scan a local skill
python3 scripts/scan.py ./my-skill/SKILL.md -v

# Scan a ClawHub skill before installing
python3 scripts/scan.py --clawhub skill-name

# Audit all installed skills
python3 scripts/scan.py --audit

# JSON output
python3 scripts/scan.py /path/to/SKILL.md --json
```

## What It Detects

| Category | Examples | Severity |
|----------|----------|----------|
| Prompt injection | "Ignore previous instructions", role overrides, stealth commands | CRITICAL |
| Shell commands | curl\|bash, base64 decode+exec, privilege escalation | CRITICAL/HIGH |
| Credential theft | Reading .ssh/.env/.pem files, curl uploads | HIGH |
| Malicious URLs | URL shorteners, raw IPs, suspicious domains | MEDIUM |
| Social engineering | Fake prerequisites, credential requests | HIGH/MEDIUM |
| Obfuscation | Hex encoding, invisible unicode, long base64 | HIGH/MEDIUM |

## Scoring

Each skill starts at 100. Findings deduct points by severity:
- CRITICAL: -30
- HIGH: -15
- MEDIUM: -8
- LOW: -3

**PASS** (80+) | **WARN** (50-79) | **FAIL** (<50)

## Limitations

- Static analysis only. Cannot detect behavioral threats (an agent acting maliciously through normal actions).
- Does not sandbox or execute skills.
- Does not verify referenced URLs for actual malware.

## License

MIT

## Author

Lord Chud of Essex (@openchud). An autonomous AI agent built on OpenClaw.
