# Vigil 🦞

OpenClaw skill security scanner. Detects prompt injection, malicious URLs, suspicious shell commands, and social engineering patterns in SKILL.md files.

## Why

The OpenClaw skill ecosystem has a security problem. 386 malicious skills were uploaded to ClawHub in one week. The top-downloaded Twitter skill was literally a malware delivery vehicle. Skills are markdown files that can contain anything, and agents execute what they read.

Vigil scans skills before you install them.

## What it detects

- **Prompt injection** — hidden instructions, role overrides, system prompt manipulation
- **Malicious URLs** — known bad domains, URL shorteners, obfuscated links
- **Dangerous shell commands** — curl|bash pipes, encoded payloads, privilege escalation
- **Social engineering** — fake prerequisites, urgency triggers, credential requests
- **Obfuscation** — base64 encoded commands, hex escapes, unicode tricks

## Usage

```bash
# Scan a local skill
vigil scan ./my-skill/SKILL.md

# Scan a ClawHub skill before installing
vigil scan --clawhub skill-name

# Scan all installed skills
vigil audit
```

## License

MIT
