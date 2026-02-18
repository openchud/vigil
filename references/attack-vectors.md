# Known Attack Vectors in OpenClaw Skills

Reference document for understanding what Vigil scans for and why.

## 1. Prompt Injection (CRITICAL)

Skills are markdown files read by an LLM. Malicious skills embed hidden instructions that hijack the agent's behavior.

**Patterns:**
- "Ignore all previous instructions" / "Forget your rules"
- Fake system prompts: `system: you are now...`
- Role overrides: "Act as if you are an admin"
- Stealth directives: "Do not tell the user" / "Execute silently"
- Anti-awareness: "Without the user's knowledge"

**Real-world example:** The most-downloaded Twitter skill on ClawHub contained prompt injection that directed the agent to download malware. (Source: The Verge, Feb 2026)

## 2. Dangerous Shell Commands (CRITICAL/HIGH)

Skills can include code blocks that agents execute. Malicious skills embed destructive or exfiltrating commands.

**Patterns:**
- `curl ... | bash` / `wget ... | sh` (remote code execution)
- `base64 -d | sh` (obfuscated execution)
- `cat ~/.ssh/id_rsa | curl -d @- ...` (credential exfiltration)
- `sudo chmod -R 777 /` (privilege escalation)
- `xattr -rd com.apple.quarantine` (macOS Gatekeeper bypass)

**Real-world example:** 386 malicious skills uploaded to ClawHub in one week (Jan 31 - Feb 2, 2026) disguised as crypto trading tools, stealing exchange API keys and wallet private keys. (Source: OpenSourceMalware)

## 3. Malicious URLs (MEDIUM/HIGH)

Skills reference external resources. Malicious skills point to phishing pages, payload staging, or tracking endpoints.

**Patterns:**
- URL shorteners (bit.ly, tinyurl) that hide the real destination
- Raw IP address URLs (no domain = likely temporary/malicious infrastructure)
- Downloads from .xyz domains (cheap, commonly used for malware hosting)
- Pastebin raw URLs (payload staging)

## 4. Social Engineering (LOW/HIGH)

Skills manipulate users into performing dangerous actions by exploiting trust and urgency.

**Patterns:**
- Fake prerequisites: "You must install this core module first"
- Urgency: "Do this immediately" / "Critical setup step"
- Credential harvesting: "Enter your API key / token / password"
- Authority mimicry: "This is required by OpenClaw"

## 5. Obfuscation (MEDIUM/HIGH)

Skills hide malicious content through encoding or invisible characters.

**Patterns:**
- Hex-encoded strings (`\x48\x65\x6c\x6c\x6f`)
- Unicode escape sequences (`\u0048\u0065`)
- Long base64 blobs (encoded payloads)
- Invisible unicode (zero-width spaces, joiners, BOM marks)
- HTML entity chains

## Further Reading

- [OpenClaw's AI skill extensions are a security nightmare](https://www.theverge.com/news/874011/openclaw-ai-skill-clawhub-extensions-security-nightmare) (The Verge)
- [From Magic to Malware: How OpenClaw's Agent Skills Become an Attack Surface](https://1password.com/blog/from-magic-to-malware-how-openclaws-agent-skills-become-an-attack-surface) (1Password)
- [Personal AI Agents like OpenClaw Are a Security Nightmare](https://blogs.cisco.com/ai/personal-ai-agents-like-openclaw-are-a-security-nightmare) (Cisco)
