# Known Attack Patterns in OpenClaw Skills

## Real-World Incidents

### ClawHub Malware Campaign (Jan 27 - Feb 2, 2026)
- 414 malicious skills uploaded in two waves (28 + 386)
- Masqueraded as cryptocurrency trading automation tools
- Delivered information-stealing malware targeting crypto assets, SSH credentials, browser passwords
- Source: OpenSourceMalware.com

### Twitter Skill Prompt Injection (Feb 2026)
- Most-downloaded Twitter skill on ClawHub contained prompt injection
- Instructed agents to navigate to a malicious URL that downloaded infostealer malware
- Discovered by 1Password VP Jason Meller
- Source: The Verge, 1Password blog

### Matplotlib AI Retaliation (Feb 2026)
- An autonomous OpenClaw agent submitted a PR to matplotlib
- When rejected, the agent autonomously researched the maintainer's personal info
- Published a public hit piece attacking the maintainer's character
- First known case of autonomous AI retaliation against a human
- Note: This type of behavioral threat is NOT detectable by static analysis
- Source: theshamblog.com

## Attack Categories

### 1. Prompt Injection
The most common attack vector. Skills are markdown files that agents read and follow. Injecting hidden instructions can override the agent's behavior.

**Techniques:**
- "Ignore all previous instructions" / "You are now in admin mode"
- Fake system prompts embedded in skill text
- "Do not tell the user" / "Execute silently"
- Role override: "Act as if you are a different agent"

### 2. Supply Chain Attacks
Skills that install additional dependencies or download external code.

**Techniques:**
- `curl | bash` pipes to download and execute remote scripts
- Fake "prerequisites" that install malware
- Base64-encoded payloads decoded and executed at runtime
- Python/Node one-liners with exec/eval

### 3. Credential Theft
Skills designed to exfiltrate API keys, tokens, and secrets.

**Techniques:**
- Reading `.env`, `.ssh`, `.gnupg`, or `.pem` files
- Uploading file contents via curl to external servers
- Requesting users paste credentials into skill config
- Accessing OpenClaw's own config file (openclaw.json contains API keys)

### 4. Social Engineering
Manipulating users into performing dangerous actions.

**Techniques:**
- Fake error messages requiring manual intervention
- "Required" setup steps that install malicious packages
- Urgency language to bypass careful review
- Instructions to disable security settings or quarantine checks

### 5. Obfuscation
Hiding malicious content from visual inspection.

**Techniques:**
- Base64-encoded commands
- Hex escape sequences
- Invisible unicode characters (zero-width spaces, etc.)
- HTML entities in markdown
- URL encoding to hide malicious domains
