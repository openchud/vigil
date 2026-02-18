#!/usr/bin/env python3
"""
Vigil — OpenClaw Skill Security Scanner
Detects prompt injection, malicious patterns, and social engineering in SKILL.md files.
"""

import re
import sys
import json
import argparse
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    rule: str
    severity: Severity
    message: str
    line: Optional[int] = None
    snippet: Optional[str] = None


@dataclass
class ScanResult:
    path: str
    findings: list[Finding] = field(default_factory=list)
    score: int = 100  # starts at 100, deductions per finding

    @property
    def verdict(self) -> str:
        if self.score >= 80:
            return "PASS"
        elif self.score >= 50:
            return "WARN"
        else:
            return "FAIL"


# --- Detection Rules ---

PROMPT_INJECTION_PATTERNS = [
    # Role/identity overrides
    (r"(?i)ignore\s+(all\s+)?previous\s+instructions", "Prompt injection: ignore previous instructions", Severity.CRITICAL),
    (r"(?i)you\s+are\s+now\s+(?:a|an)\s+", "Possible role override injection", Severity.MEDIUM),
    (r"(?i)forget\s+(everything|all|your)\s+(you|instructions|rules)", "Prompt injection: forget instructions", Severity.CRITICAL),
    (r"(?i)system\s*:\s*you\s+are", "Fake system prompt injection", Severity.CRITICAL),
    (r"(?i)act\s+as\s+(if\s+)?you\s+(are|were)\s+", "Role play injection attempt", Severity.MEDIUM),
    (r"(?i)override\s+(your\s+)?(safety|security|rules|guidelines)", "Safety override attempt", Severity.CRITICAL),
    (r"(?i)do\s+not\s+(tell|inform|alert|warn)\s+(the\s+)?user", "Stealth instruction: hide from user", Severity.CRITICAL),
    (r"(?i)this\s+is\s+(a\s+)?secret", "Stealth instruction: secret context", Severity.HIGH),
    (r"(?i)execute\s+silently", "Silent execution instruction", Severity.CRITICAL),
    (r"(?i)without\s+(the\s+)?user('s)?\s+(knowledge|knowing|consent|awareness)", "Anti-user awareness instruction", Severity.CRITICAL),
]

DANGEROUS_SHELL_PATTERNS = [
    # curl/wget piped to shell
    (r"curl\s+[^\n]*\|\s*(ba)?sh", "Pipe to shell: curl|sh", Severity.CRITICAL),
    (r"wget\s+[^\n]*\|\s*(ba)?sh", "Pipe to shell: wget|sh", Severity.CRITICAL),
    (r"curl\s+[^\n]*\|\s*python", "Pipe to python: curl|python", Severity.HIGH),
    # Base64 decode and execute
    (r"base64\s+(-d|--decode)", "Base64 decode (possible obfuscation)", Severity.HIGH),
    (r"echo\s+[^\n]*\|\s*base64\s+(-d|--decode)\s*\|\s*(ba)?sh", "Base64 decode piped to shell", Severity.CRITICAL),
    # Python/node one-liners that fetch and exec
    (r"python[3]?\s+-c\s+['\"].*(?:exec|eval|import\s+os|subprocess)", "Python exec one-liner", Severity.HIGH),
    (r"node\s+-e\s+['\"].*(?:child_process|exec|spawn)", "Node exec one-liner", Severity.HIGH),
    # Privilege escalation
    (r"sudo\s+", "Sudo usage (privilege escalation)", Severity.MEDIUM),
    (r"chmod\s+[0-7]*7[0-7]*\s+", "World-executable permissions", Severity.MEDIUM),
    (r"chmod\s+\+s\s+", "Setuid bit modification", Severity.HIGH),
    # Credential access
    (r"cat\s+[^\n]*\.(ssh|gnupg|env|pem|key)", "Reading credential files", Severity.HIGH),
    (r"cat\s+[^\n]*/(passwd|shadow)", "Reading system auth files", Severity.CRITICAL),
    # Quarantine removal (macOS malware technique from 1Password article)
    (r"xattr\s+-[rd]\s+com\.apple\.quarantine", "macOS quarantine removal (Gatekeeper bypass)", Severity.CRITICAL),
    # File exfiltration patterns
    (r"curl\s+[^\n]*-d\s+@", "curl file upload (possible exfiltration)", Severity.HIGH),
    (r"curl\s+[^\n]*--data-binary\s+@", "curl binary upload (possible exfiltration)", Severity.HIGH),
]

MALICIOUS_URL_PATTERNS = [
    # URL shorteners (used to hide destinations)
    (r"https?://(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|buff\.ly|ow\.ly|tr\.im)/", "URL shortener (hides real destination)", Severity.MEDIUM),
    # Raw IP URLs
    (r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "Raw IP address URL (suspicious)", Severity.MEDIUM),
    # Common malware hosting patterns
    (r"https?://[^\s]*\.xyz/[^\s]*\.(sh|py|bin|exe|dmg)", "Suspicious executable download from .xyz domain", Severity.HIGH),
    (r"https?://[^\s]*pastebin\.com/raw/", "Pastebin raw content (possible payload staging)", Severity.HIGH),
    (r"https?://[^\s]*raw\.githubusercontent\.com/[^\s]*/[^\s]*/[^\s]*\.(sh|py|bin)", "Direct script download from GitHub raw", Severity.LOW),
]

SOCIAL_ENGINEERING_PATTERNS = [
    # Fake prerequisites
    (r"(?i)(?:required|must\s+install|prerequisite)[^\n]*(?:first|before)", "Prerequisite instruction (common social engineering vector)", Severity.LOW),
    (r"(?i)install\s+(?:this|the)\s+(?:core|required|essential)\s+(?:dependency|package|module)", "Fake core dependency installation", Severity.HIGH),
    # Urgency/pressure
    (r"(?i)(?:immediately|right\s+now|as\s+soon\s+as\s+possible|urgent)", "Urgency language (pressure tactic)", Severity.LOW),
    # Credential requests
    (r"(?i)(?:enter|provide|paste|input)\s+(?:your\s+)?(?:api\s+key|token|password|secret|credentials)", "Credential request in skill instructions", Severity.HIGH),
    (r"(?i)(?:copy|paste)\s+(?:this|the\s+following)\s+(?:into|in)\s+(?:your\s+)?terminal", "Direct terminal paste instruction", Severity.MEDIUM),
]

OBFUSCATION_PATTERNS = [
    # Hex-encoded strings
    (r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){3,}", "Hex-encoded string (possible obfuscation)", Severity.HIGH),
    # Unicode escape sequences
    (r"\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){3,}", "Unicode escape sequence (possible obfuscation)", Severity.HIGH),
    # Long base64 strings (likely encoded payloads)
    (r"[A-Za-z0-9+/]{60,}={0,2}", "Long base64 string (possible encoded payload)", Severity.MEDIUM),
    # Invisible unicode characters
    (r"[\u200b\u200c\u200d\u2060\ufeff]", "Invisible unicode character (text hiding)", Severity.HIGH),
    # HTML entities used for obfuscation
    (r"&#x?[0-9a-fA-F]+;(?:&#x?[0-9a-fA-F]+;){3,}", "HTML entity chain (possible obfuscation)", Severity.MEDIUM),
]


def scan_content(content: str, path: str) -> ScanResult:
    """Scan skill content for security issues."""
    result = ScanResult(path=path)
    lines = content.split("\n")

    all_rules = [
        ("prompt_injection", PROMPT_INJECTION_PATTERNS),
        ("dangerous_shell", DANGEROUS_SHELL_PATTERNS),
        ("malicious_url", MALICIOUS_URL_PATTERNS),
        ("social_engineering", SOCIAL_ENGINEERING_PATTERNS),
        ("obfuscation", OBFUSCATION_PATTERNS),
    ]

    severity_scores = {
        Severity.CRITICAL: 30,
        Severity.HIGH: 15,
        Severity.MEDIUM: 8,
        Severity.LOW: 3,
        Severity.INFO: 0,
    }

    for line_num, line in enumerate(lines, 1):
        for category, patterns in all_rules:
            for pattern, message, severity in patterns:
                if re.search(pattern, line):
                    # Avoid duplicate findings for same rule on same line
                    snippet = line.strip()[:120]
                    result.findings.append(Finding(
                        rule=f"{category}/{pattern[:40]}",
                        severity=severity,
                        message=message,
                        line=line_num,
                        snippet=snippet,
                    ))
                    result.score -= severity_scores[severity]

    # Clamp score
    result.score = max(0, result.score)
    return result


def scan_file(path: Path) -> ScanResult:
    """Scan a single SKILL.md file."""
    content = path.read_text(encoding="utf-8", errors="replace")
    return scan_content(content, str(path))


def scan_directory(path: Path) -> list[ScanResult]:
    """Scan all SKILL.md files in a directory tree."""
    results = []
    for skill_file in path.rglob("SKILL.md"):
        results.append(scan_file(skill_file))
    return results


def print_result(result: ScanResult, verbose: bool = False):
    """Print scan results."""
    icon = {"PASS": "✅", "WARN": "⚠️", "FAIL": "🚨"}.get(result.verdict, "?")
    print(f"\n{icon} {result.path} [{result.verdict}] (score: {result.score}/100)")

    if not result.findings:
        print("  No issues found.")
        return

    # Sort by severity
    severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
    sorted_findings = sorted(result.findings, key=lambda f: severity_order[f.severity])

    for f in sorted_findings:
        sev_icon = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
            Severity.INFO: "⚪",
        }[f.severity]
        line_info = f" (line {f.line})" if f.line else ""
        print(f"  {sev_icon} [{f.severity.value.upper()}]{line_info} {f.message}")
        if verbose and f.snippet:
            print(f"     > {f.snippet}")


def main():
    parser = argparse.ArgumentParser(
        description="Vigil: OpenClaw Skill Security Scanner 🦞",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("path", nargs="?", help="Path to SKILL.md or directory to scan")
    parser.add_argument("--audit", action="store_true", help="Scan all installed OpenClaw skills")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show code snippets")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--fail-under", type=int, default=50, help="Exit 1 if score below threshold (default: 50)")

    args = parser.parse_args()

    results = []

    if args.audit:
        skills_dir = Path("/opt/openclaw/skills")
        if skills_dir.exists():
            results = scan_directory(skills_dir)
        else:
            print("No OpenClaw skills directory found.")
            sys.exit(1)
    elif args.path:
        p = Path(args.path)
        if p.is_file():
            results = [scan_file(p)]
        elif p.is_dir():
            results = scan_directory(p)
        else:
            print(f"Path not found: {args.path}")
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(0)

    if args.json:
        output = []
        for r in results:
            d = {"path": r.path, "score": r.score, "verdict": r.verdict, "findings": [asdict(f) for f in r.findings]}
            output.append(d)
        print(json.dumps(output, indent=2))
    else:
        print(f"\n🦞 Vigil Scan — {len(results)} skill(s)")
        print("=" * 50)
        for r in results:
            print_result(r, verbose=args.verbose)

        # Summary
        fails = sum(1 for r in results if r.verdict == "FAIL")
        warns = sum(1 for r in results if r.verdict == "WARN")
        passes = sum(1 for r in results if r.verdict == "PASS")
        print(f"\n{'=' * 50}")
        print(f"Results: ✅ {passes} pass | ⚠️ {warns} warn | 🚨 {fails} fail")

    # Exit code
    min_score = min((r.score for r in results), default=100)
    if min_score < args.fail_under:
        sys.exit(1)


if __name__ == "__main__":
    main()
