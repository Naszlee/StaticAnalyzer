"""
ioc_entropy.py - Static Malware Analyzer (Part 2):
Shannon entropy analysis, section-level checks, and static IOC extraction.

STATIC analysis only: reads bytes in memory, never executes files, and
never transmits data over the network.
"""
from __future__ import annotations

import math
import re
from collections import Counter

from pe_inspector import section_bytes

IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
URL_RE = re.compile(r"\bhttps?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|biz|info|xyz|top|ru|cn|tk|pw|cc|gov|edu|my|test|example)\b",
    re.IGNORECASE,
)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
REG_RE = re.compile(
    r"\b(?:HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU|HKEY_CLASSES_ROOT|HKCR)"
    r"\\[A-Za-z0-9_\-\\ ]+",
    re.IGNORECASE,
)
ASCII_STR_RE = re.compile(rb"[\x20-\x7e]{5,}")

SUSPICIOUS_APIS = {
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "WriteProcessMemory",
    "CreateRemoteThread", "NtUnmapViewOfSection", "SetWindowsHookEx",
    "CryptEncrypt", "CryptDecrypt", "InternetOpen", "InternetConnect",
    "HttpOpenRequest", "URLDownloadToFile", "WinExec", "ShellExecute",
    "CreateProcess", "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
}


def shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy in bits per byte [0.0, 8.0]."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def classify_entropy(score: float) -> str:
    """Return a qualitative label for an entropy score on a 0.0-8.0 scale."""
    if score < 3.5:
        return "low"
    if score < 6.5:
        return "normal"
    if score < 7.2:
        return "elevated"
    return "very_high"


def analyze_sections_and_entropy(data: bytes, pe_info: dict | None) -> tuple[list[dict], list[dict]]:
    """Calculate per-section entropy and flag high-entropy or W+X sections."""
    section_rows: list[dict] = []
    findings: list[dict] = []

    if not pe_info:
        return section_rows, findings

    for sec in pe_info.get("sections", []):
        raw = section_bytes(data, sec)
        sec_ent = shannon_entropy(raw) if raw else 0.0
        rwx = bool(sec.get("writable") and sec.get("executable"))
        label = sec.get("name") or f"#{sec.get('index', '?')}"

        section_rows.append({
            "name": label,
            "index": sec.get("index"),
            "raw_size": len(raw),
            "entropy": sec_ent,
            "rwx": rwx,
            "flags": sec.get("flags", []),
        })

        if rwx:
            findings.append({
                "severity": "HIGH",
                "message": f"Section {label} has W+X permissions (entropy={sec_ent:.2f})",
            })
        if len(raw) >= 256 and sec_ent >= 7.2:
            findings.append({
                "severity": "MEDIUM",
                "message": f"High-entropy section {label} ({sec_ent:.2f} bits/byte) - possible packing/encryption",
            })

    return section_rows, findings


def extract_static_iocs(data: bytes, max_strings: int = 200) -> tuple[dict, list[dict]]:
    """Extract printable strings and regex-matched static IOCs without executing bytes."""
    findings: list[dict] = []
    raw_matches = ASCII_STR_RE.findall(data)
    strings = [m.decode("ascii", errors="ignore") for m in raw_matches[:5000]]
    joined = "\n".join(strings)

    ips = sorted(set(IPV4_RE.findall(joined)))
    urls = sorted(set(URL_RE.findall(joined)))
    domains = sorted(set(DOMAIN_RE.findall(joined)))
    emails = sorted(set(EMAIL_RE.findall(joined)))
    reg_keys = sorted(set(REG_RE.findall(joined)))

    found_apis = sorted({
        api for api in SUSPICIOUS_APIS
        if re.search(rf"\b{re.escape(api)}\b", joined)
    })

    if found_apis:
        findings.append({
            "severity": "MEDIUM",
            "message": f"Suspicious API strings referenced: {', '.join(found_apis[:8])}",
        })
    if urls or ips:
        findings.append({
            "severity": "INFO",
            "message": f"Extracted {len(urls)} URL(s) and {len(ips)} IPv4 indicator(s) from static strings",
        })

    iocs = {
        "ipv4": ips[:100],
        "urls": urls[:100],
        "domains": domains[:100],
        "emails": emails[:100],
        "registry_keys": reg_keys[:100],
        "suspicious_apis": found_apis,
        "ascii_strings_sample": strings[:max_strings],
    }
    return iocs, findings


def analyze_entropy_and_iocs(data: bytes, pe_info: dict | None = None) -> dict:
    """Main entry point for Part 2 entropy and static IOC analysis."""
    file_ent = shannon_entropy(data)
    sec_rows, sec_findings = analyze_sections_and_entropy(data, pe_info)
    iocs, ioc_findings = extract_static_iocs(data)

    findings = list(sec_findings) + list(ioc_findings)
    if len(data) >= 256 and file_ent >= 7.2:
        findings.append({
            "severity": "MEDIUM",
            "message": f"Overall file entropy is high ({file_ent:.2f} bits/byte) - packed or encrypted content likely",
        })

    return {
        "file_entropy": file_ent,
        "entropy_assessment": classify_entropy(file_ent),
        "section_entropies": sec_rows,
        "iocs": iocs,
        "findings": findings,
    }