"""Conservative CWE-to-OWASP evidence mapping, not a compliance assessment."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any


_OWASP_TOP_10_2021_CWES: dict[str, frozenset[str]] = {
    "A01:2021 Broken Access Control": frozenset({
        "CWE-22", "CWE-23", "CWE-35", "CWE-59", "CWE-200", "CWE-201",
        "CWE-219", "CWE-284", "CWE-285", "CWE-352", "CWE-862", "CWE-863",
        "CWE-918",
    }),
    "A02:2021 Cryptographic Failures": frozenset({
        "CWE-261", "CWE-296", "CWE-310", "CWE-311", "CWE-312", "CWE-319",
        "CWE-326", "CWE-327", "CWE-328", "CWE-330", "CWE-338", "CWE-522",
        "CWE-759", "CWE-760", "CWE-780", "CWE-916",
    }),
    "A03:2021 Injection": frozenset({
        "CWE-74", "CWE-75", "CWE-77", "CWE-78", "CWE-79", "CWE-80",
        "CWE-83", "CWE-89", "CWE-90", "CWE-91", "CWE-93", "CWE-94",
        "CWE-95", "CWE-96", "CWE-116", "CWE-917", "CWE-1336",
    }),
    "A04:2021 Insecure Design": frozenset(),
    "A05:2021 Security Misconfiguration": frozenset({"CWE-16", "CWE-611"}),
    "A06:2021 Vulnerable and Outdated Components": frozenset(),
    "A07:2021 Identification and Authentication Failures": frozenset({
        "CWE-255", "CWE-259", "CWE-287", "CWE-288", "CWE-290", "CWE-294",
        "CWE-295", "CWE-297", "CWE-300", "CWE-322", "CWE-384", "CWE-521",
        "CWE-522", "CWE-613", "CWE-798", "CWE-940",
    }),
    "A08:2021 Software and Data Integrity Failures": frozenset({
        "CWE-345", "CWE-353", "CWE-494", "CWE-502", "CWE-829", "CWE-830",
        "CWE-915",
    }),
    "A09:2021 Security Logging and Monitoring Failures": frozenset({
        "CWE-117", "CWE-223", "CWE-532", "CWE-778",
    }),
    "A10:2021 Server-Side Request Forgery": frozenset({"CWE-918"}),
}


def build_compliance_evidence(
    findings: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    evidence_by_category: dict[str, list[dict[str, Any]]] = {
        category: [] for category in _OWASP_TOP_10_2021_CWES
    }
    for finding in findings:
        cwe = finding.get("cwe")
        if not isinstance(cwe, str):
            continue
        normalized_cwe = cwe.strip().upper()
        for category, known_cwes in _OWASP_TOP_10_2021_CWES.items():
            if normalized_cwe in known_cwes:
                evidence_by_category[category].append({
                    "file": finding.get("file") or finding.get("file_path"),
                    "line": finding.get("line") or finding.get("line_number"),
                    "rule_id": finding.get("rule_id"),
                    "cwe": normalized_cwe,
                })

    return {
        "framework": "OWASP Top 10:2021",
        "scope": "partial CWE-to-finding evidence mapping",
        "is_compliance_assessment": False,
        "categories": [
            {
                "category": category,
                "status": "EVIDENCE_FOUND" if evidence else "NO_MAPPED_EVIDENCE",
                "evidence_count": len(evidence),
                "evidence": evidence,
            }
            for category, evidence in evidence_by_category.items()
        ],
    }
