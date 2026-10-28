"""Generate escaped HTML and PDF executive reports from scan JSON."""

from __future__ import annotations

import html
import io
from collections.abc import Mapping, Sequence
from typing import Any
from xml.sax.saxutils import escape


def _pdf_text(value: Any) -> str:
    return escape(str(value)).replace("\n", "<br/>")


def build_html_report(
    metrics: Mapping[str, Any],
    findings: Sequence[Mapping[str, Any]],
    *,
    title: str = "AutoForge Security Scan Summary",
) -> str:
    counts = metrics.get("severity_counts", {})
    cards = "".join(
        f'<article class="card"><span>{html.escape(severity)}</span>'
        f'<strong>{int(counts.get(severity, 0))}</strong></article>'
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    )
    rows = []
    for finding in findings:
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(finding.get('severity', 'UNKNOWN')))}</td>"
            f"<td>{html.escape(str(finding.get('reachability', 'UNKNOWN')))}</td>"
            f"<td>{html.escape(str(finding.get('file', finding.get('file_path', 'unknown'))))}</td>"
            f"<td>{html.escape(str(finding.get('line', '?')))}</td>"
            f"<td>{html.escape(str(finding.get('rule_id', '')))}</td>"
            f"<td>{html.escape(str(finding.get('message', finding.get('description', ''))))}</td>"
            "</tr>"
        )
    finding_rows = "\n".join(rows) or '<tr><td colspan="6">No findings reported.</td></tr>'
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>
body{{font:15px/1.5 Arial,sans-serif;color:#172033;max-width:1100px;margin:36px auto;padding:0 20px}}
h1,h2{{color:#172033}} .muted{{color:#64748b}} .cards{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}}
.card{{padding:16px;border:1px solid #dbe2ea;border-radius:8px;background:#f8fafc}}
.card span,.card strong{{display:block}} .card strong{{font-size:28px;margin-top:4px}}
.metrics{{display:flex;gap:24px;flex-wrap:wrap;margin:20px 0}} table{{width:100%;border-collapse:collapse}}
th,td{{text-align:left;padding:9px;border-bottom:1px solid #dbe2ea;vertical-align:top}} th{{background:#f1f5f9}}
@media print{{body{{margin:0;max-width:none}} tr{{break-inside:avoid}}}}
</style>
</head>
<body>
<h1>{html.escape(title)}</h1>
<p class="muted">Generated {html.escape(str(metrics.get('scan_timestamp', 'unknown')))}</p>
<section class="cards">{cards}</section>
<section class="metrics">
<span>Files analyzed: {int(metrics.get('files_analyzed', 0))}/{int(metrics.get('files_received', 0))}</span>
<span>AST coverage: {float(metrics.get('ast_coverage_pct', 0)):.2f}%</span>
<span>Reachable: {int(metrics.get('reachable_findings', 0))}</span>
<span>Unreachable noise: {int(metrics.get('unreachable_findings', 0))}</span>
<span>Noise reduction: {float(metrics.get('noise_reduction_pct', 0)):.2f}%</span>
</section>
<h2>Findings</h2>
<table><thead><tr><th>Severity</th><th>Reachability</th><th>File</th><th>Line</th><th>Rule</th><th>Finding</th></tr></thead>
<tbody>{finding_rows}</tbody></table>
<p class="muted">Reachability is an analyzer estimate. Review findings and AI-generated suggestions before applying remediation.</p>
</body>
</html>"""


def build_pdf_report(
    metrics: Mapping[str, Any],
    findings: Sequence[Mapping[str, Any]],
    *,
    title: str = "AutoForge Security Scan Summary",
) -> bytes:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import landscape, letter
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError as error:
        raise RuntimeError(
            "PDF reporting requires reportlab; install 3_ast_analyzer\\requirements.txt"
        ) from error

    buffer = io.BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=landscape(letter),
        rightMargin=0.45 * inch,
        leftMargin=0.45 * inch,
        topMargin=0.45 * inch,
        bottomMargin=0.45 * inch,
    )
    styles = getSampleStyleSheet()
    body = styles["BodyText"]
    elements = [
        Paragraph(title, styles["Title"]),
        Paragraph(
            f"Generated {_pdf_text(metrics.get('scan_timestamp', 'unknown'))}",
            styles["Normal"],
        ),
        Spacer(1, 0.18 * inch),
        Paragraph(
            "Files analyzed: "
            f"{int(metrics.get('files_analyzed', 0))}/{int(metrics.get('files_received', 0))}"
            f" &nbsp; | &nbsp; AST coverage: {float(metrics.get('ast_coverage_pct', 0)):.2f}%"
            f" &nbsp; | &nbsp; Reachable findings: {int(metrics.get('reachable_findings', 0))}"
            f" &nbsp; | &nbsp; Unreachable noise: {int(metrics.get('unreachable_findings', 0))}"
            f" &nbsp; | &nbsp; Noise reduction: {float(metrics.get('noise_reduction_pct', 0)):.2f}%",
            body,
        ),
        Spacer(1, 0.18 * inch),
    ]
    severity_counts = metrics.get("severity_counts", {})
    cards = [
        ["Severity", "Critical", "High", "Medium", "Low"],
        ["Findings", *[int(severity_counts.get(severity, 0)) for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")]],
    ]
    elements.extend(
        [
            Table(
                cards,
                style=TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                        ("PADDING", (0, 0), (-1, -1), 7),
                    ]
                ),
            ),
            Spacer(1, 0.2 * inch),
            Paragraph("Findings", styles["Heading2"]),
        ]
    )
    table_rows: list[list[Any]] = [["Severity", "Reachability", "Location", "Rule", "Finding", "Remediation"]]
    for finding in findings:
        table_rows.append(
            [
                Paragraph(_pdf_text(finding.get("severity", "UNKNOWN")), body),
                Paragraph(_pdf_text(finding.get("reachability", "UNKNOWN")), body),
                Paragraph(
                    _pdf_text(
                        f"{finding.get('file', finding.get('file_path', 'unknown'))}:"
                        f"{finding.get('line', '?')}"
                    ),
                    body,
                ),
                Paragraph(_pdf_text(finding.get("rule_id", "")), body),
                Paragraph(
                    _pdf_text(finding.get("message", finding.get("description", ""))),
                    body,
                ),
                Paragraph(
                    _pdf_text(finding.get("remediation", "Review and remediate")),
                    body,
                ),
            ]
        )
    if len(table_rows) == 1:
        table_rows.append(["-", "-", "-", "-", "No findings reported.", "-"])
    table = Table(
        table_rows,
        repeatRows=1,
        colWidths=[0.8 * inch, 1.0 * inch, 1.2 * inch, 1.15 * inch, 3.0 * inch, 3.2 * inch],
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    elements.extend(
        [
            table,
            Spacer(1, 0.15 * inch),
            Paragraph(
                "Reachability is an analyzer estimate. Review findings and AI-generated "
                "suggestions before applying remediation.",
                styles["Italic"],
            ),
        ]
    )
    document.build(elements)
    return buffer.getvalue()
