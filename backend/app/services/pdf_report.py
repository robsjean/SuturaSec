"""
PDF Report Generator — SuturaSec
Génère un rapport PDF professionnel à partir des résultats d'un scan.
Utilise WeasyPrint (HTML → PDF) avec un template Jinja2 dédié.
"""

import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader


# ---------------------------------------------------------------------------
# Helpers de classification
# ---------------------------------------------------------------------------

def _risk_class(score: Optional[float]) -> str:
    if score is None:
        return "risk-info"
    if score >= 8:
        return "risk-critical"
    if score >= 6:
        return "risk-high"
    if score >= 4:
        return "risk-medium"
    if score >= 1:
        return "risk-low"
    return "risk-info"


def _risk_label(score: Optional[float]) -> str:
    if score is None:
        return "Non évalué"
    if score >= 8:
        return "Critique"
    if score >= 6:
        return "Élevé"
    if score >= 4:
        return "Moyen"
    if score >= 1:
        return "Faible"
    return "Info"


def _sev_order(sev: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(sev, 5)


def _sev_label_fr(sev: str) -> str:
    return {"critical": "Critique", "high": "Élevé",
            "medium": "Moyen", "low": "Faible", "info": "Info"}.get(sev, sev)


def _grade_color(grade: str) -> str:
    if grade in ("A+", "A"):
        return "#16a34a"
    if grade == "B":
        return "#d97706"
    if grade == "C":
        return "#ea580c"
    return "#dc2626"


def _score_color(score: float) -> str:
    if score >= 80:
        return "#16a34a"
    if score >= 60:
        return "#d97706"
    if score >= 40:
        return "#ea580c"
    return "#dc2626"


def _status_class(code: Optional[int]) -> str:
    if code is None:
        return ""
    if code < 300:
        return "status-2xx"
    if code < 400:
        return "status-3xx"
    if code < 500:
        return "status-4xx"
    return "status-5xx"


def _fmt_date(dt: Optional[datetime]) -> str:
    if not dt:
        return "—"
    return dt.strftime("%d/%m/%Y à %H:%M UTC")


def _scan_type_label(t: str) -> str:
    return {
        "web": "Analyse Web",
        "network": "Analyse Réseau",
        "cti": "Threat Intelligence",
        "subdomain": "Subdomain Enumeration",
    }.get(t, t)


# ---------------------------------------------------------------------------
# Générateur principal
# ---------------------------------------------------------------------------

def generate_pdf_report(scan) -> bytes:
    """Render the HTML report and convert to PDF via WeasyPrint."""
    from weasyprint import HTML

    template_dir = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "..", "templates")
    )
    env = Environment(loader=FileSystemLoader(template_dir), autoescape=True)

    # Custom filters
    env.filters["sev_label"] = _sev_label_fr
    env.filters["sev_order"] = _sev_order
    env.filters["grade_color"] = _grade_color
    env.filters["score_color"] = _score_color
    env.filters["status_class"] = _status_class
    env.filters["fmt_date"] = _fmt_date

    template = env.get_template("report.html")

    vulns = sorted(
        scan.vulnerabilities,
        key=lambda v: _sev_order(v.severity),
    )

    sev_counts = {
        "critical": sum(1 for v in vulns if v.severity == "critical"),
        "high":     sum(1 for v in vulns if v.severity == "high"),
        "medium":   sum(1 for v in vulns if v.severity == "medium"),
        "low":      sum(1 for v in vulns if v.severity == "low"),
        "info":     sum(1 for v in vulns if v.severity == "info"),
    }

    ctx = {
        "scan":           scan,
        "vulnerabilities": vulns,
        "sev_counts":     sev_counts,
        "generated_at":   datetime.utcnow().strftime("%d/%m/%Y à %H:%M UTC"),
        "risk_class":     _risk_class(scan.risk_score),
        "risk_label":     _risk_label(scan.risk_score),
        "scan_type_label": _scan_type_label(scan.scan_type),
        # quick access
        "attack_paths":   scan.attack_paths or {},
        "compliance":     scan.compliance_reports,
        "threat_intel":   scan.threat_intel,
        "subdomain":      scan.subdomain_results,
    }

    html_content = template.render(**ctx)

    # base_url allows WeasyPrint to resolve relative URLs (fonts, images)
    pdf_bytes = HTML(
        string=html_content,
        base_url=template_dir,
    ).write_pdf()

    return pdf_bytes
