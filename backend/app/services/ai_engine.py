"""
Phase 4 — AI Engine
Utilise l'API Anthropic via httpx (évite les problèmes pydantic v1 / Python 3.14)
Produit : résumé exécutif, chemins d'attaque, priorités, quick wins.
"""

import json
from typing import Any, Dict, List, Optional


SYSTEM_PROMPT = """Tu es un expert en cybersécurité offensive et défensive, spécialisé dans la modélisation des menaces (threat modeling), le framework MITRE ATT&CK et la rédaction de rapports de pentest.

Ton rôle est d'analyser les vulnérabilités détectées par un scanner automatique et de produire une analyse structurée qui aide l'équipe technique ET les décideurs à comprendre les risques réels.

Tu dois :
1. Expliquer en termes clairs ce que les vulnérabilités signifient concrètement
2. Modéliser les chemins d'attaque réalistes en les référençant avec des techniques MITRE ATT&CK (format: T1234 — Technique Name)
3. Prioriser les actions de remédiation selon le risque réel

Pour chaque attack_path, inclure les champs mitre_techniques (liste de strings au format "TXXXX — Nom") et mitre_tactics (liste des tactiques correspondantes).

Tu réponds UNIQUEMENT en JSON valide, sans markdown, sans texte supplémentaire."""


def _build_prompt(target: str, scan_type: str, findings: list) -> str:
    vuln_list = []
    for i, f in enumerate(findings, 1):
        evidence = ""
        if hasattr(f, "evidence") and f.evidence:
            evidence = f.evidence[:150]
        cvss = f.cvss_score if hasattr(f, "cvss_score") and f.cvss_score else "N/A"
        vuln_list.append(
            f"{i}. [{f.severity.upper()}] {f.title}\n"
            f"   Catégorie: {f.category}\n"
            f"   Description: {f.description}\n"
            f"   Evidence: {evidence or 'N/A'}\n"
            f"   CVSS: {cvss}"
        )

    vulns_text = "\n\n".join(vuln_list) if vuln_list else "Aucune vulnérabilité détectée."
    total = len(findings)
    critical = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")
    medium = sum(1 for f in findings if f.severity == "medium")

    return f"""Analyse le rapport de scan de sécurité suivant et génère une réponse JSON structurée.

## Cible
- URL/IP: {target}
- Type de scan: {scan_type}
- Total vulnérabilités: {total} ({critical} critique(s), {high} élevée(s), {medium} moyenne(s))

## Vulnérabilités détectées

{vulns_text}

## Format de réponse attendu (JSON strict)

{{
  "executive_summary": "Résumé non-technique de 2-3 phrases pour un décideur",
  "risk_narrative": "Analyse technique de 3-4 phrases sur le niveau de risque global",
  "attack_paths": [
    {{
      "name": "Nom court du scénario d'attaque",
      "severity": "critical|high|medium|low",
      "probability": "high|medium|low",
      "prerequisites": "Ce dont l'attaquant a besoin",
      "steps": ["Étape 1", "Étape 2", "Étape 3"],
      "impact": "Impact concret si réussi",
      "vulnerabilities_used": ["titre vuln 1", "titre vuln 2"],
      "mitre_techniques": ["T1190 — Exploit Public-Facing Application", "T1059 — Command and Scripting Interpreter"],
      "mitre_tactics": ["Initial Access", "Execution"]
    }}
  ],
  "top_priorities": [
    {{
      "rank": 1,
      "action": "Action concrète à réaliser",
      "reason": "Pourquoi c'est prioritaire",
      "effort": "faible|moyen|élevé",
      "impact_if_fixed": "Ce que ça corrige concrètement"
    }}
  ],
  "quick_wins": ["Action rapide 1", "Action rapide 2", "Action rapide 3"]
}}

Génère 1 à 3 attack_paths réalistes. Génère exactement 3 top_priorities et 3 quick_wins.
Réponds UNIQUEMENT avec le JSON, sans aucun texte autour."""


def run_ai_analysis(
    target: str,
    scan_type: str,
    findings: list,
    api_key: str,
) -> Optional[Dict[str, Any]]:
    """Appelle Claude via httpx direct (pas de SDK) pour éviter les pb Pydantic/Python 3.14."""
    if not api_key:
        return None

    try:
        import httpx

        payload = {
            "model": "claude-opus-4-6",
            "max_tokens": 4096,
            "system": SYSTEM_PROMPT,
            "messages": [
                {"role": "user", "content": _build_prompt(target, scan_type, findings)}
            ],
        }

        with httpx.Client(timeout=120.0) as client:
            response = client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json=payload,
            )

        if response.status_code != 200:
            print(f"[AI Engine] HTTP {response.status_code}: {response.text[:300]}")
            return None

        data = response.json()
        text = ""
        for block in data.get("content", []):
            if block.get("type") == "text":
                text = block["text"].strip()
                break

        if not text:
            return None

        # Nettoyer les backticks éventuels
        if text.startswith("```"):
            text = text.split("```", 2)[1]
            if text.startswith("json"):
                text = text[4:]
            text = text.rsplit("```", 1)[0].strip()

        return json.loads(text)

    except Exception as e:
        print(f"[AI Engine] Erreur: {e}")
        return None


def enrich_scan_with_ai(
    target: str,
    scan_type: str,
    findings: list,
    api_key: str,
) -> Dict[str, Any]:
    """Wrapper avec fallback si l'IA échoue."""
    result = run_ai_analysis(target, scan_type, findings, api_key)

    if result:
        return result

    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    summary = f"Analyse de {target} terminée. {len(findings)} résultat(s) détecté(s)."
    if counts.get("critical"):
        summary += f" ATTENTION : {counts['critical']} vulnérabilité(s) critique(s)."

    return {
        "executive_summary": summary,
        "risk_narrative": "Analyse IA non disponible. Consultez les vulnérabilités détectées pour une évaluation manuelle.",
        "attack_paths": [],
        "top_priorities": [],
        "quick_wins": [],
    }
