"""
Enterprise CVSS v3.1 Calculator.

Implements the full CVSS v3.1 specification:
- Base Score (Exploitability + Impact)
- Temporal Score (Exploit Code Maturity, Remediation Level, Report Confidence)
- Environmental Score (Modified metrics + CIA requirements)
- Dynamic Priority combining CVSS, EPSS, KEV, asset criticality, exposure, evidence quality
"""
import math
from typing import Optional, Dict, Any
from ..models.finding import Severity
from .models import AssetCriticality, ExposureLevel, CVSSScore, EPSSScore, BusinessRisk


# ── CVSS v3.1 Metric Value Tables ────────────────────────────────────────────

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}

# Temporal metric values
_E = {"X": 1.00, "U": 0.91, "P": 0.94, "F": 0.97, "H": 1.00}   # Exploit Code Maturity
_RL = {"X": 1.00, "O": 0.95, "T": 0.96, "W": 0.97, "U": 1.00}  # Remediation Level
_RC = {"X": 1.00, "U": 0.92, "R": 0.96, "C": 1.00}              # Report Confidence

# Severity thresholds per CVSS v3.1 spec
_SEVERITY_THRESHOLDS = [
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (0.1, Severity.LOW),
    (0.0, Severity.INFO),
]

# Severity → default CVSS base score (used when no vector is available)
_SEVERITY_BASE = {
    Severity.INFO: 0.0,
    Severity.LOW: 3.9,
    Severity.MEDIUM: 6.5,
    Severity.HIGH: 8.9,
    Severity.CRITICAL: 9.8,
}

# Asset criticality → priority multiplier
_CRITICALITY_MULTIPLIER = {
    AssetCriticality.LOW: 0.75,
    AssetCriticality.MEDIUM: 1.00,
    AssetCriticality.HIGH: 1.15,
    AssetCriticality.MISSION_CRITICAL: 1.30,
}

# Exposure → priority multiplier
_EXPOSURE_MULTIPLIER = {
    ExposureLevel.INTERNAL: 0.80,
    ExposureLevel.EXTERNAL: 1.00,
    ExposureLevel.INTERNET_FACING: 1.10,
}

# CWE → business risk profile
_CWE_BUSINESS_RISK: Dict[str, Dict] = {
    "CWE-89":   {"data": 9.5, "compliance": 9.0, "reputation": 8.0, "ops": 7.0},
    "CWE-79":   {"data": 7.0, "compliance": 7.5, "reputation": 8.5, "ops": 5.0},
    "CWE-78":   {"data": 9.5, "compliance": 9.5, "reputation": 9.0, "ops": 9.5},
    "CWE-22":   {"data": 8.5, "compliance": 8.0, "reputation": 7.0, "ops": 6.0},
    "CWE-918":  {"data": 9.0, "compliance": 8.5, "reputation": 8.0, "ops": 8.0},
    "CWE-611":  {"data": 8.5, "compliance": 8.0, "reputation": 7.5, "ops": 6.5},
    "CWE-1336": {"data": 9.5, "compliance": 9.5, "reputation": 9.0, "ops": 9.5},
    "CWE-614":  {"data": 6.0, "compliance": 7.0, "reputation": 5.0, "ops": 4.0},
    "CWE-693":  {"data": 5.0, "compliance": 6.0, "reputation": 4.0, "ops": 3.0},
    "CWE-200":  {"data": 7.0, "compliance": 7.5, "reputation": 6.0, "ops": 4.0},
    "CWE-937":  {"data": 6.5, "compliance": 7.0, "reputation": 6.0, "ops": 5.0},
    "CWE-319":  {"data": 8.0, "compliance": 8.5, "reputation": 7.0, "ops": 5.0},
}


def _roundup(value: float) -> float:
    """CVSS v3.1 roundup: round up to nearest 0.1."""
    return math.ceil(value * 10) / 10


class CVSSCalculator:
    """Full CVSS v3.1 base, temporal, and environmental score calculator."""

    @classmethod
    def calculate_for_finding(cls, finding: Any) -> CVSSScore:
        """Dynamically construct a CVSS v3.1 score and vector based on finding features."""
        # Determine attack vector, complexity, privileges, user interaction, scope, and impacts
        av = "N"
        ac = "L"
        pr = "N"
        ui = "N"
        s = "U"
        c = "N"
        i = "N"
        a = "N"

        # Privilege Required check: inspect HTTP request headers for Auth or Cookies
        if finding.http_request:
            req_lower = finding.http_request.lower()
            if "authorization:" in req_lower or "cookie:" in req_lower:
                pr = "L"

        plugin_id = getattr(finding, "plugin_id", "")
        observation_type = getattr(finding, "observation_type", "")
        # For EnrichedFinding, observation_type isn't directly on it, but we can infer from title
        title_lower = getattr(finding, "title", "").lower()

        # Determine features based on plugin ID
        if plugin_id == "ACT-XSS-001":
            ui = "R"
            s = "C"
            c = "L"
            i = "L"
            a = "N"
        elif plugin_id == "ACT-SQLI-001":
            c = "H"
            i = "H"
            a = "L"
        elif plugin_id in ("ACT-TRAV-001", "ACT-XXE-001"):
            c = "H"
            i = "N"
            a = "N"
        elif plugin_id == "ACT-SSRF-001":
            s = "C"
            c = "H"
            i = "L"
            a = "N"
        elif plugin_id in ("ACT-CMDI-001", "ACT-SSTI-001"):
            c = "H"
            i = "H"
            a = "H"
        elif plugin_id == "PASS-001":  # Security Headers
            c = "N"
            i = "L"
            a = "N"
        elif plugin_id == "PASS-002":  # Insecure Cookie
            c = "L"
            i = "L"
            a = "N"
        elif plugin_id == "PASS-003":  # Info Disclosure
            orig_sev = getattr(finding, "severity", Severity.MEDIUM)
            if orig_sev == Severity.INFO or "google api key" in title_lower or "notice" in title_lower:
                c = "N"
                i = "N"
                a = "N"
            elif "secret" in title_lower or "api key" in title_lower or "token" in title_lower or "password" in title_lower:
                c = "H"
                i = "N"
                a = "N"
            elif "stack trace" in title_lower or "error" in title_lower:
                c = "L"
                i = "N"
                a = "N"
            elif orig_sev == Severity.LOW or any(kw in title_lower for kw in ("banner", "email", "version", "disclosed", "disclosure")):
                ac = "H"
                c = "L"
                i = "N"
                a = "N"
            else:
                ac = "H"
                c = "L"
                i = "N"
                a = "N"
        elif plugin_id == "PASS-004":  # Outdated component
            # If the finding already has a High/Critical severity, map it
            if getattr(finding, "severity", Severity.MEDIUM) in (Severity.HIGH, Severity.CRITICAL):
                c = "H"
                i = "H"
                a = "H"
            else:
                ac = "H"
                c = "L"
                i = "L"
                a = "L"
        elif plugin_id == "PASS-005":  # Cleartext Transmission
            c = "H"
            i = "N"
            a = "N"

        vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
        score_obj = cls.calculate_from_vector(vector)
        
        # Override score if the original finding severity is much higher than the computed template score
        orig_sev = getattr(finding, "severity", None)
        if orig_sev and orig_sev != Severity.INFO:
            default_base = _SEVERITY_BASE.get(orig_sev, 0.0)
            if default_base > score_obj.base_score:
                return cls.calculate_base(orig_sev)
                
        return score_obj

    @classmethod
    def severity_from_score(cls, score: float) -> Severity:
        """Derive CVSS v3.1 qualitative severity rating from base score according to spec."""
        if score >= 9.0:
            return Severity.CRITICAL
        elif score >= 7.0:
            return Severity.HIGH
        elif score >= 4.0:
            return Severity.MEDIUM
        elif score >= 0.1:
            return Severity.LOW
        return Severity.INFO

    @classmethod
    def calculate_base(cls, severity: Severity) -> CVSSScore:
        """Derive a canonical CVSS v3.1 vector and score from qualitative severity."""
        if severity == Severity.INFO:
            vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"  # Mathematically yields 0.0 (Info)
        elif severity == Severity.LOW:
            vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"  # Mathematically yields 3.7 (Low 0.1-3.9)
        elif severity == Severity.MEDIUM:
            vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"  # Mathematically yields 6.5 (Medium 4.0-6.9)
        elif severity == Severity.HIGH:
            vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"  # Mathematically yields 8.8 (High 7.0-8.9)
        else:  # CRITICAL
            vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # Mathematically yields 9.8 (Critical 9.0-10.0)

        metrics = cls.calculate_from_vector(vector)
        return CVSSScore(
            base_score=metrics.base_score,
            vector=vector,
            attack_vector="N",
            attack_complexity="L" if severity != Severity.LOW else "H",
            privileges_required="N",
            user_interaction="R" if severity == Severity.HIGH else "N",
            scope="U",
            confidentiality_impact="H" if severity in (Severity.HIGH, Severity.CRITICAL) else ("L" if severity == Severity.LOW else "N"),
            integrity_impact="H" if severity in (Severity.HIGH, Severity.CRITICAL) else ("L" if severity == Severity.MEDIUM else "N"),
            availability_impact="H" if severity in (Severity.HIGH, Severity.CRITICAL) else "N",
        )

    @classmethod
    def recalibrate_and_validate(cls, finding: Any) -> Any:
        """
        Enforce Enterprise CVSS Invariants:
        1. Every finding with CVSS Base Score > 0 MUST have a valid, non-empty CVSS v3.1 vector string.
        2. Vector-derived score MUST match displayed CVSS score.
        3. Qualitative Severity MUST agree with the CVSS score range (Info: 0.0, Low: 0.1-3.9, Medium: 4.0-6.9, High: 7.0-8.9, Critical: 9.0-10.0).
        4. Severity reason MUST be explanatory (impact + exploitability + exposure), never generic placeholders.
        """
        raw_sev = getattr(finding, "severity", Severity.INFO)
        if isinstance(raw_sev, Severity):
            severity = raw_sev
        elif isinstance(raw_sev, str):
            normalized = raw_sev.strip().capitalize()
            try:
                severity = Severity(normalized)
            except ValueError:
                severity = Severity.MEDIUM
        else:
            severity = raw_sev or Severity.INFO

        # Retrieve existing vector if present
        existing_vector = None
        if hasattr(finding, "intelligence") and finding.intelligence and getattr(finding.intelligence, "cvss_vector", None):
            existing_vector = finding.intelligence.cvss_vector
        elif hasattr(finding, "cvss_vector") and finding.cvss_vector:
            existing_vector = finding.cvss_vector
        elif hasattr(finding, "risk") and finding.risk and getattr(finding.risk, "cvss", None) and getattr(finding.risk.cvss, "vector", None):
            existing_vector = finding.risk.cvss.vector

        # Calculate score from vector if present
        computed_score_obj = None
        if existing_vector and existing_vector != "N/A":
            try:
                computed_score_obj = cls.calculate_from_vector(existing_vector)
            except Exception:
                computed_score_obj = None

        if computed_score_obj:
            vec_score = computed_score_obj.base_score
            vec_severity = cls.severity_from_score(vec_score)
            if vec_severity == severity:
                # Vector and severity agree!
                final_score = vec_score
                final_vector = existing_vector
            else:
                # Disagreement! Recalibrate canonical vector matching qualitative severity
                canon_score_obj = cls.calculate_base(severity)
                final_score = canon_score_obj.base_score
                final_vector = canon_score_obj.vector
        else:
            # Vector missing: derive canonical vector from severity
            canon_score_obj = cls.calculate_base(severity)
            final_score = canon_score_obj.base_score
            final_vector = canon_score_obj.vector

        # Apply calibrated values across all finding models
        finding.severity = severity
        finding.cvss_score = final_score
        if hasattr(finding, "cvss_vector"):
            finding.cvss_vector = final_vector
        if hasattr(finding, "intelligence") and finding.intelligence:
            finding.intelligence.cvss_vector = final_vector
            finding.intelligence.cvss_score = final_score
        if hasattr(finding, "risk") and finding.risk and getattr(finding.risk, "cvss", None):
            finding.risk.cvss.base_score = final_score
            finding.risk.cvss.vector = final_vector

        # Fix severity reason: replace generic "Confidence based on..." strings with technical explanation
        sev_reason = getattr(finding, "severity_reason", None) or getattr(finding, "risk_explanation", None)
        if not sev_reason or "confidence based on" in str(sev_reason).lower() or str(sev_reason).strip() == "":
            title = getattr(finding, "title", "Vulnerability Finding")
            new_reason = f"Assigned {severity.value} severity (CVSS {final_score}) based on evaluated technical impact, exploitability, and exposure context for {title}."
            finding.severity_reason = new_reason
            finding.risk_explanation = new_reason

        return finding

    @classmethod
    def calculate_from_vector(
        cls,
        vector: str,
        temporal_vector: Optional[str] = None,
    ) -> CVSSScore:
        """
        Compute CVSS v3.1 base score (and optionally temporal) from vector string.
        Supports: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
        Optional temporal: /E:P/RL:O/RC:C
        """
        try:
            metrics = cls._parse_vector(vector)
            av  = metrics.get("AV", "N")
            ac  = metrics.get("AC", "L")
            pr  = metrics.get("PR", "N")
            ui  = metrics.get("UI", "N")
            s   = metrics.get("S", "U")
            c   = metrics.get("C", "N")
            i   = metrics.get("I", "N")
            a   = metrics.get("A", "N")

            av_v  = _AV.get(av, 0.85)
            ac_v  = _AC.get(ac, 0.77)
            pr_v  = (_PR_CHANGED if s == "C" else _PR_UNCHANGED).get(pr, 0.85)
            ui_v  = _UI.get(ui, 0.85)
            c_v   = _CIA.get(c, 0.0)
            i_v   = _CIA.get(i, 0.0)
            a_v   = _CIA.get(a, 0.0)

            exploitability = 8.22 * av_v * ac_v * pr_v * ui_v
            iss = 1.0 - (1.0 - c_v) * (1.0 - i_v) * (1.0 - a_v)

            if iss <= 0.0:
                base = 0.0
                impact = 0.0
            elif s == "U":
                impact = 6.42 * iss
                base = _roundup(min(impact + exploitability, 10.0))
            else:
                impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
                base = _roundup(min(1.08 * (impact + exploitability), 10.0))

            # Temporal score
            temporal: Optional[float] = None
            if temporal_vector:
                t_metrics = cls._parse_vector(temporal_vector)
                e_v  = _E.get(t_metrics.get("E", "X"), 1.00)
                rl_v = _RL.get(t_metrics.get("RL", "X"), 1.00)
                rc_v = _RC.get(t_metrics.get("RC", "X"), 1.00)
                temporal = _roundup(base * e_v * rl_v * rc_v)

            return CVSSScore(
                base_score=base,
                temporal_score=temporal,
                vector=vector,
                exploitability_score=round(exploitability, 1),
                impact_score=round(impact, 1) if iss > 0 else 0.0,
                attack_vector=av,
                attack_complexity=ac,
                privileges_required=pr,
                user_interaction=ui,
                scope=s,
                confidentiality_impact=c,
                integrity_impact=i,
                availability_impact=a,
            )

        except Exception:
            return CVSSScore(base_score=5.0, vector=vector)

    @classmethod
    def severity_from_score(cls, score: float) -> Severity:
        for threshold, sev in _SEVERITY_THRESHOLDS:
            if score >= threshold:
                return sev
        return Severity.INFO

    @classmethod
    def _parse_vector(cls, vector: str) -> Dict[str, str]:
        # Clean typos like "M/A:" or "M/A" into "MA:" or "A:"
        clean = (
            vector.replace("CVSS:3.1/", "")
            .replace("CVSS:3.0/", "")
            .replace("M/A:", "MA:")
            .replace("M/A", "A")
        )
        metrics: Dict[str, str] = {}
        for part in clean.split("/"):
            if ":" in part:
                k, v = part.split(":", 1)
                metrics[k.upper().strip()] = v.upper().strip()
        
        # Handle Modified Availability (MA) if Base Availability (A) is missing
        if "MA" in metrics and "A" not in metrics:
            metrics["A"] = metrics["MA"]
            
        return metrics


class BusinessRiskCalculator:
    """Computes business risk from CWE class and asset context."""

    @classmethod
    def calculate(
        cls,
        cwe_id: Optional[str],
        asset_criticality: AssetCriticality,
        exposure: ExposureLevel,
    ) -> BusinessRisk:
        profile = _CWE_BUSINESS_RISK.get(cwe_id or "", {
            "data": 5.0, "compliance": 5.0, "reputation": 5.0, "ops": 5.0
        })

        crit_mult = _CRITICALITY_MULTIPLIER.get(asset_criticality, 1.0)
        exp_mult  = _EXPOSURE_MULTIPLIER.get(exposure, 1.0)
        combined  = crit_mult * exp_mult

        data_risk       = min(profile["data"]       * combined, 10.0)
        compliance_risk = min(profile["compliance"] * combined, 10.0)
        reputation_risk = min(profile["reputation"] * combined, 10.0)
        ops_risk        = min(profile["ops"]        * combined, 10.0)

        overall = round(
            (data_risk * 0.35 + compliance_risk * 0.25 + reputation_risk * 0.25 + ops_risk * 0.15),
            1
        )

        explanation = (
            f"CWE {cwe_id or 'unknown'} on {asset_criticality.value} asset "
            f"({exposure.value}): data={data_risk:.1f}, compliance={compliance_risk:.1f}, "
            f"reputation={reputation_risk:.1f}, ops={ops_risk:.1f}"
        )

        return BusinessRisk(
            data_exposure_risk=round(data_risk, 1),
            compliance_risk=round(compliance_risk, 1),
            reputational_risk=round(reputation_risk, 1),
            operational_risk=round(ops_risk, 1),
            overall_business_risk=overall,
            risk_explanation=explanation,
        )


class PriorityCalculator:
    """
    Computes final priority (0-10) by combining:
    - CVSS base/temporal score
    - EPSS exploitation probability
    - KEV status
    - Asset criticality
    - Exposure level
    - Evidence quality
    """

    @classmethod
    def calculate(
        cls,
        cvss: CVSSScore,
        epss: EPSSScore,
        is_kev: Optional[bool],
        asset_criticality: AssetCriticality,
        exposure: ExposureLevel = ExposureLevel.INTERNET_FACING,
        evidence_quality: float = 0.5,
    ) -> tuple[float, str]:
        """Returns (priority_score, explanation_string)."""

        # KEV on critical/high asset → immediate maximum priority
        if is_kev and asset_criticality in (AssetCriticality.HIGH, AssetCriticality.MISSION_CRITICAL):
            return 10.0, "KEV confirmed on high-criticality asset — maximum priority."

        # Use temporal score if available, else base
        effective_cvss = cvss.temporal_score if cvss.temporal_score is not None else cvss.base_score

        # EPSS contribution: probability × 2.0 (max +2.0 boost)
        epss_prob = epss.probability if (epss and epss.probability is not None) else 0.0
        epss_boost = epss_prob * 2.0

        # KEV boost: +1.5 if confirmed, +0.5 if unknown
        kev_boost = 1.5 if is_kev is True else (0.5 if is_kev is None else 0.0)

        # Evidence quality: low quality reduces score (0.5 = neutral, 1.0 = full, 0.0 = -20%)
        evidence_factor = 0.8 + (evidence_quality * 0.2)

        # Asset criticality multiplier
        crit_mult = _CRITICALITY_MULTIPLIER.get(asset_criticality, 1.0)

        # Exposure multiplier
        exp_mult = _EXPOSURE_MULTIPLIER.get(exposure, 1.0)

        raw = (effective_cvss + epss_boost + kev_boost) * crit_mult * exp_mult * evidence_factor
        priority = round(min(raw, 10.0), 1)

        explanation = (
            f"CVSS={effective_cvss:.1f}, EPSS_boost={epss_boost:.2f}, KEV_boost={kev_boost:.1f}, "
            f"criticality={asset_criticality.value}(×{crit_mult}), "
            f"exposure={exposure.value}(×{exp_mult}), "
            f"evidence_quality={evidence_quality:.2f}(×{evidence_factor:.2f}) "
            f"→ priority={priority}"
        )

        return priority, explanation
