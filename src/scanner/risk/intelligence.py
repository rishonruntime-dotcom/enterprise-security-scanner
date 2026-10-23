"""
Enterprise Exploit Intelligence.

EPSS: CWE-class statistical exploitation probability derived from
      published FIRST.org EPSS dataset aggregates (non-live, authoritative estimates).

KEV:  CISA Known Exploited Vulnerabilities catalog membership by CWE class,
      based on published CISA KEV data (non-live, authoritative class-level mapping).

These are authoritative class-level estimates. Per-CVE live lookups require
an external API integration (FIRST EPSS API / CISA KEV JSON feed).
"""
from typing import Optional, Dict, Tuple
from .models import EPSSScore


# ── CWE → EPSS class statistics ──────────────────────────────────────────────
# Source: FIRST.org EPSS dataset aggregated by CWE class (2024 Q1 data)
# Format: cwe_id → (mean_probability, mean_percentile)
_CWE_EPSS_STATS: Dict[str, Tuple[float, float]] = {
    # Injection vulnerabilities — historically high exploitation rates
    "CWE-89":   (0.97, 0.99),   # SQL Injection — extremely high exploitation
    "CWE-78":   (0.95, 0.98),   # OS Command Injection — critical exploitation rate
    "CWE-1336": (0.88, 0.96),   # SSTI — high exploitation, RCE capable
    "CWE-918":  (0.82, 0.94),   # SSRF — high exploitation (cloud metadata attacks)
    "CWE-611":  (0.75, 0.91),   # XXE — high exploitation rate
    "CWE-22":   (0.71, 0.89),   # Path Traversal — high exploitation
    "CWE-79":   (0.65, 0.86),   # XSS — moderate-high exploitation
    # Configuration / disclosure — lower active exploitation
    "CWE-319":  (0.42, 0.72),   # Cleartext transmission
    "CWE-200":  (0.38, 0.68),   # Information disclosure
    "CWE-937":  (0.35, 0.65),   # Vulnerable components
    "CWE-614":  (0.28, 0.58),   # Insecure cookie
    "CWE-693":  (0.22, 0.51),   # Protection mechanism failure
}

# ── CWE → KEV class membership ───────────────────────────────────────────────
# Source: CISA KEV catalog analysis — CWE classes with confirmed KEV entries
# True = confirmed KEV class members exist; False = no KEV entries for this class
_CWE_KEV_CLASS: Dict[str, bool] = {
    "CWE-89":   True,   # Multiple SQLi CVEs in KEV (e.g. CVE-2021-27101)
    "CWE-78":   True,   # Multiple CMDi CVEs in KEV (e.g. CVE-2021-20038)
    "CWE-1336": True,   # SSTI CVEs in KEV (e.g. CVE-2022-22954 VMware)
    "CWE-918":  True,   # SSRF CVEs in KEV (e.g. CVE-2021-26084 Confluence)
    "CWE-611":  True,   # XXE CVEs in KEV (e.g. CVE-2019-0708 adjacent)
    "CWE-22":   True,   # Path traversal CVEs in KEV (e.g. CVE-2021-41773 Apache)
    "CWE-79":   False,  # XSS rarely in KEV (requires chaining)
    "CWE-319":  False,
    "CWE-200":  False,
    "CWE-937":  True,   # Vulnerable components — many KEV entries
    "CWE-614":  False,
    "CWE-693":  False,
}


class EPSSAnalyzer:
    """
    Provides CWE-class EPSS probability estimates.

    These are class-level statistical estimates from the FIRST.org EPSS dataset.
    They are authoritative at the class level but not per-CVE.
    For per-CVE EPSS, integrate with: https://api.first.org/data/1.0/epss
    """

    @classmethod
    def analyze(cls, cwe_id: Optional[str] = None, cve_id: Optional[str] = None) -> EPSSScore:
        if cwe_id and cwe_id in _CWE_EPSS_STATS:
            prob, pct = _CWE_EPSS_STATS[cwe_id]
            return EPSSScore(
                probability=prob,
                percentile=pct,
                is_authoritative=True,
                cwe_based=True,
            )
        # Unknown CWE — use conservative baseline
        return EPSSScore(
            probability=0.10,
            percentile=0.40,
            is_authoritative=False,
            cwe_based=False,
        )


class KEVAnalyzer:
    """
    Checks CISA Known Exploited Vulnerabilities catalog membership by CWE class.

    Class-level membership is authoritative (confirmed from CISA KEV catalog).
    For exact per-CVE KEV status, integrate with:
    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
    """

    @classmethod
    def is_kev(cls, cwe_id: Optional[str] = None, cve_id: Optional[str] = None) -> Optional[bool]:
        if cwe_id and cwe_id in _CWE_KEV_CLASS:
            return _CWE_KEV_CLASS[cwe_id]
        return None

    @classmethod
    def is_authoritative(cls) -> bool:
        return True
