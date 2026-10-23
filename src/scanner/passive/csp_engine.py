import structlog
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from ..models.finding import Evidence, Severity
from ..models.standards import StandardsRegistry
from .models import PassiveObservation
from ..network.models import HTTPResponse

logger = structlog.get_logger(__name__)


class CSPDirectiveType(Enum):
    SCRIPT = "script-src"
    STYLE = "style-src"
    OBJECT = "object-src"
    DEFAULT = "default-src"
    CONNECT = "connect-src"
    FORM_ACTION = "form-action"
    FRAME_ANCESTORS = "frame-ancestors"
    BASE_URI = "base-uri"
    UPGRADE = "upgrade-insecure-requests"
    SANDBOX = "sandbox"
    WORKER_SRC = "worker-src"
    MANIFEST_SRC = "manifest-src"
    REPORT_URI = "report-uri"
    REPORT_TO = "report-to"
    TRUSTED_TYPES = "trusted-types"
    REQUIRE_TRUSTED_TYPES = "require-trusted-types-for"


@dataclass
class CSPDirective:
    name: str
    values: Set[str]


@dataclass
class CSPContext:
    """Contextual signals extracted from the full CSP policy."""
    has_nonce: bool = False
    has_hash: bool = False
    has_strict_dynamic: bool = False
    has_trusted_types: bool = False
    trusted_types_policy: str = ""  # Raw trusted-types directive value
    require_trusted_types_for: str = ""  # Raw require-trusted-types-for directive value
    has_upgrade_insecure: bool = False
    has_report_uri: bool = False
    has_report_to: bool = False
    has_sandbox: bool = False
    has_frame_ancestors: bool = False
    has_base_uri: bool = False
    object_src_none: bool = False
    default_src_present: bool = False
    unsafe_inline_script: bool = False
    unsafe_eval_script: bool = False
    unsafe_inline_style: bool = False
    wildcard_script: bool = False
    http_script: bool = False
    wildcard_connect: bool = False
    wildcard_form_action: bool = False
    missing_script_src: bool = False
    missing_connect_src: bool = False
    missing_style_src: bool = False
    missing_form_action: bool = False
    missing_worker_src: bool = False
    missing_manifest_src: bool = False
    has_img_src: bool = False
    has_font_src: bool = False
    protections: List[str] = field(default_factory=list)
    weaknesses: List[str] = field(default_factory=list)
    browser_notes: List[str] = field(default_factory=list)
    mitigation_notes: List[str] = field(default_factory=list)


BROWSER_SUPPORT = {
    "strict-dynamic": {
        "chromium": "67+",
        "firefox": "59+",
        "safari": "10+",
        "note": "Modern browsers ignore 'unsafe-inline' when 'strict-dynamic' + nonce/hash are present"
    },
    "nonce": {
        "chromium": "25+",
        "firefox": "4+",
        "safari": "7+",
        "note": "Well supported; overrides 'unsafe-inline' in CSP Level 2+ browsers"
    },
    "hash": {
        "chromium": "25+",
        "firefox": "4+",
        "safari": "7+",
        "note": "Well supported; overrides 'unsafe-inline' in CSP Level 2+ browsers"
    },
    "trusted-types": {
        "chromium": "83+",
        "firefox": "79+",
        "safari": "15.4+",
        "note": "Restricts string-to-code APIs; mitigates DOM XSS even with 'unsafe-eval'"
    },
    "upgrade-insecure-requests": {
        "chromium": "43+",
        "firefox": "39+",
        "safari": "11+",
        "note": "Automatically upgrades HTTP requests to HTTPS"
    },
    "report-uri": {
        "chromium": "25+",
        "firefox": "31+",
        "safari": "7+",
        "note": "Deprecated in favor of 'report-to' but still widely supported"
    },
    "report-to": {
        "chromium": "84+",
        "firefox": "79+",
        "safari": "15.4+",
        "note": "Preferred reporting mechanism; broader than report-uri"
    },
    "sandbox": {
        "chromium": "25+",
        "firefox": "4+",
        "safari": "7+",
        "note": "Supported; restricts form submission and popups"
    },
    "frame-ancestors": {
        "chromium": "40+",
        "firefox": "32+",
        "safari": "9+",
        "note": "Well supported; replaces X-Frame-Options"
    },
    "base-uri": {
        "chromium": "25+",
        "firefox": "31+",
        "safari": "7+",
        "note": "Well supported; prevents base tag injection"
    },
    "worker-src": {
        "chromium": "73+",
        "firefox": "66+",
        "safari": "12+",
        "note": "Restricts Web Worker sources"
    },
    "manifest-src": {
        "chromium": "73+",
        "firefox": "66+",
        "safari": "11.1+",
        "note": "Restricts web app manifest sources"
    }
}


class CSPParser:
    """Parses Content-Security-Policy header strings into structured directives."""

    @staticmethod
    def parse(csp_value: str) -> Dict[str, CSPDirective]:
        if not csp_value:
            return {}

        directives: Dict[str, CSPDirective] = {}
        for raw_directive in csp_value.split(";"):
            tokens = raw_directive.strip().split()
            if not tokens:
                continue
            dir_name = tokens[0].lower()
            dir_values = {t.lower() for t in tokens[1:]}
            directives[dir_name] = CSPDirective(name=dir_name, values=dir_values)
        return directives


class CSPContextAnalyzer:
    """Extracts contextual signals from parsed CSP directives."""

    @staticmethod
    def analyze(directives: Dict[str, CSPDirective]) -> CSPContext:
        ctx = CSPContext()

        script_src = directives.get("script-src", directives.get("default-src", CSPDirective("default-src", set())))
        style_src = directives.get("style-src", directives.get("default-src", CSPDirective("default-src", set())))
        object_src = directives.get("object-src", directives.get("default-src", CSPDirective("default-src", set())))
        connect_src = directives.get("connect-src", directives.get("default-src", CSPDirective("default-src", set())))
        form_action = directives.get("form-action", directives.get("default-src", CSPDirective("default-src", set())))
        img_src = directives.get("img-src", directives.get("default-src", CSPDirective("default-src", set())))
        font_src = directives.get("font-src", directives.get("default-src", CSPDirective("default-src", set())))

        ctx.default_src_present = "default-src" in directives
        ctx.has_nonce = any(v.startswith("'nonce-") for v in script_src.values)
        ctx.has_hash = any(v.startswith("'sha256-") or v.startswith("'sha384-") or v.startswith("'sha512-") for v in script_src.values)
        ctx.has_strict_dynamic = "'strict-dynamic'" in script_src.values
        ctx.has_upgrade_insecure = "upgrade-insecure-requests" in directives
        ctx.has_report_uri = "report-uri" in directives
        ctx.has_report_to = "report-to" in directives
        ctx.has_sandbox = "sandbox" in directives
        ctx.has_frame_ancestors = "frame-ancestors" in directives
        ctx.has_base_uri = "base-uri" in directives
        ctx.object_src_none = "'none'" in object_src.values
        ctx.unsafe_inline_script = "'unsafe-inline'" in script_src.values
        ctx.unsafe_eval_script = "'unsafe-eval'" in script_src.values
        ctx.unsafe_inline_style = "'unsafe-inline'" in style_src.values
        ctx.wildcard_script = "*" in script_src.values or "'*'" in script_src.values
        ctx.http_script = "http:" in script_src.values or "http://" in script_src.values
        ctx.wildcard_connect = "*" in connect_src.values or "'*'" in connect_src.values or "http:" in connect_src.values
        ctx.wildcard_form_action = "*" in form_action.values or "'*'" in form_action.values
        ctx.missing_script_src = "script-src" not in directives and not ctx.default_src_present
        ctx.missing_connect_src = "connect-src" not in directives and not ctx.default_src_present
        ctx.missing_style_src = "style-src" not in directives and not ctx.default_src_present
        ctx.missing_form_action = "form-action" not in directives and not ctx.default_src_present
        ctx.missing_worker_src = "worker-src" not in directives and not ctx.default_src_present
        ctx.missing_manifest_src = "manifest-src" not in directives and not ctx.default_src_present
        ctx.has_img_src = "img-src" in directives or ctx.default_src_present
        ctx.has_font_src = "font-src" in directives or ctx.default_src_present

        # ── Trusted Types deep inspection ─────────────────────────────────
        tt_directive = directives.get("trusted-types", CSPDirective("trusted-types", set()))
        ctx.trusted_types_policy = " ".join(sorted(tt_directive.values)) if tt_directive.values else ""
        ctx.has_trusted_types = bool(tt_directive.values)
        rtt_directive = directives.get("require-trusted-types-for", CSPDirective("require-trusted-types-for", set()))
        ctx.require_trusted_types_for = " ".join(sorted(rtt_directive.values)) if rtt_directive.values else ""

        tt_enforced = False
        if "script" in rtt_directive.values or "'script'" in rtt_directive.values or "all" in rtt_directive.values or "'all'" in rtt_directive.values:
            tt_enforced = True
        if not tt_directive.values and not rtt_directive.values:
            ctx.has_trusted_types = False

        if tt_enforced:
            if "'allow-duplicate-trusted-types'" in tt_directive.values or "allow-duplicate-trusted-types" in tt_directive.values:
                ctx.mitigation_notes.append("Trusted Types is enforced but allows duplicate policies (reduces effectiveness)")
            else:
                ctx.mitigation_notes.append("Trusted Types is fully enforced for script")
        elif ctx.has_trusted_types:
            ctx.mitigation_notes.append("Trusted Types policy declared but not enforced without require-trusted-types-for")

        # Build protections and weaknesses lists
        if ctx.has_nonce:
            ctx.protections.append("script nonce")
        if ctx.has_hash:
            ctx.protections.append("script hash")
        if ctx.has_strict_dynamic:
            ctx.protections.append("strict-dynamic")
        if tt_enforced:
            ctx.protections.append("Trusted Types enforcement")
        elif ctx.has_trusted_types:
            ctx.protections.append("Trusted Types policy (not enforced)")
        if ctx.has_upgrade_insecure:
            ctx.protections.append("upgrade-insecure-requests")
        if ctx.has_report_uri or ctx.has_report_to:
            ctx.protections.append("reporting endpoint")
        if ctx.object_src_none:
            ctx.protections.append("object-src 'none'")
        if ctx.has_base_uri:
            ctx.protections.append("base-uri")
        if ctx.has_frame_ancestors:
            ctx.protections.append("frame-ancestors")
        if ctx.has_sandbox:
            ctx.protections.append("sandbox")
        if not ctx.unsafe_inline_script:
            ctx.protections.append("no unsafe-inline in script-src")
        if not ctx.unsafe_eval_script:
            ctx.protections.append("no unsafe-eval in script-src")
        if not ctx.wildcard_script:
            ctx.protections.append("no wildcard script-src")
        if not ctx.http_script:
            ctx.protections.append("no HTTP script sources")
        if not ctx.wildcard_connect:
            ctx.protections.append("no wildcard connect-src")
        if not ctx.wildcard_form_action:
            ctx.protections.append("no wildcard form-action")
        if ctx.default_src_present:
            ctx.protections.append("default-src fallback")
        if ctx.has_img_src:
            ctx.protections.append("img-src controlled")
        if ctx.has_font_src:
            ctx.protections.append("font-src controlled")

        if ctx.unsafe_inline_script and not (ctx.has_strict_dynamic and (ctx.has_nonce or ctx.has_hash)):
            ctx.weaknesses.append("unsafe-inline in script-src without effective mitigation")
        if ctx.unsafe_eval_script and not tt_enforced:
            ctx.weaknesses.append("unsafe-eval in script-src without Trusted Types enforcement")
        if ctx.unsafe_inline_style:
            ctx.weaknesses.append("unsafe-inline in style-src")
        if ctx.wildcard_script and not ctx.has_strict_dynamic:
            ctx.weaknesses.append("wildcard script-src without strict-dynamic")
        if ctx.http_script:
            ctx.weaknesses.append("HTTP script sources")
        if ctx.wildcard_connect:
            ctx.weaknesses.append("wildcard connect-src")
        if ctx.wildcard_form_action:
            ctx.weaknesses.append("wildcard form-action")
        if not ctx.object_src_none:
            ctx.weaknesses.append("missing object-src 'none'")
        if not ctx.has_base_uri:
            ctx.weaknesses.append("missing base-uri")
        if not ctx.has_frame_ancestors:
            ctx.weaknesses.append("missing frame-ancestors")
        if not ctx.default_src_present:
            ctx.weaknesses.append("missing default-src")
        if ctx.missing_worker_src:
            ctx.weaknesses.append("missing worker-src")
        if ctx.missing_manifest_src:
            ctx.weaknesses.append("missing manifest-src")
        if not ctx.has_report_uri and not ctx.has_report_to:
            ctx.weaknesses.append("missing reporting endpoint")
        if ctx.has_trusted_types and not tt_enforced:
            ctx.weaknesses.append("Trusted Types policy declared but not enforced")
        if not ctx.has_img_src:
            ctx.weaknesses.append("missing img-src fallback")
        if not ctx.has_font_src:
            ctx.weaknesses.append("missing font-src fallback")

        # Browser compatibility notes
        if ctx.has_strict_dynamic:
            ctx.browser_notes.append("strict-dynamic: Chromium 67+, Firefox 59+, Safari 10+ (modern browsers ignore unsafe-inline when nonce/hash present)")
        if ctx.has_nonce or ctx.has_hash:
            ctx.browser_notes.append("nonce/hash: Chromium 25+, Firefox 4+, Safari 7+ (overrides unsafe-inline in CSP2+)")
        if tt_enforced:
            ctx.browser_notes.append("Trusted Types enforcement: Chromium 83+, Firefox 79+, Safari 15.4+")
        elif ctx.has_trusted_types:
            ctx.browser_notes.append("Trusted Types policy present but not enforced without require-trusted-types-for")
        if ctx.has_upgrade_insecure:
            ctx.browser_notes.append("upgrade-insecure-requests: Chromium 43+, Firefox 39+, Safari 11+")
        if ctx.has_report_to:
            ctx.browser_notes.append("report-to: Chromium 84+, Firefox 79+, Safari 15.4+")
        if ctx.has_report_uri and not ctx.has_report_to:
            ctx.browser_notes.append("report-uri: deprecated but widely supported; consider migrating to report-to")
        if ctx.has_sandbox:
            ctx.browser_notes.append("sandbox: supported with minor browser quirks")
        if ctx.unsafe_inline_script and not (ctx.has_strict_dynamic and (ctx.has_nonce or ctx.has_hash)):
            ctx.browser_notes.append("unsafe-inline without strict-dynamic/nonce-hash: active XSS risk in all modern browsers")
        if ctx.wildcard_script and not ctx.has_strict_dynamic:
            ctx.browser_notes.append("wildcard script-src: allows scripts from any origin, high XSS risk")
        if ctx.http_script:
            ctx.browser_notes.append("HTTP script sources: vulnerable to MITM attacks, should use HTTPS only")

        return ctx


class CSPReasoningEngine:
    """
    Context-aware CSP reasoning engine.
    
    Evaluates the entire policy holistically rather than individual directives.
    Considers directive interactions, modern CSP features, and browser compatibility.
    Separates policy quality score from vulnerability severity classification.
    """

    WEIGHT_SCRIPT_NONCE = 18
    WEIGHT_SCRIPT_HASH = 14
    WEIGHT_STRICT_DYNAMIC = 22
    WEIGHT_TRUSTED_TYPES_ENFORCED = 18
    WEIGHT_TRUSTED_TYPES_PRESENT = 8
    WEIGHT_UPGRADE_INSECURE = 10
    WEIGHT_REPORTING = 5
    WEIGHT_OBJECT_NONE = 12
    WEIGHT_BASE_URI = 10
    WEIGHT_FRAME_ANCESTORS = 10
    WEIGHT_SANDBOX = 10
    WEIGHT_NO_UNSAFE_INLINE_SCRIPT = 10
    WEIGHT_NO_UNSAFE_EVAL_SCRIPT = 8
    WEIGHT_NO_WILDCARD_SCRIPT = 10
    WEIGHT_NO_HTTP_SCRIPT = 5
    WEIGHT_NO_WILDCARD_CONNECT = 8
    WEIGHT_NO_WILDCARD_FORM = 5
    WEIGHT_DEFAULT_SRC = 10
    WEIGHT_IMG_SRC = 5
    WEIGHT_FONT_SRC = 5

    PENALTY_UNSAFE_INLINE_SCRIPT = 20
    PENALTY_UNSAFE_EVAL_SCRIPT = 10
    PENALTY_WILDCARD_SCRIPT = 18
    PENALTY_HTTP_SCRIPT = 10
    PENALTY_WILDCARD_CONNECT = 12
    PENALTY_WILDCARD_FORM = 8
    PENALTY_MISSING_OBJECT_NONE = 8
    PENALTY_MISSING_BASE_URI = 8
    PENALTY_MISSING_FRAME_ANCESTORS = 8
    PENALTY_MISSING_DEFAULT_SRC = 12
    PENALTY_MISSING_WORKER_SRC = 4
    PENALTY_MISSING_MANIFEST_SRC = 4
    PENALTY_TT_NOT_ENFORCED = 8
    PENALTY_MISSING_IMG_SRC = 4
    PENALTY_MISSING_FONT_SRC = 4

    @staticmethod
    def evaluate(csp_value: str, endpoint: str, html_body: Optional[str] = None) -> PassiveObservation:
        if not csp_value:
            return PassiveObservation(
                plugin_id="PASS-006-CSP-REASONING",
                observation_type="csp_reasoning",
                title="Missing Content-Security-Policy Header",
                description="No Content-Security-Policy header was detected. CSP is essential for mitigating XSS and data injection attacks.",
                endpoint=endpoint,
                severity=Severity.LOW,
                evidence=[Evidence(type="missing_csp", description="CSP header absent", data={"header": "Content-Security-Policy"})],
                remediation="Implement a Content-Security-Policy header starting with 'default-src \\'self\\''.",
                **StandardsRegistry.get("missing_csp").__dict__
            )

        directives = CSPParser.parse(csp_value)
        ctx = CSPContextAnalyzer.analyze(directives)

        score = 0
        score += CSPReasoningEngine.WEIGHT_SCRIPT_NONCE if ctx.has_nonce else 0
        score += CSPReasoningEngine.WEIGHT_SCRIPT_HASH if ctx.has_hash else 0
        score += CSPReasoningEngine.WEIGHT_STRICT_DYNAMIC if ctx.has_strict_dynamic else 0
        if ctx.has_trusted_types:
            tt_enforced = "script" in ctx.require_trusted_types_for or "all" in ctx.require_trusted_types_for
            score += CSPReasoningEngine.WEIGHT_TRUSTED_TYPES_ENFORCED if tt_enforced else CSPReasoningEngine.WEIGHT_TRUSTED_TYPES_PRESENT
        score += CSPReasoningEngine.WEIGHT_UPGRADE_INSECURE if ctx.has_upgrade_insecure else 0
        score += CSPReasoningEngine.WEIGHT_REPORTING if ctx.has_report_uri or ctx.has_report_to else 0
        score += CSPReasoningEngine.WEIGHT_OBJECT_NONE if ctx.object_src_none else 0
        score += CSPReasoningEngine.WEIGHT_BASE_URI if ctx.has_base_uri else 0
        score += CSPReasoningEngine.WEIGHT_FRAME_ANCESTORS if ctx.has_frame_ancestors else 0
        score += CSPReasoningEngine.WEIGHT_SANDBOX if ctx.has_sandbox else 0
        score += CSPReasoningEngine.WEIGHT_NO_UNSAFE_INLINE_SCRIPT if not ctx.unsafe_inline_script else 0
        score += CSPReasoningEngine.WEIGHT_NO_UNSAFE_EVAL_SCRIPT if not ctx.unsafe_eval_script else 0
        score += CSPReasoningEngine.WEIGHT_NO_WILDCARD_SCRIPT if not ctx.wildcard_script else 0
        score += CSPReasoningEngine.WEIGHT_NO_HTTP_SCRIPT if not ctx.http_script else 0
        score += CSPReasoningEngine.WEIGHT_NO_WILDCARD_CONNECT if not ctx.wildcard_connect else 0
        score += CSPReasoningEngine.WEIGHT_NO_WILDCARD_FORM if not ctx.wildcard_form_action else 0
        score += CSPReasoningEngine.WEIGHT_DEFAULT_SRC if ctx.default_src_present else 0
        score += CSPReasoningEngine.WEIGHT_IMG_SRC if ctx.has_img_src else 0
        score += CSPReasoningEngine.WEIGHT_FONT_SRC if ctx.has_font_src else 0

        penalty = 0
        if ctx.unsafe_inline_script and not (ctx.has_strict_dynamic and (ctx.has_nonce or ctx.has_hash)):
            penalty += CSPReasoningEngine.PENALTY_UNSAFE_INLINE_SCRIPT
        if ctx.unsafe_eval_script and not (ctx.has_trusted_types and ("script" in ctx.require_trusted_types_for or "all" in ctx.require_trusted_types_for)):
            penalty += CSPReasoningEngine.PENALTY_UNSAFE_EVAL_SCRIPT
        if ctx.wildcard_script and not ctx.has_strict_dynamic:
            penalty += CSPReasoningEngine.PENALTY_WILDCARD_SCRIPT
        if ctx.http_script:
            penalty += CSPReasoningEngine.PENALTY_HTTP_SCRIPT
        if ctx.wildcard_connect:
            penalty += CSPReasoningEngine.PENALTY_WILDCARD_CONNECT
        if ctx.wildcard_form_action:
            penalty += CSPReasoningEngine.PENALTY_WILDCARD_FORM
        if not ctx.object_src_none:
            penalty += CSPReasoningEngine.PENALTY_MISSING_OBJECT_NONE
        if not ctx.has_base_uri:
            penalty += CSPReasoningEngine.PENALTY_MISSING_BASE_URI
        if not ctx.has_frame_ancestors:
            penalty += CSPReasoningEngine.PENALTY_MISSING_FRAME_ANCESTORS
        if not ctx.default_src_present:
            penalty += CSPReasoningEngine.PENALTY_MISSING_DEFAULT_SRC
        if ctx.missing_worker_src:
            penalty += CSPReasoningEngine.PENALTY_MISSING_WORKER_SRC
        if ctx.missing_manifest_src:
            penalty += CSPReasoningEngine.PENALTY_MISSING_MANIFEST_SRC
        if ctx.has_trusted_types and not ("script" in ctx.require_trusted_types_for or "all" in ctx.require_trusted_types_for):
            penalty += CSPReasoningEngine.PENALTY_TT_NOT_ENFORCED
        if not ctx.has_img_src:
            penalty += CSPReasoningEngine.PENALTY_MISSING_IMG_SRC
        if not ctx.has_font_src:
            penalty += CSPReasoningEngine.PENALTY_MISSING_FONT_SRC

        tt_enforced = "script" in ctx.require_trusted_types_for or "all" in ctx.require_trusted_types_for
        strong_mitigations = sum([
            ctx.has_strict_dynamic,
            ctx.has_nonce or ctx.has_hash,
            tt_enforced,
            ctx.has_upgrade_insecure,
        ])
        if strong_mitigations >= 2:
            penalty = int(penalty * 0.65)
        elif strong_mitigations >= 1:
            penalty = int(penalty * 0.8)

        final_score = max(0, min(100, score - penalty))

        severity, title, description, reasoning = CSPReasoningEngine._interpret_score(
            final_score, ctx, csp_value
        )

        evidence = [
            Evidence(
                type="csp_policy_assessment",
                description="Holistic CSP policy evaluation",
                data={
                    "raw_csp": csp_value,
                    "policy_quality_score": final_score,
                    "protections": ctx.protections,
                    "weaknesses": ctx.weaknesses,
                    "reasoning": reasoning,
                    "browser_compatibility": ctx.browser_notes,
                    "mitigation_notes": ctx.mitigation_notes,
                    "trusted_types_policy": ctx.trusted_types_policy,
                    "require_trusted_types_for": ctx.require_trusted_types_for,
                    "directives": {k: list(v.values) for k, v in directives.items()}
                }
            )
        ]

        remediation = CSPReasoningEngine._build_remediation(ctx, final_score)

        return PassiveObservation(
            plugin_id="PASS-006-CSP-REASONING",
            observation_type="csp_policy_assessment",
            title=title,
            description=description,
            endpoint=endpoint,
            severity=severity,
            evidence=evidence,
            remediation=remediation,
            **StandardsRegistry.get("missing_csp").__dict__
        )

    @staticmethod
    def _interpret_score(score: int, ctx: CSPContext, raw_csp: str) -> Tuple[Severity, str, str, str]:
        tt_enforced = "script" in ctx.require_trusted_types_for or "all" in ctx.require_trusted_types_for
        tt_present = ctx.has_trusted_types
        has_strong_mitigations = ctx.has_nonce or ctx.has_hash or ctx.has_strict_dynamic or tt_enforced

        if score < 20:
            title = "CSP Policy Weakness: Insufficient Protection Against XSS"
            reasoning = (
                f"The policy scored {score}/100. "
                f"It allows dangerous script execution vectors "
                f"and lacks modern mitigations like nonces, hashes, strict-dynamic, or Trusted Types. "
                f"Modern browsers enforce strict-dynamic and ignore unsafe-inline when nonces/hashes are present, "
                f"but this policy does not use those mechanisms."
            )
            description = (
                f"The Content-Security-Policy scored {score}/100 and provides minimal XSS protection. "
                f"The policy allows dangerous script execution vectors including "
                f"{'unsafe-inline, ' if ctx.unsafe_inline_script else ''}"
                f"{'unsafe-eval, ' if ctx.unsafe_eval_script else ''}"
                f"{'wildcard sources, ' if ctx.wildcard_script else ''}"
                f"{'HTTP sources, ' if ctx.http_script else ''}"
                f"and lacks modern mitigations like nonces, hashes, or strict-dynamic. "
                f"Immediate remediation is required."
            )
            return Severity.HIGH, title, description, reasoning

        if score < 40:
            title = "CSP Policy Weakness: Moderate Protection with Notable Gaps"
            reasoning = (
                f"The policy scored {score}/100. "
                f"{'Nonces/hashes or strict-dynamic are present, ' if has_strong_mitigations else 'Some directives exist, '}"
                f"but the policy still contains significant weaknesses including "
                f"{'unsafe-inline in script-src without strict-dynamic mitigation, ' if ctx.unsafe_inline_script and not (ctx.has_strict_dynamic and (ctx.has_nonce or ctx.has_hash)) else ''}"
                f"{'unsafe-eval without Trusted Types, ' if ctx.unsafe_eval_script and not tt_enforced else ''}"
                f"{'wildcard connect-src, ' if ctx.wildcard_connect else ''}"
                f"{'missing object-src none, ' if not ctx.object_src_none else ''}"
                f"reducing effectiveness against XSS attacks."
            )
            description = (
                f"The Content-Security-Policy scored {score}/100 and provides partial XSS protection. "
                f"While {'nonces/hashes or strict-dynamic are present' if has_strong_mitigations else 'some directives exist'}, "
                f"the policy still contains significant weaknesses including "
                f"{'unsafe-inline in script-src' if ctx.unsafe_inline_script and not (ctx.has_strict_dynamic and (ctx.has_nonce or ctx.has_hash)) else ''}"
                f"{'unsafe-eval without Trusted Types' if ctx.unsafe_eval_script and not tt_enforced else ''}"
                f"{'wildcard connect-src' if ctx.wildcard_connect else ''}"
                f"{'missing object-src none' if not ctx.object_src_none else ''}"
                f". These gaps reduce the policy's effectiveness against XSS attacks."
            )
            return Severity.MEDIUM, title, description, reasoning

        if score < 60:
            title = "CSP Policy Notice: Good Protection with Minor Weaknesses"
            reasoning = (
                f"The policy scored {score}/100. "
                f"Modern mitigations are present (nonces/hashes/strict-dynamic), "
                f"but minor issues remain including "
                f"{'unsafe-inline in style-src, ' if ctx.unsafe_inline_style else ''}"
                f"{'missing reporting endpoints, ' if not ctx.has_report_uri and not ctx.has_report_to else ''}"
                f"{'missing worker-src, ' if ctx.missing_worker_src else ''}"
                f"which do not significantly weaken XSS protection but should be addressed."
            )
            description = (
                f"The Content-Security-Policy scored {score}/100 and provides good XSS protection. "
                f"Modern mitigations {'are present (nonces/hashes/strict-dynamic)' if has_strong_mitigations else 'are partially present'}. "
                f"Minor issues include "
                f"{'unsafe-inline in style-src' if ctx.unsafe_inline_style else ''}"
                f"{'missing reporting endpoints' if not ctx.has_report_uri and not ctx.has_report_to else ''}"
                f"{'missing worker-src' if ctx.missing_worker_src else ''}"
                f". These do not significantly weaken XSS protection but should be addressed."
            )
            return Severity.LOW, title, description, reasoning

        title = "CSP Policy: Strong Protection"
        reasoning = (
            f"The policy scored {score}/100. "
            f"It uses modern best practices including "
            f"{'nonces/hashes, ' if ctx.has_nonce or ctx.has_hash else ''}"
            f"{'strict-dynamic, ' if ctx.has_strict_dynamic else ''}"
            f"{'Trusted Types, ' if ctx.has_trusted_types else ''}"
            f"{'upgrade-insecure-requests, ' if ctx.has_upgrade_insecure else ''}"
            f"{'reporting endpoints, ' if ctx.has_report_uri or ctx.has_report_to else ''}"
            f"{'sandbox, ' if ctx.has_sandbox else ''}"
            f"effectively mitigating XSS and code injection risks."
        )
        description = (
            f"The Content-Security-Policy scored {score}/100 and provides strong XSS protection. "
            f"The policy uses modern best practices including "
            f"{'nonces/hashes' if ctx.has_nonce or ctx.has_hash else ''}"
            f"{'strict-dynamic' if ctx.has_strict_dynamic else ''}"
            f"{'Trusted Types' if ctx.has_trusted_types else ''}"
            f"{'upgrade-insecure-requests' if ctx.has_upgrade_insecure else ''}"
            f"{'reporting endpoints' if ctx.has_report_uri or ctx.has_report_to else ''}"
            f"{'sandbox' if ctx.has_sandbox else ''}"
            f". The policy effectively mitigates XSS and code injection risks."
        )
        return Severity.INFO, title, description, reasoning

    @staticmethod
    def _build_remediation(ctx: CSPContext, score: int) -> str:
        steps = []
        tt_enforced = "script" in ctx.require_trusted_types_for or "all" in ctx.require_trusted_types_for

        if ctx.unsafe_inline_script and not (ctx.has_strict_dynamic and (ctx.has_nonce or ctx.has_hash)):
            steps.append("Remove 'unsafe-inline' from script-src and implement nonces or cryptographic hashes")
        if ctx.unsafe_eval_script and not tt_enforced:
            steps.append("Remove 'unsafe-eval' from script-src or enforce Trusted Types with require-trusted-types-for 'script'")
        if ctx.wildcard_script and not ctx.has_strict_dynamic:
            steps.append("Replace wildcard (*) in script-src with explicit trusted origins or use 'strict-dynamic'")
        if ctx.http_script:
            steps.append("Remove HTTP sources from script-src and enforce HTTPS-only origins")
        if ctx.wildcard_connect:
            steps.append("Restrict connect-src to specific trusted origins instead of wildcard")
        if ctx.wildcard_form_action:
            steps.append("Restrict form-action to specific trusted origins")
        if not ctx.object_src_none:
            steps.append("Set object-src to 'none' to prevent legacy plugin execution")
        if not ctx.has_base_uri:
            steps.append("Add base-uri 'self' to prevent base tag injection")
        if not ctx.has_frame_ancestors:
            steps.append("Add frame-ancestors 'self' to prevent clickjacking")
        if not ctx.default_src_present:
            steps.append("Add default-src 'self' as a fallback for unspecified directives")
        if not ctx.has_report_uri and not ctx.has_report_to:
            steps.append("Add report-uri or report-to for CSP violation monitoring")
        if ctx.has_trusted_types and not tt_enforced:
            steps.append("Add require-trusted-types-for 'script' to enforce Trusted Types policy")
        if ctx.has_strict_dynamic and not ctx.has_nonce and not ctx.has_hash:
            steps.append("strict-dynamic requires nonces or hashes — add nonce-* or sha*-* values to script-src")
        if not ctx.has_img_src:
            steps.append("Add img-src directive to restrict image sources")
        if not ctx.has_font_src:
            steps.append("Add font-src directive to restrict font sources")

        if not steps:
            return "No immediate remediation required. Policy meets current best practices."

        if score >= 75:
            steps.append("Continue monitoring CSP violations and refine policy as needed")
        elif score >= 50:
            steps.append("Address remaining gaps to strengthen XSS protection")
        else:
            steps.append("Prioritize CSP remediation as a critical security control")

        return ". ".join(steps) + "."


class CSPReasoningPlugin:
    """Context-aware CSP reasoning plugin that evaluates the entire policy holistically."""

    @property
    def metadata(self):
        from .models import PluginMetadata
        return PluginMetadata(
            id="PASS-006",
            name="Context-Aware CSP Reasoning Engine",
            description="Evaluates the entire Content-Security-Policy holistically, considering directive interactions, modern mitigations (nonces, hashes, strict-dynamic, Trusted Types), and browser compatibility.",
            version="2.0.0"
        )

    def analyze(self, response: HTTPResponse) -> List[PassiveObservation]:
        observations: List[PassiveObservation] = []
        url_lower = response.url.lower()

        if any(url_lower.endswith(ext) or f"{ext}?" in url_lower for ext in [
            '.otf', '.ttf', '.woff', '.woff2', '.eot', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.css', '.mp4', '.webm', '.map', '.js'
        ]):
            return observations

        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        csp_value = headers_lower.get("content-security-policy")

        if not csp_value:
            observations.append(
                PassiveObservation(
                    plugin_id=self.metadata.id,
                    observation_type="csp_policy_assessment",
                    title="Missing Content-Security-Policy Header",
                    description="No Content-Security-Policy header was detected. CSP is essential for mitigating XSS and data injection attacks.",
                    endpoint=response.url,
                    severity=Severity.LOW,
                    evidence=[Evidence(type="missing_csp", description="CSP header absent", data={"header": "Content-Security-Policy"})],
                    remediation="Implement a Content-Security-Policy header starting with 'default-src \\'self\\''.",
                    **StandardsRegistry.get("missing_csp").__dict__
                )
            )
            return observations

        observation = CSPReasoningEngine.evaluate(csp_value, response.url)
        observations.append(observation)

        return observations
