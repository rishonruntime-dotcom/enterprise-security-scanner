"""Context-aware cookie security analysis with enhanced intelligence."""
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from ...interfaces.passive import PassivePluginInterface
from ...passive.models import PluginMetadata, PassiveObservation
from ...network.models import Cookie, HTTPResponse
from ...models.finding import Evidence, Severity
from ...models.standards import StandardsRegistry


@dataclass(frozen=True)
class CookieContext:
    role: str
    first_party: bool
    persistent: bool
    client_readable_expected: bool
    cookie_type: str = "unknown"
    same_site_strength: str = "missing"
    has_host_prefix: bool = False
    has_secure_prefix: bool = False
    security_score: float = 0.0


class CookieSecurityAnalyzer:
    _SESSION_TOKENS = (
        "session", "sess", "sid", "phpsessid", "aspsessionid",
        "jsessionid", "sessionid", "sessid", "usersession"
    )
    _AUTH_TOKENS = (
        "auth", "token", "jwt", "login", "identity", "access",
        "refresh", "bearer", "credentials", "user_token", "api_key"
    )
    _OAUTH_TOKENS = (
        "oauth", "oauth2", "access_token", "refresh_token", "id_token",
        "authorization", "code", "state"
    )
    _CLIENT_READABLE_TOKENS = (
        "csrf", "xsrf", "nonce", "theme", "lang", "locale",
        "consent", "preference", "settings", "ui"
    )
    _ANALYTICS_TOKENS = (
        "_ga", "_gid", "_gat", "_gcl_au", "_fbp", "analytics",
        "amplitude", "mixpanel", "segment", "heap", "hotjar"
    )
    _THIRD_PARTY_INDICATORS = (
        "doubleclick", "googlead", "facebook", "twitter", "amazon",
        "ads", "tracking", "pixel", "taboola", "outbrain"
    )

    @classmethod
    def _detect_cookie_type(cls, name: str, role: str) -> str:
        lower = name.lower()
        if any(t in lower for t in cls._OAUTH_TOKENS):
            return "oauth"
        if any(t in lower for t in cls._AUTH_TOKENS):
            return "authentication"
        if any(t in lower for t in cls._SESSION_TOKENS):
            return "session"
        if any(t in lower for t in cls._ANALYTICS_TOKENS):
            return "analytics"
        if any(t in lower for t in cls._THIRD_PARTY_INDICATORS):
            return "third_party"
        if role == "client-readable security or preference":
            return "functional"
        if role == "application":
            return "application"
        return "unknown"

    @classmethod
    def _assess_same_site_strength(cls, same_site: Optional[str]) -> str:
        if not same_site:
            return "missing"
        val = same_site.lower()
        if val == "strict":
            return "strict"
        if val == "lax":
            return "lax"
        if val == "none":
            return "none"
        return "missing"

    @classmethod
    def _calculate_security_score(
        cls,
        secure: bool,
        http_only: bool,
        same_site: Optional[str],
        same_site_strength: str,
        has_host_prefix: bool,
        has_secure_prefix: bool,
        cookie_type: str,
        first_party: bool,
        persistent: bool,
    ) -> float:
        score = 0.0
        score += 0.25 if secure else 0.0
        score += 0.20 if http_only else 0.0

        if same_site_strength == "strict":
            score += 0.25
        elif same_site_strength == "lax":
            score += 0.15
        elif same_site_strength == "none":
            score += 0.05

        if has_host_prefix:
            score += 0.15
        elif has_secure_prefix:
            score += 0.10

        if cookie_type in ("authentication", "oauth", "session"):
            score += 0.05 if first_party else 0.0
            if persistent and same_site_strength != "missing":
                score += 0.05
        elif cookie_type == "analytics":
            score += 0.03
        elif cookie_type == "third_party":
            score += 0.02

        return min(1.0, max(0.0, score))

    @classmethod
    def classify(cls, cookie: Cookie, response_url: str) -> CookieContext:
        name = cookie.name.lower()
        host = (urlparse(response_url).hostname or "").lower()
        domain = (cookie.domain or "").lstrip(".").lower()
        first_party = not domain or host == domain or host.endswith(f".{domain}")
        expires = cookie.expires
        if expires and expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        persistent = bool(cookie.max_age and cookie.max_age > 0) or bool(expires and expires > datetime.now(timezone.utc))
        client_readable = any(token in name for token in cls._CLIENT_READABLE_TOKENS)

        if any(token in name for token in cls._AUTH_TOKENS) or any(token in name for token in cls._OAUTH_TOKENS) or any(token in name for token in cls._SESSION_TOKENS):
            role = "authentication/session"
        elif any(token in name for token in cls._ANALYTICS_TOKENS):
            role = "analytics"
        elif client_readable:
            role = "client-readable security or preference"
        else:
            role = "application"

        cookie_type = cls._detect_cookie_type(cookie.name, role)
        same_site_strength = cls._assess_same_site_strength(cookie.same_site)
        has_host_prefix = cookie.name.startswith("__Host-")
        has_secure_prefix = cookie.name.startswith("__Secure-")
        security_score = cls._calculate_security_score(
            secure=cookie.secure,
            http_only=cookie.http_only,
            same_site=cookie.same_site,
            same_site_strength=same_site_strength,
            has_host_prefix=has_host_prefix,
            has_secure_prefix=has_secure_prefix,
            cookie_type=cookie_type,
            first_party=first_party,
            persistent=persistent,
        )

        return CookieContext(
            role=role,
            first_party=first_party,
            persistent=persistent,
            client_readable_expected=client_readable,
            cookie_type=cookie_type,
            same_site_strength=same_site_strength,
            has_host_prefix=has_host_prefix,
            has_secure_prefix=has_secure_prefix,
            security_score=round(security_score, 2),
        )

    @classmethod
    def analyze(cls, cookie: Cookie, response_url: str) -> tuple[list[str], Severity | None, CookieContext, str | None]:
        context = cls.classify(cookie, response_url)
        issues: list[str] = []
        https = urlparse(response_url).scheme.lower() == "https"
        same_site = (cookie.same_site or "").lower()

        if same_site == "none" and not cookie.secure:
            return [], None, context, "SameSite=None without Secure is rejected by modern browsers."

        if cookie.name.startswith("__Host-"):
            prefix_issues = []
            if not cookie.secure:
                prefix_issues.append("__Host- prefix without Secure")
            if cookie.domain:
                prefix_issues.append("__Host- prefix with Domain")
            if cookie.path != "/":
                prefix_issues.append("__Host- prefix without Path=/")
            if prefix_issues:
                return prefix_issues, Severity.INFO, context, "The browser rejects this cookie because invalid __Host- prefix semantics are rejected."
        if cookie.name.startswith("__Secure-") and not cookie.secure:
            return ["__Secure- prefix without Secure"], Severity.INFO, context, "The browser rejects this cookie because invalid __Secure- prefix semantics are rejected."

        if https and not cookie.secure:
            issues.append("Secure")
        if not cookie.http_only and not context.client_readable_expected:
            issues.append("HttpOnly")

        sensitive = context.cookie_type in ("session", "authentication", "oauth")
        if sensitive and context.persistent:
            if not same_site:
                issues.append("SameSite")
            elif same_site == "none":
                issues.append("SameSite=None")

        if not issues:
            return issues, None, context, None

        if sensitive and {"Secure", "HttpOnly"}.issubset(issues):
            severity = Severity.HIGH
        elif sensitive and "Secure" in issues:
            severity = Severity.HIGH if context.persistent else Severity.MEDIUM
        elif sensitive and "HttpOnly" in issues:
            severity = Severity.MEDIUM
        elif sensitive and ("SameSite" in issues or "SameSite=None" in issues):
            severity = Severity.LOW
        elif not context.first_party:
            severity = Severity.INFO
        elif "Secure" in issues:
            severity = Severity.LOW
        else:
            severity = Severity.INFO
        return issues, severity, context, None


class InsecureCookiePlugin(PassivePluginInterface):
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            id="PASS-002",
            name="Context-Aware Cookie Security Analyzer",
            description="Evaluates cookie flags using role, party context, persistence, SameSite, __Host-/__Secure- prefix semantics, and security scoring.",
        )

    def analyze(self, response: HTTPResponse) -> List[PassiveObservation]:
        observations: List[PassiveObservation] = []
        for cookie in response.cookies:
            issues, severity, context, browser_note = CookieSecurityAnalyzer.analyze(cookie, response.url)
            if not issues or severity is None:
                continue
            if "Secure" in issues and "HttpOnly" not in issues:
                metadata = StandardsRegistry.get("cookie_missing_secure")
            elif "HttpOnly" in issues and "Secure" not in issues:
                metadata = StandardsRegistry.get("cookie_missing_httponly")
            else:
                metadata = StandardsRegistry.get("cookie_missing_both")
            scope = "first-party" if context.first_party else "third-party"
            observations.append(PassiveObservation(
                plugin_id=self.metadata.id,
                observation_type="cookie_security_context",
                title=f"Cookie Security Configuration: {cookie.name}",
                endpoint=response.url,
                description=(
                    f"The {scope} {context.cookie_type} cookie '{cookie.name}' is missing: {', '.join(issues)}. "
                    f"Persistence: {'persistent' if context.persistent else 'session'}. "
                    f"SameSite: {context.same_site_strength}. "
                    f"Security score: {context.security_score:.2f}/1.0."
                    + (f" {browser_note}" if browser_note else "")
                ),
                severity=severity,
                evidence=[Evidence(
                    type="cookie_security_context",
                    description=f"Contextual cookie assessment for {cookie.name}.",
                    data={
                        "name": cookie.name,
                        "missing_attributes": issues,
                        "role": context.role,
                        "cookie_type": context.cookie_type,
                        "party_context": scope,
                        "persistent": context.persistent,
                        "host_only": cookie.host_only,
                        "same_site": cookie.same_site,
                        "same_site_strength": context.same_site_strength,
                        "secure": cookie.secure,
                        "http_only": cookie.http_only,
                        "partitioned": cookie.partitioned,
                        "has_host_prefix": context.has_host_prefix,
                        "has_secure_prefix": context.has_secure_prefix,
                        "security_score": context.security_score,
                    },
                )],
                remediation="Use Secure for HTTPS cookies; use HttpOnly for cookies not read by JavaScript; set an appropriate SameSite policy; and use valid __Host-/__Secure- prefix semantics.",
                cookie_type=context.cookie_type,
                cookie_role=context.role,
                cookie_first_party=context.first_party,
                cookie_persistent=context.persistent,
                cookie_same_site=context.same_site_strength,
                cookie_security_score=context.security_score,
                cookie_has_host_prefix=context.has_host_prefix,
                cookie_has_secure_prefix=context.has_secure_prefix,
                cookie_is_third_party=not context.first_party,
                **metadata.__dict__,
            ))
        return observations


CookieSecurityPlugin = InsecureCookiePlugin

__all__ = ["InsecureCookiePlugin", "CookieSecurityPlugin", "CookieSecurityAnalyzer"]
