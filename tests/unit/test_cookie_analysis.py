from scanner.models.finding import Severity
from scanner.network.models import Cookie
from scanner.passive.plugins.cookies import CookieSecurityAnalyzer


def test_persistent_first_party_session_cookie_missing_secure_and_httponly_is_high():
    cookie = Cookie(name="session_id", value="redacted", max_age=3600, secure=False, http_only=False)

    issues, severity, context, _ = CookieSecurityAnalyzer.analyze(cookie, "https://portal.example.test/")

    assert issues == ["Secure", "HttpOnly", "SameSite"]
    assert severity == Severity.HIGH
    assert context.role == "authentication/session"
    assert context.first_party is True
    assert context.persistent is True


def test_client_readable_csrf_cookie_is_not_flagged_for_missing_httponly():
    cookie = Cookie(name="XSRF-TOKEN", value="redacted", secure=True, http_only=False, same_site="Lax")

    issues, severity, context, _ = CookieSecurityAnalyzer.analyze(cookie, "https://app.example.test/")

    assert issues == []
    assert severity is None
    assert context.client_readable_expected is True


def test_third_party_analytics_cookie_is_informational_not_session_severity():
    cookie = Cookie(name="_ga", value="redacted", domain="analytics.example.net", secure=False, http_only=False)

    issues, severity, context, _ = CookieSecurityAnalyzer.analyze(cookie, "https://app.example.test/")

    assert "Secure" in issues
    assert severity == Severity.INFO
    assert context.first_party is False


def test_samesite_none_without_secure_is_not_reported_as_exploitable_cookie():
    cookie = Cookie(name="session", value="redacted", same_site="None", secure=False, http_only=False)

    issues, severity, _, note = CookieSecurityAnalyzer.analyze(cookie, "https://app.example.test/")

    assert issues == []
    assert severity is None
    assert "rejected" in note


def test_host_prefix_violation_is_informational_due_to_browser_enforcement():
    cookie = Cookie(name="__Host-session", value="redacted", domain="example.test", path="/account", secure=False)

    issues, severity, _, note = CookieSecurityAnalyzer.analyze(cookie, "https://example.test/")

    assert severity == Severity.INFO
    assert "__Host- prefix" in issues[0]
    assert "rejected" in note
