import urllib.parse
from dataclasses import dataclass
from typing import Any, Mapping, Tuple

from .models import EndpointClass, AssetCategory
from ..models.finding import Severity


@dataclass(frozen=True)
class EndpointClassification:
    """A reproducible classification assigned during endpoint discovery."""

    endpoint_class: EndpointClass
    confidence: float
    reason: str
    severity_multiplier: float


@dataclass(frozen=True)
class AssetClassification:
    """Classification of an asset/URL into an ownership/integration category."""

    asset_category: AssetCategory
    confidence: float
    reason: str


class EndpointClassifier:
    """Classifies endpoints into functional classes and calculates severity impact multipliers."""

    @staticmethod
    def classify(url: str) -> Tuple[EndpointClass, float]:
        """
        Classifies a URL into a functional endpoint class and returns:
        (EndpointClass, severity_multiplier)
        """
        result = EndpointClassifier.classify_endpoint(url)
        return result.endpoint_class, result.severity_multiplier

    @staticmethod
    def classify_endpoint(
        url: str,
        method: str = "GET",
        parameters: Mapping[str, Any] | None = None,
    ) -> EndpointClassification:
        """Classify an endpoint from stable URL, method, and input evidence.

        Matching is deliberately based on path *segments* and extensions rather
        than arbitrary substrings.  This avoids labelling routes such as
        ``/catalog`` as authentication merely because they contain ``/log``.
        """
        if not url:
            return EndpointClassification(EndpointClass.MAIN_APP, 0.25, "No URL available", 1.0)

        parsed = urllib.parse.urlparse(str(url))
        path = urllib.parse.unquote(parsed.path).lower()
        segments = {part for part in path.split("/") if part}
        extension = path.rsplit(".", 1)[-1] if "." in path.rsplit("/", 1)[-1] else ""
        query_names = {name.lower() for name, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)}
        parameter_names = {str(name).lower() for name in (parameters or {})}
        input_names = query_names | parameter_names
        normalized_method = method.upper()

        def result(kind: EndpointClass, confidence: float, reason: str, multiplier: float) -> EndpointClassification:
            return EndpointClassification(kind, confidence, reason, multiplier)

        admin_portal_segments = {"admin-portal", "sysadmin", "control-panel", "console", "manager"}
        admin_segments = {"admin", "wp-admin", "wp-login", "dashboard", "management", "control", "internal", "system-status"}
        if segments & admin_portal_segments:
            return result(EndpointClass.ADMIN_PORTAL, 0.98, "administrative portal or control console route", 1.35)
        if segments & admin_segments:
            return result(EndpointClass.ADMIN, 0.94, "administrative route segment", 1.30)

        pg_segments = {"payment-gateway", "pg", "stripe", "paypal", "braintree", "razorpay", "payu", "adyen", "cybersource", "worldpay"}
        if segments & pg_segments:
            return result(EndpointClass.PAYMENT_GATEWAY, 0.96, "payment gateway integration route", 1.40)

        checkout_segments = {"checkout", "cart", "basket", "purchase", "buy"}
        if segments & checkout_segments:
            return result(EndpointClass.CHECKOUT, 0.95, "checkout or purchasing flow route", 1.35)

        identity_segments = {"sso", "saml", "idp", "identity", "oidc", "auth0", "okta", "keycloak", "onelogin", "userinfo"}
        if segments & identity_segments:
            return result(EndpointClass.IDENTITY, 0.96, "identity provider or SSO route", 1.30)

        auth_segments = {"login", "signin", "signup", "register", "logout", "auth", "oauth", "session", "token", "password-reset", "forgot-password"}
        if segments & auth_segments or ({"username", "password"} <= input_names and normalized_method in {"POST", "PUT", "PATCH"}):
            return result(EndpointClass.AUTHENTICATION, 0.96, "authentication route or credential form", 1.25)

        cust_data_segments = {"customer", "customers", "customer-data", "pii", "user-vault", "sensitive", "kyc", "user-data"}
        if segments & cust_data_segments:
            return result(EndpointClass.CUSTOMER_DATA, 0.94, "customer data or PII store route", 1.35)

        if "graphql" in segments or "gql" in segments or "wsdl" in input_names or path.endswith(".asmx"):
            return result(EndpointClass.API, 0.98, "GraphQL or SOAP API signature", 1.15)
        if "api" in segments or "rest" in segments or "services" in segments or any(segment in {"v1", "v2", "v3", "v4"} for segment in segments):
            return result(EndpointClass.API, 0.88, "API route segment", 1.15)

        payment_segments = {"payment", "payments", "billing", "billing-info", "order", "orders", "invoice", "invoices", "receipt", "refund"}
        if segments & payment_segments:
            return result(EndpointClass.PAYMENT, 0.90, "payment or billing route segment", 1.30)

        upload_segments = {"upload", "file-upload", "fileupload", "media-upload", "image-upload"}
        if segments & upload_segments:
            return result(EndpointClass.UPLOAD, 0.92, "file upload route segment", 1.20)

        if path.endswith(("/feed", "/rss", "/atom", "/sitemap.xml")) or "feeds" in segments:
            return result(EndpointClass.FEED, 0.95, "syndication or sitemap resource", 0.60)
        if extension in {"png", "jpg", "jpeg", "gif", "webp", "svg", "mp4", "webm", "mp3", "wav"} or bool({"images", "image", "media", "img", "uploads"} & segments):
            return result(EndpointClass.MEDIA, 0.91, "media extension or media path segment", 0.55)
        if extension in {"pdf", "zip", "tar", "gz", "csv", "xlsx", "docx"} or bool({"download", "downloads", "export"} & segments):
            return result(EndpointClass.DOWNLOAD, 0.89, "download extension or download path segment", 0.70)
        if extension in {"css", "js", "mjs", "woff", "woff2", "ttf", "eot", "map"} or bool({"static", "assets", "dist", "build"} & segments):
            return result(EndpointClass.STATIC_ASSETS, 0.93, "static asset extension or path segment", 0.50)
        if bool({"embed", "iframe", "widget", "widgets", "thirdparty", "external"} & segments):
            return result(EndpointClass.THIRD_PARTY, 0.70, "embedded or third-party integration route", 0.70)

        return result(EndpointClass.MAIN_APP, 0.60, "no specialised endpoint signature", 1.0)

    @staticmethod
    def adjust_severity(
        severity: Severity,
        endpoint_class: EndpointClass,
        *,
        plugin_id: str = "",
        is_passive: bool = False,
    ) -> Severity:
        """
        Adjusts finding severity based on functional endpoint class:
        - High-criticality Business Assets (Admin Portal, Payment Gateway, Checkout, Customer Data, Identity, Auth, Payment) escalate severity by one level.
        - API endpoints escalate Medium to High.
        - Upload endpoints escalate Low to Medium, Medium to High.
        - Low-sensitivity endpoints (Feed, Media, Static Assets) downgrade Medium to Low and Low to Info.
        """
        severity_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

        _HIGH_CRITICALITY = {
            EndpointClass.ADMIN_PORTAL,
            EndpointClass.ADMIN,
            EndpointClass.PAYMENT_GATEWAY,
            EndpointClass.CHECKOUT,
            EndpointClass.CUSTOMER_DATA,
            EndpointClass.IDENTITY,
            EndpointClass.AUTHENTICATION,
            EndpointClass.PAYMENT,
        }

        if endpoint_class in _HIGH_CRITICALITY:
            if severity == Severity.INFO:
                return severity
            idx = severity_order.index(severity)
            if idx < len(severity_order) - 1:
                return severity_order[idx + 1]
            return severity

        if endpoint_class == EndpointClass.API and severity == Severity.MEDIUM:
            return Severity.HIGH

        if endpoint_class == EndpointClass.UPLOAD:
            if severity == Severity.LOW:
                return Severity.MEDIUM
            elif severity == Severity.MEDIUM:
                return Severity.HIGH
            return severity

        generic_configuration_finding = is_passive or plugin_id.upper().startswith("PASS-")
        if generic_configuration_finding and endpoint_class in (EndpointClass.FEED, EndpointClass.MEDIA, EndpointClass.STATIC_ASSETS, EndpointClass.STATIC):
            if severity == Severity.MEDIUM:
                return Severity.LOW
            elif severity == Severity.LOW:
                return Severity.INFO
        return severity


class AssetClassifier:
    """Classifies assets/URLs into ownership and integration categories."""

    _CDN_DOMAINS = {
        "cloudflare.com", "cloudfront.net", "fastly.net", "akamai.net", "akamaihd.net",
        "cdn.jsdelivr.net", "unpkg.com", "cdn.cloudflare.net", "b-cdn.net", "bunny.net",
        "keycdn.com", "stackpathdns.com", "netdna-cdn.com", "cdn77.org", "cdnify.com",
    }
    _ANALYTICS_DOMAINS = {
        "google-analytics.com", "analytics.google.com", "googletagmanager.com", "gtag.com",
        "facebook.com/tr", "connect.facebook.net", "pixel.facebook.com", "twitter.com/i/adsct",
        "linkedin.com/collect", "ads.linkedin.com", "bing.com/collect", "clarity.ms",
        "hotjar.com", "mixpanel.com", "amplitude.com", "segment.com", "segment.io",
        "matomo.cloud", "piwik.net", "newrelic.com", "nr-data.net", "sentry.io",
    }
    _OAUTH_DOMAINS = {
        "accounts.google.com", "login.microsoftonline.com", "login.microsoft.com",
        "github.com/login/oauth", "gitlab.com/oauth", "slack.com/oauth", "facebook.com/v2.0/dialog/oauth",
        "apple.com/auth", "oauth.vk.com", "auth0.com", "okta.com", "onelogin.com",
        "pingidentity.com", "keycloak.org", "auth0.net",
    }
    _PAYMENT_DOMAINS = {
        "stripe.com", "stripe.network", "m.stripe.com", "checkout.stripe.com", "js.stripe.com",
        "paypal.com", "paypalobjects.com", "braintreegateway.com", "braintreepayments.com",
        "adyen.com", "squareup.com", "squarecdn.com", "authorize.net", "razorpay.com",
        "checkout.razorpay.com", "payu.com", "payu.in", "worldpay.com", "cybersource.com",
    }
    _EMBEDDED_WIDGET_SEGMENTS = {
        "embed", "iframe", "widget", "widgets", "player", "video-player", "chat-widget",
        "support-widget", "intercom", "zendesk", "drift", "hubspot", "salesforce", "livechat",
        "tawk.to", "crisp.chat", "olark", "userlike", "help", "help-center", "kb",
    }

    @staticmethod
    def classify(url: str, primary_domain: str = "") -> AssetClassification:
        if not url:
            return AssetClassification(AssetCategory.FIRST_PARTY, 0.25, "No URL available",)

        parsed = urllib.parse.urlparse(str(url))
        hostname = (parsed.netloc or "").lower().replace("www.", "")
        path = urllib.parse.unquote(parsed.path).lower()
        segments = {part for part in path.split("/") if part}

        if not hostname:
            return AssetClassification(AssetCategory.FIRST_PARTY, 0.25, "No hostname available",)

        primary = primary_domain.lower().replace("www.", "") if primary_domain else ""

        if primary and hostname == primary:
            return AssetClassification(AssetCategory.FIRST_PARTY, 0.99, "Matches primary target domain",)

        if any(hostname == cdn or hostname.endswith("." + cdn) for cdn in AssetClassifier._CDN_DOMAINS):
            return AssetClassification(AssetCategory.CDN, 0.95, "Known CDN provider domain",)

        if any(hostname == analytics or hostname.endswith("." + analytics) for analytics in AssetClassifier._ANALYTICS_DOMAINS):
            return AssetClassification(AssetCategory.ANALYTICS, 0.95, "Known analytics provider domain",)

        if any(hostname == oauth or hostname.endswith("." + oauth) for oauth in AssetClassifier._OAUTH_DOMAINS):
            return AssetClassification(AssetCategory.OAUTH, 0.95, "Known OAuth / identity provider domain",)

        if any(hostname == payment or hostname.endswith("." + payment) for payment in AssetClassifier._PAYMENT_DOMAINS):
            return AssetClassification(AssetCategory.PAYMENT, 0.95, "Known payment provider domain",)

        if segments & AssetClassifier._EMBEDDED_WIDGET_SEGMENTS:
            return AssetClassification(AssetCategory.EMBEDDED_WIDGETS, 0.80, "Path suggests embedded widget or integration",)

        if primary and (hostname.endswith("." + primary) or primary.endswith("." + hostname)):
            return AssetClassification(AssetCategory.FIRST_PARTY, 0.85, "Subdomain of primary target",)

        return AssetClassification(AssetCategory.THIRD_PARTY, 0.70, "External domain not matching first-party or known provider patterns",)
