import pytest
import os
from scanner.network.models import HTTPResponse
from scanner.intelligence.signatures import JSONSignatureProvider
from scanner.intelligence.detectors import TechnologyDetector
from scanner.intelligence.engine import FingerprintManager


def test_fingerprint_manager_integration():
    """Test full fingerprinting pipeline with mock signatures."""
    # Ensure we use the mock signatures file
    sig_path = os.path.join("src", "scanner", "intelligence", "signatures.json")
    provider = JSONSignatureProvider(file_path=sig_path)
    detector = TechnologyDetector(provider=provider)
    manager = FingerprintManager(detectors=[detector], confidence_threshold=40)
    
    # Create a dummy HTTPRequest to satisfy the model requirement
    from scanner.network.models import HTTPRequest
    dummy_req = HTTPRequest(method="GET", url="https://example-wordpress.com")
    
    # Mock Response simulating a WordPress site on Nginx
    mock_response = HTTPResponse(
        status_code=200,
        url="https://example-wordpress.com",
        headers={
            "Server": "nginx/1.24.0",
            "X-Powered-By": "PHP/8.2.0"
        },
        cookies=[],
        body=b"dummy body",
        text="dummy body",
        request=dummy_req
    )
    
    html_content = """
    <html>
        <head>
            <meta name="generator" content="WordPress 6.4.2" />
            <link rel="stylesheet" href="/wp-content/themes/style.css" />
        </head>
        <body>
            <div data-reactroot></div>
        </body>
    </html>
    """
    
    res = manager.analyze_response(mock_response, html_content)
    techs = res if isinstance(res, list) else res.technologies
    
    tech_names = [t.name for t in techs]
    
    assert "Nginx" in tech_names
    assert "PHP" in tech_names
    assert "WordPress" in tech_names
    assert "React" in tech_names
    assert "MySQL" in tech_names  # Implied by WordPress
    
    nginx_tech = next(t for t in techs if t.name == "Nginx")
    assert "1.24.0" in nginx_tech.versions
    assert nginx_tech.confidence == 100
    
    wp_tech = next(t for t in techs if t.name == "WordPress")
    assert "6.4.2" in wp_tech.versions
    assert wp_tech.confidence >= 80
