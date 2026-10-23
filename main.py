import asyncio
import os
import sys
from pathlib import Path

from scanner.di.containers import ApplicationContainer
import structlog

async def main():
    """Main entrypoint for the enterprise scanner."""
    
    # 1. Setup DI Container
    # Point the container to the config directory
    config_dir = Path(__file__).parent / "config"
    container = ApplicationContainer(config_path=str(config_dir))
    
    # Wire the container to any modules that use dependency injection
    # For this minimal foundation, we don't have injected functions yet,
    # but normally we would do:
    # container.wire(modules=[__name__, "scanner.some_module"])
    
    # 2. Resolve Core Components
    # Initialize config (and consequently logging due to the resource provider)
    config = container.config()
    # Initialize logging via the container
    container.logging()
    
    logger = structlog.get_logger(__name__)
    logger.info("Application starting up...", environment=config.environment, app_name=config.app_name)
    
    # 3. Application Lifecycle
    lifecycle_manager = container.lifecycle_manager()
    scan_scheduler = container.scan_scheduler()
    browser_manager = container.browser_manager()
    http_manager = container.http_manager()
    
    # Register lifecycle tasks
    lifecycle_manager.add_startup_task(scan_scheduler.start)
    lifecycle_manager.add_startup_task(browser_manager.start)
    
    lifecycle_manager.add_shutdown_task(scan_scheduler.stop)
    lifecycle_manager.add_shutdown_task(browser_manager.stop)
    lifecycle_manager.add_shutdown_task(http_manager.close)
    
    try:
        # Start services
        await lifecycle_manager.startup()
        
        logger.info("Scanner orchestrator is running.")
        
        # Test HTTP
        from scanner.network.models import HTTPRequest
        logger.info("Testing HTTP client...")
        shared_http = http_manager.get_shared_client()
        # Including a mock auth header to test redaction
        req = HTTPRequest(
            method="GET", 
            url="https://example.com", 
            headers={"Authorization": "Bearer super-secret-token"}
        )
        resp = await shared_http.send(req)
        logger.info("HTTP Test successful", status_code=resp.status_code, url=resp.url)
        
        # Test Crawler
        from scanner.crawler.models import CrawlSession
        crawl_manager = container.crawl_manager()
        logger.info("Starting crawler test on example.com...")
        session = CrawlSession(
            scan_id="manual-test",
            allowed_domains=["example.com"],
            max_depth=1,
            max_urls=10,
            use_browser=False
        )
        
        result = await crawl_manager.crawl(["https://example.com"], session)
        logger.info("Crawler Test successful", endpoints=len(result.endpoints), forms=len(result.forms))
        
        # Test Fingerprinting
        logger.info("Testing Technology Fingerprinting...")
        fingerprint_manager = container.fingerprint_manager()
        # Create a mock response mimicking Nginx + React
        from scanner.network.models import HTTPRequest, HTTPResponse
        req_fp = HTTPRequest(method="GET", url="https://example.com")
        resp_fp = HTTPResponse(
            status_code=200,
            url="https://example.com",
            headers={"Server": "nginx/1.22.0"},
            cookies=[],
            body=b"<div data-reactroot></div>",
            text="<div data-reactroot></div>",
            request=req_fp
        )
        tech_profile = fingerprint_manager.analyze_response(resp_fp, resp_fp.text)
        logger.info("Fingerprint Test successful", technologies=[t.name for t in tech_profile.technologies])
        
        # Test Passive Scanner
        logger.info("Testing Passive Security Engine...")
        passive_manager = container.passive_manager()
        
        # Test the mock response from fingerprinting for passive vulnerabilities
        req_pass = HTTPRequest(method="GET", url="https://example.com")
        from scanner.network.models import Cookie
        insecure_cookie = Cookie(name="session_id", value="12345", secure=False, http_only=False)
        
        resp_pass = HTTPResponse(
            status_code=200,
            url="https://example.com",
            headers={"Server": "nginx/1.22.0"},  # Missing security headers
            cookies=[insecure_cookie],
            body=b"<html></html>",
            text="<html></html>",
            request=req_pass
        )
        findings = passive_manager.analyze_response(resp_pass)
        for finding in findings:
            logger.info("Security Finding Discovered", title=finding.title)
            
        logger.info("Passive Scanner Test successful", total_findings=len(findings))

        # Test Active Scanner
        logger.info("Testing Active Security Engine...")
        active_manager = container.active_manager()
        
        # Test the active scanner against a vulnerable endpoint
        # Note: example.com is generally safe but might not reflect XSS. The integration test validates the mock.
        active_findings = await active_manager.analyze_endpoint("https://example.com/search?q=test")
        
        for finding in active_findings:
            logger.warning("Active Security Finding Discovered", plugin_id=finding.plugin_id, parameter=finding.parameter)
            
        # Process findings through the Correlation Pipeline
        logger.info("Testing Finding Correlation Pipeline...")
        finding_pipeline = container.finding_pipeline()
        
        all_raw_items = findings + active_findings
        enriched_findings = []
        
        for raw_item in all_raw_items:
            processed = await finding_pipeline.process(raw_item)
            if processed:
                enriched_findings.append(processed)
                cwe_id = processed.intelligence.cwe_id if processed.intelligence else "Unknown CWE"
                priority = processed.risk.final_priority if processed.risk else 0.0
                logger.warning("Enriched Vulnerability Ready for Reporting", 
                               title=processed.title, 
                               severity=processed.severity.value,
                               cwe=cwe_id,
                               priority=priority,
                               is_verified=processed.is_verified)
            else:
                logger.debug("Finding dropped by pipeline", title=getattr(raw_item, 'title', 'unknown'))
                
        logger.info("Correlation Pipeline Test complete", raw_count=len(all_raw_items), enriched_count=len(enriched_findings))

        if os.environ.get("SCANNER_TEST_RUN"):
             await asyncio.sleep(1)
        else:
            # Simulate a long running process in dev
            while True:
                await asyncio.sleep(3600)
                
    except KeyboardInterrupt:
        logger.info("Shutdown signal received")
    except Exception as e:
        logger.exception("Application crashed")
        sys.exit(1)
    finally:
        # Shutdown services
        await lifecycle_manager.shutdown()

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "api":
        import uvicorn
        from scanner.api.app import app
        uvicorn.run(app, host="0.0.0.0", port=5000)
    else:
        asyncio.run(main())

