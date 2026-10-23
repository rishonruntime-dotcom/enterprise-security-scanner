import asyncio
import urllib.parse
import json
from typing import List, Optional, Dict, Any
import structlog
from datetime import datetime

from ..database.models.scan import ScanORM, ScanStatus
from ..crawler.models import CrawlSession, CrawlResult, Endpoint
from ..crawler.engine import CrawlManager
from ..passive.engine import PassiveScannerManager
from ..active.engine import ActiveScannerManager
from ..intelligence.engine import FingerprintManager
from ..correlation.pipeline import FindingPipeline
from ..network.models import HTTPResponse, HTTPRequest
from ..network.http.manager import HTTPClientManager
from ..network.exposure.scanner import NetworkExposureScanner
from ..network.exposure.models import NetworkExposureResult, ExposedServiceFinding

logger = structlog.get_logger(__name__)


class ScanManager:
    """Orchestrates end-to-end scanning lifecycle."""

    def __init__(
        self,
        scan_repo: Any,
        finding_repo: Any,
        tech_repo: Any,
        event_publisher: Any = None,
        crawler: Optional[CrawlManager] = None,
        fingerprinter: Optional[FingerprintManager] = None,
        passive_scanner: Optional[PassiveScannerManager] = None,
        active_scanner: Optional[ActiveScannerManager] = None,
        pipeline: Optional[FindingPipeline] = None,
        http_manager: Optional[HTTPClientManager] = None,
        network_exposure_scanner: Optional[NetworkExposureScanner] = None,
        config: Any = None,
    ):
        self.scan_repo = scan_repo
        self.finding_repo = finding_repo
        self.tech_repo = tech_repo
        self.event_publisher = event_publisher
        self.crawler = crawler
        self.fingerprinter = fingerprinter
        self.passive_scanner = passive_scanner
        self.active_scanner = active_scanner
        self.pipeline = pipeline
        self.http_manager = http_manager
        self.network_exposure_scanner = network_exposure_scanner
        self.config = config
        self._active_tasks: Dict[str, asyncio.Task] = {}

    async def create_scan(self, target_url: str, scan_type: str = "full", profile: str = "default", asset_criticality: Optional[str] = None, exposure: Optional[str] = None) -> ScanORM:
        scan = ScanORM(
            target_url=target_url,
            scan_type=scan_type,
            profile=profile,
            status=ScanStatus.PENDING,
            progress=0.0,
            total_findings=0,
            asset_criticality=asset_criticality,
            exposure=exposure,
        )
        scan = await self.scan_repo.create(scan)
        logger.info("Created scan target", scan_id=scan.id, target_url=target_url)
        return scan

    async def start_scan(self, scan_id: str) -> Optional[ScanORM]:
        scan = await self.scan_repo.get_by_id(scan_id)
        if not scan:
            return None

        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.utcnow()
        scan.progress = 5.0
        await self.scan_repo.update(scan)

        # Launch scan task asynchronously
        task = asyncio.create_task(self._run_actual_scan(scan_id))
        self._active_tasks[scan_id] = task
        return scan

    async def pause_scan(self, scan_id: str) -> Optional[ScanORM]:
        scan = await self.scan_repo.get_by_id(scan_id)
        if not scan:
            return None
        if scan_id in self._active_tasks:
            self._active_tasks[scan_id].cancel()
            del self._active_tasks[scan_id]
        scan.status = ScanStatus.PAUSED
        await self.scan_repo.update(scan)
        return scan

    async def cancel_scan(self, scan_id: str) -> Optional[ScanORM]:
        scan = await self.scan_repo.get_by_id(scan_id)
        if not scan:
            return None
        if scan_id in self._active_tasks:
            self._active_tasks[scan_id].cancel()
            del self._active_tasks[scan_id]
        scan.status = ScanStatus.CANCELLED
        await self.scan_repo.update(scan)
        return scan

    async def _run_actual_scan(self, scan_id: str):
        """Executes Phase 1-5 scanning workflow."""
        scan = await self.scan_repo.get_by_id(scan_id)
        if not scan:
            return

        target_url = scan.target_url
        parsed_target = urllib.parse.urlparse(target_url)
        domain = parsed_target.netloc or parsed_target.path

        try:
            # ─────────────────────────────────────────────────────────────
            # PHASE 1: CRAWLING & DISCOVERY
            # ─────────────────────────────────────────────────────────────
            logger.info("Executing Phase 1: Crawling & Discovery", scan_id=scan_id, target=target_url)
            scan.progress = 15.0
            await self.scan_repo.update(scan)

            discovered_endpoints: List[Endpoint] = []
            forms_found = 0

            if self.crawler:
                c_depth = getattr(self.config.crawler, "max_depth", 3) if (self.config and hasattr(self.config, "crawler")) else 3
                c_urls = getattr(self.config.crawler, "max_urls", 250) if (self.config and hasattr(self.config, "crawler")) else 250
                crawl_sess = CrawlSession(
                    scan_id=scan_id,
                    allowed_domains=[domain],
                    max_depth=c_depth,
                    max_urls=c_urls,
                    use_browser=True
                )
                try:
                    crawl_res: CrawlResult = await self.crawler.crawl([target_url], crawl_sess)
                    discovered_endpoints = crawl_res.endpoints
                    forms_found = len(crawl_res.forms)
                except Exception as c_err:
                    logger.error("Crawler execution failed, falling back to root endpoint", error=str(c_err))

            # Guarantee root endpoint is present
            if not any(e.url == target_url for e in discovered_endpoints):
                discovered_endpoints.insert(0, Endpoint(method="GET", url=target_url, source_url=target_url))

            from ..crawler.utils import ScopeValidator
            scope_val = ScopeValidator([domain, domain.replace("www.", ""), f"www.{domain}"])

            # Deduplicate and strictly scope-check endpoints by (method, url)
            unique_endpoints = []
            seen_eps = set()
            for ep in discovered_endpoints:
                if scope_val.in_scope(ep.url):
                    key = (ep.method.upper(), ep.url)
                    if key not in seen_eps:
                        seen_eps.add(key)
                        unique_endpoints.append(ep)

            # Persist Phase 1 metrics to database
            scan.urls_discovered = len(unique_endpoints)
            scan.pages_discovered = len(unique_endpoints)
            scan.endpoints_discovered = len(unique_endpoints)
            scan.forms_discovered = forms_found
            scan.http_requests_sent = len(unique_endpoints) + 5
            await self.scan_repo.update(scan)

            # ─────────────────────────────────────────────────────────────
            # PHASE 2: TECHNOLOGY FINGERPRINTING
            # ─────────────────────────────────────────────────────────────
            logger.info("Executing Phase 2: Technology Fingerprinting", scan_id=scan_id)
            scan.progress = 35.0
            await self.scan_repo.update(scan)

            responses_map: Dict[str, HTTPResponse] = {}
            if self.http_manager:
                client = self.http_manager.get_shared_client()
                for ep in unique_endpoints[:15]:  # Process up to 15 key endpoints
                    try:
                        req = HTTPRequest(method=ep.method, url=ep.url)
                        resp = await client.send(req)
                        if resp:
                            responses_map[ep.url] = resp
                    except Exception as http_ex:
                        logger.warning("Failed to fetch response for endpoint", url=ep.url, error=str(http_ex))

            # Fingerprint discovered technologies dynamically
            if self.fingerprinter and responses_map:
                import uuid
                from ..database.models.technology import TechnologyORM
                for url, resp in responses_map.items():
                    try:
                        profile = self.fingerprinter.analyze_response(resp)
                        detected_techs = profile.technologies if hasattr(profile, "technologies") else profile
                        if detected_techs:
                            for tech in detected_techs:
                                tech_name = getattr(tech, "name", str(tech))
                                tech_cat = getattr(tech, "category", "General")
                                if hasattr(tech_cat, "value"):
                                    tech_cat = tech_cat.value
                                tech_ver = "N/A"
                                if getattr(tech, "versions", None) and len(tech.versions) > 0:
                                    tech_ver = tech.versions[0]
                                elif getattr(tech, "version", None):
                                    tech_ver = tech.version

                                tech_orm = TechnologyORM(
                                    id=str(uuid.uuid4()),
                                    scan_id=scan_id,
                                    target_url=url,
                                    name=tech_name,
                                    category=str(tech_cat),
                                    version=str(tech_ver),
                                    confidence=getattr(tech, "confidence", 100),
                                    cpe=getattr(tech, "cpe", None),
                                    detection_method="fingerprinting",
                                )
                                await self.tech_repo.upsert(tech_orm)
                    except Exception as fp_err:
                        logger.error("Fingerprinting error", url=url, error=str(fp_err))

            # ─────────────────────────────────────────────────────────────
            # PHASE 2.5: NETWORK EXPOSURE & INFRASTRUCTURE SCANNING
            # ─────────────────────────────────────────────────────────────
            logger.info("Executing Phase 2.5: Network Exposure & Infrastructure Scanning", scan_id=scan_id, domain=domain)
            scan.progress = 45.0
            await self.scan_repo.update(scan)

            try:
                from ..network.exposure.scanner import NetworkExposureScanner
                exposure_scanner = NetworkExposureScanner({"timeout": 2.0, "concurrency": 50})
                net_result = await exposure_scanner.scan(domain)
                if net_result:
                    await self._ingest_network_technologies(net_result, scan_id, target_url, scan)
            except Exception as net_ex:
                logger.error("Network exposure scan error", domain=domain, error=str(net_ex))

            # ─────────────────────────────────────────────────────────────
            # PHASE 3: PASSIVE SECURITY ANALYSIS
            # ─────────────────────────────────────────────────────────────
            logger.info("Executing Phase 3: Passive Security Analysis", scan_id=scan_id)
            scan.progress = 55.0
            await self.scan_repo.update(scan)

            raw_observations = []
            if self.passive_scanner and responses_map:
                for url, resp in responses_map.items():
                    try:
                        obs = self.passive_scanner.analyze_response(resp)
                        if obs:
                            raw_observations.extend(obs)
                    except Exception as pass_err:
                        logger.error("Passive scanner error", url=url, error=str(pass_err))

            # ─────────────────────────────────────────────────────────────
            # PHASE 4: ACTIVE SECURITY SCANNING
            # ─────────────────────────────────────────────────────────────
            logger.info("Executing Phase 4: Active Security Analysis", scan_id=scan_id)
            scan.progress = 75.0
            await self.scan_repo.update(scan)

            if self.active_scanner and unique_endpoints:
                try:
                    active_obs = None
                    if hasattr(self.active_scanner, "scan_endpoints"):
                        active_obs = await self.active_scanner.scan_endpoints(unique_endpoints)
                    elif hasattr(self.active_scanner, "scan"):
                        active_obs = await self.active_scanner.scan(unique_endpoints)
                    elif hasattr(self.active_scanner, "run_plugins"):
                        active_obs = await self.active_scanner.run_plugins(unique_endpoints)

                    if active_obs:
                        raw_observations.extend(active_obs)
                except Exception as act_err:
                    logger.error("Active scanner error", error=str(act_err))

            # ─────────────────────────────────────────────────────────────
            # PHASE 4.5: NETWORK EXPOSURE ANALYSIS
            # ─────────────────────────────────────────────────────────────
            network_exposure_result = None
            ne_enabled = False
            if self.config:
                ne_cfg = getattr(self.config, "network_exposure", None)
                if ne_cfg is not None:
                    ne_enabled = bool(getattr(ne_cfg, "enabled", False))
            if self.network_exposure_scanner and target_url and ne_enabled:
                logger.info("Executing Phase 4.5: Network Exposure Analysis", scan_id=scan_id)
                try:
                    parsed_target = urllib.parse.urlparse(target_url)
                    target_host = parsed_target.netloc or parsed_target.path
                    
                    network_findings = await self.network_exposure_scanner.analyze(target_host)
                    for nf in network_findings:
                        raw_observations.append(nf)
                        logger.debug(
                            "Network exposure finding",
                            port=nf.port,
                            service=nf.service,
                            severity=nf.severity,
                        )
                    
                    network_exposure_result = await self.network_exposure_scanner.scan(target_host)
                    await self._ingest_network_technologies(network_exposure_result, scan_id, target_url, scan)
                except Exception as net_err:
                    logger.error("Network exposure scanner error", error=str(net_err))

            # ─────────────────────────────────────────────────────────────
            # PHASE 5: CORRELATION, VERIFICATION & PERSISTENCE
            # ─────────────────────────────────────────────────────────────
            logger.info("Executing Phase 5: Correlation & Persistence", scan_id=scan_id)
            scan.progress = 90.0
            await self.scan_repo.update(scan)

            enriched_findings = []
            if self.pipeline and raw_observations:
                try:
                    res = await self.pipeline.process(
                        raw_observations,
                        scan_id=scan_id,
                        severity_context={
                            "asset_criticality": scan.asset_criticality,
                            "exposure": scan.exposure,
                        },
                    )
                    if res is not None:
                        enriched_findings = res if isinstance(res, list) else [res]
                except Exception as pipe_err:
                    logger.error("Finding pipeline error", error=str(pipe_err))

            # Save processed findings to database
            import uuid
            from ..database.models.finding import FindingORM
            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            for finding in enriched_findings:
                if isinstance(finding, FindingORM):
                    finding.scan_id = scan_id
                    await self.finding_repo.create(finding)
                    sev_str = str(finding.severity).upper()
                    if sev_str in severity_counts:
                        severity_counts[sev_str] += 1
                elif hasattr(finding, "title"):
                    ev_matched = None
                    ev_rule = None
                    ev_reason = None
                    ev_raw_req = None
                    ev_raw_resp = None
                    ev_raw = None
                    if hasattr(finding, "evidence") and finding.evidence:
                        first_ev = finding.evidence[0]
                        ev_matched = getattr(first_ev, "matched_value", None)
                        ev_rule = getattr(first_ev, "detection_rule", None)
                        ev_reason = getattr(first_ev, "reason", None)
                        ev_raw_req = getattr(first_ev, "raw_request", None)
                        ev_raw_resp = getattr(first_ev, "raw_response", None)
                        ev_raw = json.dumps(getattr(first_ev, "data", ""), default=str)

                    sev_str = finding.severity.value.upper() if hasattr(finding.severity, "value") else str(finding.severity).upper()
                    if sev_str in severity_counts:
                        severity_counts[sev_str] += 1

                    finding_orm = FindingORM(
                        id=str(uuid.uuid4()),
                        scan_id=scan_id,
                        plugin_id=finding.plugin_id,
                        title=finding.title,
                        description=finding.description,
                        severity=sev_str,
                        original_severity=getattr(finding, "original_severity", None).value if getattr(finding, "original_severity", None) and hasattr(getattr(finding, "original_severity", None), "value") else (str(getattr(finding, "original_severity", None)) or None),
                        confidence=finding.confidence.value.upper() if hasattr(finding.confidence, "value") else str(finding.confidence).upper(),
                        endpoint=finding.endpoint,
                        endpoint_class=getattr(finding, "endpoint_class", "Main Application"),
                        asset_category=getattr(finding, "asset_category", "First-party"),
                        why_detected=getattr(finding, "why_detected", None),
                        how_verified=getattr(finding, "how_verified", None),
                        severity_reason=getattr(finding, "severity_reason", None),
                        false_positive_reasons=json.dumps(getattr(finding, "false_positive_reasons", []), default=str) if getattr(finding, "false_positive_reasons", None) else None,
                        cwe_id=finding.intelligence.cwe_id if hasattr(finding, "intelligence") and finding.intelligence else getattr(finding, "cwe_id", None),
                        cvss_score=finding.risk.cvss.base_score if hasattr(finding, "risk") and finding.risk and finding.risk.cvss else getattr(finding, "cvss_score", None),
                        epss_score=finding.risk.epss.probability if hasattr(finding, "risk") and finding.risk and finding.risk.epss else getattr(finding, "epss_score", None),
                        priority_score=finding.risk.final_priority if hasattr(finding, "risk") and finding.risk else getattr(finding, "priority_score", None),
                        is_verified=getattr(finding, "is_verified", False),
                        verification_status=finding.verification_status.value if hasattr(finding, "verification_status") and hasattr(finding.verification_status, "value") else str(getattr(finding, "verification_status", "Not Actively Verified")),
                        detection_method=finding.detection_method.value if hasattr(finding, "detection_method") and hasattr(finding.detection_method, "value") else str(getattr(finding, "detection_method", "Passive")),
                        cvss_vector=finding.risk.cvss.vector if hasattr(finding, "risk") and finding.risk and finding.risk.cvss else (finding.intelligence.cvss_vector if hasattr(finding, "intelligence") and finding.intelligence else getattr(finding, "cvss_vector", None)),
                        capec_id=finding.intelligence.capec_id if hasattr(finding, "intelligence") and finding.intelligence else getattr(finding, "capec_id", None),
                        remediation=finding.remediation,
                        matched_value=ev_matched,
                        detection_rule=ev_rule,
                        reason=ev_reason,
                        raw_request=ev_raw_req,
                        raw_response=ev_raw_resp,
                        owasp_category=finding.intelligence.owasp_category if hasattr(finding, "intelligence") and finding.intelligence else getattr(finding, "owasp_category", None),
                        raw_evidence=ev_raw,
                        raw_risk=json.dumps(finding.risk.model_dump(), default=str) if finding.risk else None,
                        false_positive_probability=getattr(finding, "false_positive_probability", 0.0),
                    )
                    await self.finding_repo.create(finding_orm)

            # Mark scan completed
            scan.status = ScanStatus.COMPLETED
            scan.progress = 100.0
            scan.total_findings = len(enriched_findings)
            scan.critical_findings = severity_counts.get("CRITICAL", 0)
            scan.high_findings = severity_counts.get("HIGH", 0)
            scan.medium_findings = severity_counts.get("MEDIUM", 0)
            scan.low_findings = severity_counts.get("LOW", 0)
            scan.completed_at = datetime.utcnow()
            
            await self.scan_repo.update(scan)

            logger.info("Scan completed successfully", scan_id=scan_id, total_findings=len(enriched_findings))

        except Exception as e:
            logger.error("Unhandled exception during scan execution", scan_id=scan_id, error=str(e), exc_info=True)
            scan.status = ScanStatus.FAILED
            scan.error_message = str(e)
            await self.scan_repo.update(scan)
        finally:
            if scan_id in self._active_tasks:
                del self._active_tasks[scan_id]

    async def _ingest_network_technologies(self, network_result: Any, scan_id: str, target_url: str, scan: Any = None) -> None:
        """Ingest network-exposed services into the technology inventory and store report section."""
        if not self.tech_repo or not network_result:
            return
        
        try:
            from ..database.models.technology import TechnologyORM
            import uuid
            from ..network.exposure.scanner import NetworkExposureScanner
            from ..network.exposure.models import NetworkExposureSection
            
            scanner = NetworkExposureScanner()
            section = scanner.build_report_section(network_result)
            
            for port_info in network_result.open_ports:
                if port_info.service_name and port_info.service_name not in ("HTTP", "HTTPS"):
                    tech = TechnologyORM(
                        id=str(uuid.uuid4()),
                        scan_id=scan_id,
                        name=port_info.product or port_info.service_name,
                        category="Network Service",
                        version=port_info.version,
                        vendor=port_info.service_name,
                        confidence=0.9 if port_info.banner else 0.7,
                        target_url=target_url,
                        detection_method="network_banner",
                    )
                    await self.tech_repo.upsert(tech)
                    logger.debug(
                        "Network technology ingested",
                        service=port_info.service_name,
                        product=port_info.product,
                        port=port_info.port,
                    )
            
            if scan is not None:
                scan.network_open_ports = len(network_result.open_ports)
                scan.network_services_detected = len(network_result.services)
                risky_services = [p for p in network_result.open_ports if p.port in [21, 23, 445, 3306, 3389, 5432, 6379, 27017, 27018, 9200, 2375, 2376, 6443, 2379, 2380, 5900, 11211, 5984, 7474]]
                scan.network_risky_services = len(risky_services)
                scan.network_exposure_result = section.model_dump_json()
                logger.debug(
                    "Network exposure section stored",
                    open_ports=scan.network_open_ports,
                    risky_services=scan.network_risky_services,
                )
        except Exception as tech_err:
            logger.error("Failed to ingest network technologies", error=str(tech_err))
