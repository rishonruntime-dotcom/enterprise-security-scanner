# In src/scanner/di/containers.py:

from dependency_injector import containers, providers
import structlog
import os

from ..config.loader import ConfigurationLoader
from ..core.lifecycle import LifecycleManager
from ..logging.setup import setup_logging
from ..events.publisher import InMemoryEventPublisher
from ..network.http.manager import HTTPClientManager
from ..network.browser.manager import BrowserManager
from ..network.session import InMemorySessionManager
from ..network.exposure.scanner import NetworkExposureScanner
from ..network.exposure.models import NetworkExposureResult, ExposedServiceFinding
from ..crawler.queue import InMemoryURLQueue
from ..crawler.extractors import HTMLExtractor
from ..crawler.engine import CrawlManager
from ..intelligence.signatures import JSONSignatureProvider
from ..intelligence.detectors import TechnologyDetector
from ..intelligence.engine import FingerprintManager
from ..passive.engine import PassiveScannerManager
from ..active.engine import ActiveScannerManager
from ..correlation.pipeline import FindingPipeline
from ..correlation.verification import EvidenceVerificationStep
from ..correlation.deduplication import DeduplicationStep
from ..correlation.intelligence import IntelligenceEnrichmentStep
from ..correlation.cvss_step import CVSSCalculationStep
from ..correlation.risk_step import RiskCalculationStep
from ..correlation.priority_step import BusinessPriorityStep
from ..correlation.severity_context import ContextualSeverityStep
from ..correlation.false_positive import FalsePositiveReductionStep
from ..correlation.dynamic_severity import DynamicSeverityStep
from ..correlation.dynamic_confidence import DynamicConfidenceStep
from ..correlation.central_evaluator import CentralEvaluationStep
from ..risk.engine import RiskEngine
from ..risk.models import AssetCriticality
from ..reporting.exporters import JSONExporter, SARIFExporter, MarkdownExporter, HTMLExporter, PDFExporter
from ..reporting.manager import ReportManager
from ..network.exposure.scanner import NetworkExposureScanner
from ..network.exposure.pipeline_step import NetworkExposureStep
from ..network.exposure.models import NetworkExposureResult, ExposedServiceFinding
from ..infrastructure.repositories import InMemoryScanRepository
from ..services.orchestrator import StateController, ScanExecutor, ScanScheduler
from ..services.scanner_engine_adapter import (
    CrawlerEngine,
    FingerprintEngine,
    PassiveEngine,
    ActiveEngine,
)

logger = structlog.get_logger(__name__)


def init_logging(config, app_name: str) -> None:
    setup_logging(config, app_name)
    logger.info("Logging initialized", level=config.level)


class ApplicationContainer(containers.DeclarativeContainer):
    """Inversion of Control (IoC) container for the application."""
    
    config_path = providers.Dependency(instance_of=str)
    
    config = providers.Singleton(
        ConfigurationLoader.load,
        config_path=config_path,
    )

    logging = providers.Resource(
        init_logging,
        config=config.provided.logging,
        app_name=config.provided.app_name,
    )

    lifecycle_manager = providers.Singleton(LifecycleManager)
    event_publisher = providers.Singleton(InMemoryEventPublisher)

    http_manager = providers.Singleton(
        HTTPClientManager,
        default_timeout=config.provided.network.default_timeout,
        max_connections=config.provided.network.max_connections,
    )
    
    browser_manager = providers.Singleton(
        BrowserManager,
        headless=config.provided.browser.headless,
        timeout=config.provided.browser.timeout,
    )
    
    session_manager = providers.Singleton(InMemorySessionManager)

    url_queue = providers.Factory(
        InMemoryURLQueue,
        max_depth=config.provided.crawler.max_depth,
    )

    html_extractor = providers.Singleton(HTMLExtractor)
    
    crawl_manager = providers.Factory(
        CrawlManager,
        http_client=http_manager.provided.get_shared_client.call(),
        queue=url_queue,
        extractors=providers.List(html_extractor),
        browser_context=None,
        concurrency=config.provided.crawler.concurrency,
        browser_manager=browser_manager
    )

    signature_provider = providers.Singleton(
        JSONSignatureProvider,
        file_path=config.provided.intelligence.signature_file_path,
    )
    
    technology_detector = providers.Singleton(
        TechnologyDetector,
        provider=signature_provider,
    )
    
    fingerprint_manager = providers.Singleton(
        FingerprintManager,
        detectors=providers.List(technology_detector),
        confidence_threshold=config.provided.intelligence.confidence_threshold,
    )

    passive_manager = providers.Singleton(
        PassiveScannerManager,
        plugin_package=config.provided.passive.plugins_package,
    )

    active_manager = providers.Singleton(
        ActiveScannerManager,
        http_manager=http_manager,
        plugin_package=config.provided.active.plugins_package,
    )

    risk_engine = providers.Singleton(
        RiskEngine,
        default_criticality=AssetCriticality.MISSION_CRITICAL,
        target_context={},
    )

    verification_step = providers.Factory(
        EvidenceVerificationStep,
        http_manager=http_manager,
        browser_manager=browser_manager
    )
    deduplication_step = providers.Singleton(DeduplicationStep)
    intelligence_step = providers.Singleton(IntelligenceEnrichmentStep)
    cvss_step = providers.Singleton(CVSSCalculationStep)
    risk_step = providers.Singleton(
        RiskCalculationStep,
        risk_engine=risk_engine
    )
    priority_step = providers.Singleton(BusinessPriorityStep)
    severity_context_step = providers.Singleton(ContextualSeverityStep, risk_engine=risk_engine)
    false_positive_step = providers.Singleton(FalsePositiveReductionStep)
    dynamic_severity_step = providers.Singleton(DynamicSeverityStep)
    dynamic_confidence_step = providers.Singleton(DynamicConfidenceStep)
    central_evaluation_step = providers.Singleton(CentralEvaluationStep)
    network_exposure_step = providers.Singleton(NetworkExposureStep)
    
    finding_pipeline = providers.Factory(
        FindingPipeline
    )
    finding_pipeline.add_kwargs(steps=providers.List(
        verification_step,
        deduplication_step,
        intelligence_step,
        cvss_step,
        risk_step,
        priority_step
    ), severity_context_step=severity_context_step, false_positive_step=false_positive_step, dynamic_severity_step=dynamic_severity_step, dynamic_confidence_step=dynamic_confidence_step, central_evaluation_step=central_evaluation_step)

    network_exposure_scanner = providers.Factory(
        NetworkExposureScanner,
        config=config.provided.network_exposure,
    )

    json_exporter = providers.Factory(JSONExporter)
    sarif_exporter = providers.Factory(SARIFExporter)
    markdown_exporter = providers.Factory(
        MarkdownExporter,
        template_dir=os.path.join(os.path.dirname(__file__), "..", "reporting", "templates")
    )
    html_exporter = providers.Factory(
        HTMLExporter,
        template_dir=os.path.join(os.path.dirname(__file__), "..", "reporting", "templates")
    )
    pdf_exporter = providers.Factory(
        PDFExporter,
        browser_manager=browser_manager,
        html_exporter=html_exporter
    )
    
    report_manager = providers.Singleton(
        ReportManager,
        exporters=providers.Dict({
            "json": json_exporter,
            "sarif": sarif_exporter,
            "md": markdown_exporter,
            "html": html_exporter,
            "pdf": pdf_exporter
        }),
        output_dir=config.provided.reporting.output_dir
    )

    scan_repo = providers.Singleton(InMemoryScanRepository)

    state_controller = providers.Singleton(
        StateController,
        repository=scan_repo,
        publisher=event_publisher,
    )

    crawler_engine = providers.Factory(
        CrawlerEngine,
        crawl_manager=crawl_manager,
        config=config,
    )

    fingerprint_engine = providers.Factory(
        FingerprintEngine,
        fingerprinter=fingerprint_manager,
        http_manager=http_manager,
    )

    passive_engine = providers.Factory(
        PassiveEngine,
        passive_scanner=passive_manager,
        http_manager=http_manager,
    )

    active_engine = providers.Factory(
        ActiveEngine,
        active_scanner=active_manager,
    )

    engines = providers.Dict({
        "crawler": crawler_engine,
        "fingerprint": fingerprint_engine,
        "passive": passive_engine,
        "active": active_engine,
    })

    scan_executor = providers.Singleton(
        ScanExecutor,
        state_controller=state_controller,
        engines=engines,
        publisher=event_publisher,
    )

    scan_scheduler = providers.Singleton(
        ScanScheduler,
        executor=scan_executor,
        max_concurrency=config.provided.scanner.max_concurrency,
    )
