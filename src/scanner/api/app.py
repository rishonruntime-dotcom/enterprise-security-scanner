"""
Rebuilt FastAPI application — enterprise architecture.

All services are instantiated once at startup and exposed via module-level
accessors, making them usable from route modules without circular import issues.
Swap SQLite for PostgreSQL by changing DATABASE_URL in config — zero code changes elsewhere.
"""
import asyncio
import os
from contextlib import asynccontextmanager
from typing import Optional
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncEngine

from ..database.engine import build_engine, Base
from ..database.session import build_session_factory
from ..database.models import ScanORM, TargetORM, FindingORM, TechnologyORM
from ..repositories.scan_repo import SQLAlchemyScanRepository
from ..repositories.target_repo import SQLAlchemyTargetRepository
from ..repositories.finding_repo import SQLAlchemyFindingRepository
from ..repositories.technology_repo import SQLAlchemyTechnologyRepository
from ..streaming.publisher import InMemoryEventPublisher
from ..streaming.connection_manager import WebSocketConnectionManager
from ..management.scan_manager import ScanManager
from ..management.target_manager import TargetManager
from ..management.dashboard_service import DashboardService
from ..management.analytics_service import AnalyticsService
from ..di.containers import ApplicationContainer

# ── Module-level singletons ──────────────────────────────────────────────────
_engine: Optional[AsyncEngine] = None
_session_factory: Optional[async_sessionmaker] = None
_publisher: Optional[InMemoryEventPublisher] = None
_ws_manager: Optional[WebSocketConnectionManager] = None
_scan_manager: Optional[ScanManager] = None
_target_manager: Optional[TargetManager] = None
_dashboard_service: Optional[DashboardService] = None
_analytics_service: Optional[AnalyticsService] = None
_container: Optional[ApplicationContainer] = None


def get_db_session_factory() -> async_sessionmaker:
    assert _session_factory is not None, "App not started"
    return _session_factory


def get_ws_manager() -> WebSocketConnectionManager:
    assert _ws_manager is not None, "App not started"
    return _ws_manager


def get_scan_manager() -> ScanManager:
    assert _scan_manager is not None, "App not started"
    return _scan_manager


def get_target_manager() -> TargetManager:
    assert _target_manager is not None, "App not started"
    return _target_manager


def get_dashboard_service() -> DashboardService:
    assert _dashboard_service is not None, "App not started"
    return _dashboard_service


def get_analytics_service() -> AnalyticsService:
    assert _analytics_service is not None, "App not started"
    return _analytics_service


def get_container() -> ApplicationContainer:
    assert _container is not None, "App not started"
    return _container


# ── Lifespan (startup / shutdown) ────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    global _engine, _session_factory, _publisher, _ws_manager
    global _scan_manager, _target_manager, _dashboard_service, _analytics_service
    global _container

    # Initialize Application Container
    config_dir = Path(__file__).parent.parent / "config"
    _container = ApplicationContainer(config_path=str(config_dir))
    _container.logging()
    
    # Ensure BrowserManager and HTTPClientManager lifecycle hooks are registered
    bm = _container.browser_manager()
    hm = _container.http_manager()
    lm = _container.lifecycle_manager()
    lm.add_startup_task(bm.start)
    lm.add_shutdown_task(bm.stop)
    lm.add_shutdown_task(hm.close)
    
    await lm.startup()

    database_url = os.environ.get(
        "DATABASE_URL",
        "sqlite+aiosqlite:///./scanner.db"
    )

    _engine = build_engine(database_url)
    _session_factory = build_session_factory(_engine)

    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    from ..database.upgrade import upgrade_schema
    await upgrade_schema(_engine)

    _publisher = InMemoryEventPublisher()
    _ws_manager = WebSocketConnectionManager(_publisher)

    _scan_manager = _build_scan_manager(_container)
    _target_manager = _build_target_manager()
    _dashboard_service = _build_dashboard_service()
    _analytics_service = _build_analytics_service()

    asyncio.create_task(_ws_manager.listen_and_forward("scan.progress"))
    asyncio.create_task(_ws_manager.listen_and_forward("scan.completed"))
    asyncio.create_task(_ws_manager.listen_and_forward("scan.created"))

    yield

    if _container:
        await _container.lifecycle_manager().shutdown()
    await _engine.dispose()


def _build_scan_manager(container: ApplicationContainer) -> ScanManager:
    class _SessionScanRepo:
        async def create(self, scan):
            async with _session_factory() as s:
                repo = SQLAlchemyScanRepository(s)
                result = await repo.create(scan)
                await s.commit()
                return result

        async def get_by_id(self, scan_id):
            async with _session_factory() as s:
                return await SQLAlchemyScanRepository(s).get_by_id(scan_id)

        async def get_all(self, skip=0, limit=100):
            async with _session_factory() as s:
                return await SQLAlchemyScanRepository(s).get_all(skip, limit)

        async def update(self, scan):
            async with _session_factory() as s:
                s.add(scan)
                await s.commit()
                await s.refresh(scan)
                return scan

        async def delete(self, scan_id):
            async with _session_factory() as s:
                await SQLAlchemyScanRepository(s).delete(scan_id)
                await s.commit()

        async def get_recent(self, limit=10):
            async with _session_factory() as s:
                return await SQLAlchemyScanRepository(s).get_recent(limit)

        async def count_by_status(self):
            async with _session_factory() as s:
                return await SQLAlchemyScanRepository(s).count_by_status()

    class _SessionFindingRepo:
        async def create(self, finding):
            async with _session_factory() as s:
                repo = SQLAlchemyFindingRepository(s)
                result = await repo.create(finding)
                await s.commit()
                return result

    class _SessionTechRepo:
        async def upsert(self, tech):
            async with _session_factory() as s:
                repo = SQLAlchemyTechnologyRepository(s)
                result = await repo.upsert(tech)
                await s.commit()
                return result

    return ScanManager(
        scan_repo=_SessionScanRepo(),
        finding_repo=_SessionFindingRepo(),
        tech_repo=_SessionTechRepo(),
        event_publisher=_publisher,
        crawler=container.crawl_manager(),
        fingerprinter=container.fingerprint_manager(),
        passive_scanner=container.passive_manager(),
        active_scanner=container.active_manager(),
        pipeline=container.finding_pipeline(),
        http_manager=container.http_manager(),
        network_exposure_scanner=container.network_exposure_scanner(),
        config=container.config()
    )


def _build_target_manager() -> TargetManager:
    class _SessionTargetRepo:
        async def create(self, target):
            async with _session_factory() as s:
                repo = SQLAlchemyTargetRepository(s)
                result = await repo.create(target)
                await s.commit()
                return result

        async def get_by_id(self, tid):
            async with _session_factory() as s:
                return await SQLAlchemyTargetRepository(s).get_by_id(tid)

        async def get_all(self, skip=0, limit=100):
            async with _session_factory() as s:
                return await SQLAlchemyTargetRepository(s).get_all(skip, limit)

        async def update(self, target):
            async with _session_factory() as s:
                s.add(target)
                await s.commit()
                await s.refresh(target)
                return target

        async def delete(self, tid):
            async with _session_factory() as s:
                await SQLAlchemyTargetRepository(s).delete(tid)
                await s.commit()

        async def get_by_url(self, url):
            async with _session_factory() as s:
                return await SQLAlchemyTargetRepository(s).get_by_url(url)

        async def count(self):
            async with _session_factory() as s:
                return await SQLAlchemyTargetRepository(s).count()

    return TargetManager(target_repo=_SessionTargetRepo())


def _build_dashboard_service() -> DashboardService:
    class _SessionScanRepo:
        async def get_recent(self, limit=5):
            async with _session_factory() as s:
                return await SQLAlchemyScanRepository(s).get_recent(limit)
        async def count_by_status(self):
            async with _session_factory() as s:
                return await SQLAlchemyScanRepository(s).count_by_status()
        async def create(self, x): pass
        async def get_by_id(self, x): pass
        async def get_all(self, **k): pass
        async def update(self, x): pass
        async def delete(self, x): pass

    class _SessionFindingRepo:
        async def get_all(self, skip=0, limit=5):
            async with _session_factory() as s:
                return await SQLAlchemyFindingRepository(s).get_all(skip, limit)
        async def count_by_severity(self):
            async with _session_factory() as s:
                return await SQLAlchemyFindingRepository(s).count_by_severity()
        async def count(self):
            async with _session_factory() as s:
                return await SQLAlchemyFindingRepository(s).count()
        async def create(self, x): pass
        async def get_by_id(self, x): pass
        async def get_by_scan(self, x): pass
        async def get_trend(self, **k): pass

    class _SessionTargetRepo:
        async def count(self):
            async with _session_factory() as s:
                return await SQLAlchemyTargetRepository(s).count()
        async def create(self, x): pass
        async def get_by_id(self, x): pass
        async def get_all(self, **k): pass
        async def update(self, x): pass
        async def delete(self, x): pass
        async def get_by_url(self, x): pass

    class _SessionTechRepo:
        async def count(self):
            async with _session_factory() as s:
                return await SQLAlchemyTechnologyRepository(s).count()
        async def upsert(self, x): pass
        async def get_all(self, **k): pass
        async def get_by_category(self, x): pass

    return DashboardService(
        scan_repo=_SessionScanRepo(),
        finding_repo=_SessionFindingRepo(),
        target_repo=_SessionTargetRepo(),
        technology_repo=_SessionTechRepo(),
    )


def _build_analytics_service() -> AnalyticsService:
    class _SessionFindingRepo:
        async def get_trend(self, days=30):
            async with _session_factory() as s:
                return await SQLAlchemyFindingRepository(s).get_trend(days)
        async def count_by_severity(self):
            async with _session_factory() as s:
                return await SQLAlchemyFindingRepository(s).count_by_severity()
        async def get_all(self, limit=500):
            async with _session_factory() as s:
                return await SQLAlchemyFindingRepository(s).get_all(limit=limit)
        async def create(self, x): pass
        async def get_by_id(self, x): pass
        async def get_by_scan(self, x): pass
        async def count(self): pass

    class _SessionScanRepo:
        async def count_by_status(self):
            async with _session_factory() as s:
                return await SQLAlchemyScanRepository(s).count_by_status()
        async def create(self, x): pass
        async def get_by_id(self, x): pass
        async def get_all(self, **k): pass
        async def update(self, x): pass
        async def delete(self, x): pass
        async def get_recent(self, **k): pass

    return AnalyticsService(
        finding_repo=_SessionFindingRepo(),
        scan_repo=_SessionScanRepo(),
    )


# ── App factory ───────────────────────────────────────────────────────────────
def create_app() -> FastAPI:
    from .routes.health import router as health_router
    from .routes.findings import router as findings_router
    from .routes.scans import router as scans_router
    from .routes.targets import router as targets_router
    from .routes.technologies import router as technologies_router
    from .routes.analytics import router as analytics_router
    from .routes.dashboard import router as dashboard_router
    from .routes.ws import router as ws_router
    from .routes.reports import router as reports_router, build_report_data

    application = FastAPI(
        title="Enterprise Security Scanner API",
        description="Enterprise-grade vulnerability scanner REST API + WebSocket interface.",
        version="2.4.0-enterprise",
        lifespan=lifespan,
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    application.include_router(health_router)
    application.include_router(findings_router)
    application.include_router(scans_router)
    application.include_router(targets_router)
    application.include_router(technologies_router)
    application.include_router(analytics_router)
    application.include_router(dashboard_router)
    application.include_router(ws_router)
    application.include_router(reports_router)

    # DIRECT OVERRIDE ROUTE: Guarantees GET export endpoint registers in OpenAPI
    @application.get("/api/v1/reports/{scan_id}/export", tags=["Reports"], summary="Export Report File")
    async def direct_export_report(scan_id: str, format: str = "pdf"):
        from fastapi import HTTPException
        from fastapi.responses import FileResponse
        import os

        scan, output_paths = await build_report_data(scan_id, [format])

        file_path = output_paths.get(format)
        if not file_path or not os.path.exists(file_path):
            raise HTTPException(status_code=500, detail=f"Failed to render {format} report file")

        media_type_map = {
            "pdf": "application/pdf",
            "html": "text/html",
            "json": "application/json",
            "sarif": "application/json",
            "md": "text/markdown"
        }
        media_type = media_type_map.get(format.lower(), "application/octet-stream")

        return FileResponse(
            path=file_path,
            filename=f"report_{scan.id}.{format}",
            media_type=media_type,
            headers={
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Content-Disposition": f"inline; filename=report_{scan.id}.{format}"
            }
        )

    # Register static file mounts
    import os
    from fastapi.staticfiles import StaticFiles
    os.makedirs("reports", exist_ok=True)
    application.mount("/static-reports", StaticFiles(directory="reports"), name="static_reports")
    application.mount("/reports", StaticFiles(directory="reports"), name="reports_static")

    return application

# Expose app instance at module scope for main.py imports
app = create_app()