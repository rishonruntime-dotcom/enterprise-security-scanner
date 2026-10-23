"""Tests for technology inventory improvements."""
import json
from datetime import datetime
from unittest.mock import MagicMock, AsyncMock

import pytest

from scanner.database.models.technology import TechnologyORM
from scanner.repositories.technology_repo import SQLAlchemyTechnologyRepository


def _make_orm(
    scan_id: str = "scan-123",
    name: str = "nginx",
    category: str = "server",
    version: str = "1.25.0",
    vendor: str = "nginx",
    confidence: float = 0.9,
    cpe: str = "cpe:2.3:a:nginx:nginx:1.25.0:*:*:*:*:*:*:*",
    target_url: str = "https://example.com",
    detection_method: str = "wappalyzer",
    detection_methods: str = '["wappalyzer"]',
    occurrence_count: int = 1,
) -> TechnologyORM:
    return TechnologyORM(
        id="tech-1",
        scan_id=scan_id,
        name=name,
        category=category,
        version=version,
        vendor=vendor,
        confidence=confidence,
        cpe=cpe,
        target_url=target_url,
        detection_method=detection_method,
        detection_methods=detection_methods,
        occurrence_count=occurrence_count,
        detected_at=datetime.now(),
    )


@pytest.mark.asyncio
async def test_upsert_inserts_new_technology():
    session = AsyncMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = None
    session.execute.return_value = result

    repo = SQLAlchemyTechnologyRepository(session)
    orm = _make_orm()

    created = MagicMock()
    repo.create = AsyncMock(return_value=created)

    resp = await repo.upsert(orm)
    assert resp is created
    repo.create.assert_awaited_once()


@pytest.mark.asyncio
async def test_upsert_merges_duplicate_technology():
    existing = _make_orm()
    existing.detection_methods = json.dumps(["wappalyzer"])
    existing.confidence = 0.7

    result = MagicMock()
    result.scalar_one_or_none.return_value = existing

    session = AsyncMock()
    session.execute.return_value = result

    repo = SQLAlchemyTechnologyRepository(session)
    repo.update = AsyncMock(return_value=existing)

    new_tech = _make_orm(version="1.26.0", detection_method="headers")
    resp = await repo.upsert(new_tech)

    assert resp is existing
    assert resp.occurrence_count == 2
    assert resp.confidence == 0.9
    assert resp.version == "1.26.0"
    assert json.loads(resp.detection_methods) == ["wappalyzer", "headers"]


@pytest.mark.asyncio
async def test_get_grouped_by_category():
    nginx = _make_orm(name="nginx", category="server")
    apache = _make_orm(name="apache", category="server", vendor="apache")
    php = _make_orm(name="php", category="language", confidence=0.5)

    repo = SQLAlchemyTechnologyRepository(MagicMock())
    repo.get_by_scan = AsyncMock(return_value=[nginx, apache, php])

    grouped = await repo.get_grouped_by_category("scan-123")

    assert "server" in grouped
    assert "language" in grouped
    assert len(grouped["server"]) == 2
    assert len(grouped["language"]) == 1


@pytest.mark.asyncio
async def test_detection_methods_parsed_as_list():
    existing = _make_orm()
    existing.detection_methods = json.dumps(["wappalyzer", "headers"])

    result = MagicMock()
    result.scalar_one_or_none.return_value = existing

    session = AsyncMock()
    session.execute.return_value = result

    repo = SQLAlchemyTechnologyRepository(session)
    repo.update = AsyncMock(return_value=existing)

    new_tech = _make_orm(detection_method="wappalyzer")
    await repo.upsert(new_tech)

    methods = json.loads(existing.detection_methods)
    assert "wappalyzer" in methods
    assert "headers" in methods
