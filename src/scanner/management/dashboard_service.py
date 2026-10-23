"""DashboardService — aggregates data for all dashboard overview widgets."""
from typing import Dict, Any, List
from ..interfaces.repositories import (
    AbstractScanRepository,
    AbstractFindingRepository,
    AbstractTargetRepository,
    AbstractTechnologyRepository,
)


class DashboardService:

    def __init__(
        self,
        scan_repo: AbstractScanRepository,
        finding_repo: AbstractFindingRepository,
        target_repo: AbstractTargetRepository,
        technology_repo: AbstractTechnologyRepository,
    ) -> None:
        self._scans = scan_repo
        self._findings = finding_repo
        self._targets = target_repo
        self._technologies = technology_repo

    async def get_summary(self) -> Dict[str, Any]:
        """Returns all data needed to populate the Dashboard Overview page."""
        scan_counts = await self._scans.count_by_status()
        severity_counts = await self._findings.count_by_severity()

        total_scans = sum(scan_counts.values())
        running = scan_counts.get("running", 0)
        completed = scan_counts.get("completed", 0)
        failed = scan_counts.get("failed", 0)

        total_findings = sum(severity_counts.values())
        critical = severity_counts.get("Critical", 0) + severity_counts.get("CRITICAL", 0)
        high = severity_counts.get("High", 0) + severity_counts.get("HIGH", 0)
        medium = severity_counts.get("Medium", 0) + severity_counts.get("MEDIUM", 0)
        low = severity_counts.get("Low", 0) + severity_counts.get("LOW", 0)
        info = severity_counts.get("Info", 0) + severity_counts.get("INFO", 0)

        # Count active vs passive findings
        all_findings = await self._findings.get_all(skip=0, limit=1000)
        active_count = sum(1 for f in all_findings if f.plugin_id.startswith("ACT-"))
        passive_count = sum(1 for f in all_findings if f.plugin_id.startswith("PASS-"))

        target_count = await self._targets.count()
        tech_count = await self._technologies.count()

        recent_scans = await self._scans.get_recent(limit=5)
        recent_findings = await self._findings.get_all(skip=0, limit=5)

        return {
            "scans": {
                "total": total_scans,
                "running": running,
                "completed": completed,
                "failed": failed,
            },
            "findings": {
                "total": total_findings,
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "info": info,
                "active": active_count,
                "passive": passive_count,
            },
            "targets": target_count,
            "technologies": tech_count,
            "recent_scans": [self._format_scan(s) for s in recent_scans],
            "recent_findings": [self._format_finding(f) for f in recent_findings],
        }

    def _format_scan(self, scan: Any) -> dict:
        return {
            "id": scan.id,
            "target_url": scan.target_url,
            "status": scan.status,
            "progress": scan.progress,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
        }

    def _format_finding(self, finding: Any) -> dict:
        return {
            "id": finding.id,
            "title": finding.title,
            "severity": finding.severity,
            "endpoint": finding.endpoint,
            "created_at": finding.created_at.isoformat() if finding.created_at else None,
        }
