"""AnalyticsService — trends, historical analysis, severity distribution."""
from typing import List, Dict, Any
from ..interfaces.repositories import AbstractFindingRepository, AbstractScanRepository


class AnalyticsService:

    def __init__(
        self,
        finding_repo: AbstractFindingRepository,
        scan_repo: AbstractScanRepository,
    ) -> None:
        self._findings = finding_repo
        self._scans = scan_repo

    async def get_findings_trend(self, days: int = 30) -> List[Dict[str, Any]]:
        """Returns time-series data of findings per day per severity for the last N days."""
        raw = await self._findings.get_trend(days=days)
        return raw

    async def get_severity_breakdown(self) -> Dict[str, int]:
        """Returns total counts by severity."""
        return await self._findings.count_by_severity()

    async def get_scan_status_breakdown(self) -> Dict[str, int]:
        return await self._scans.count_by_status()

    async def get_risk_distribution(self) -> List[Dict[str, Any]]:
        """Returns data for the risk score distribution chart."""
        findings = await self._findings.get_all(limit=500)
        buckets = {"0-2": 0, "2-4": 0, "4-6": 0, "6-8": 0, "8-10": 0}
        for f in findings:
            score = f.priority_score or 0.0
            if score < 2:
                buckets["0-2"] += 1
            elif score < 4:
                buckets["2-4"] += 1
            elif score < 6:
                buckets["4-6"] += 1
            elif score < 8:
                buckets["6-8"] += 1
            else:
                buckets["8-10"] += 1
        return [{"range": k, "count": v} for k, v in buckets.items()]
