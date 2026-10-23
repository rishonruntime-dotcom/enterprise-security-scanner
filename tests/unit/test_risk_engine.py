import pytest
from scanner.models.finding import Finding, Evidence, Severity, Confidence
from scanner.risk.models import AssetCriticality
from scanner.risk.calculators import CVSSCalculator, PriorityCalculator
from scanner.risk.engine import RiskEngine
from scanner.correlation.models import EnrichedFinding, VulnerabilityIntelligence
from scanner.correlation.risk_step import RiskCalculationStep

def test_cvss_calculator():
    score = CVSSCalculator.calculate_base(Severity.HIGH)
    assert score.base_score == 8.8
    assert "CVSS:3.1" in score.vector

def test_priority_calculator():
    # Base 8.8, EPSS 0.05, KEV False, Criticality MEDIUM
    res = PriorityCalculator.calculate(
        cvss=CVSSCalculator.calculate_base(Severity.HIGH),
        epss=type('EPSSScore', (), {'probability': 0.05, 'percentile': 0.20})(),
        is_kev=False,
        asset_criticality=AssetCriticality.MEDIUM
    )
    score_med = res[0]
    assert score_med == 8.8
    
    # Mission critical multiplier = 1.25 => 8.975 * 1.25 = 11.2 => capped at 10.0
    res_mc = PriorityCalculator.calculate(
        cvss=CVSSCalculator.calculate_base(Severity.HIGH),
        epss=type('EPSSScore', (), {'probability': 0.05, 'percentile': 0.20})(),
        is_kev=False,
        asset_criticality=AssetCriticality.MISSION_CRITICAL
    )
    score_mc = res_mc[0]
    assert score_mc == 10.0
    
    # KEV + HIGH = 10.0
    res_kev = PriorityCalculator.calculate(
        cvss=CVSSCalculator.calculate_base(Severity.LOW),
        epss=type('EPSSScore', (), {'probability': 0.05, 'percentile': 0.20})(),
        is_kev=True,
        asset_criticality=AssetCriticality.HIGH
    )
    score_kev = res_kev[0]
    assert score_kev == 10.0

@pytest.mark.asyncio
async def test_risk_step():
    from scanner.correlation.cvss_step import CVSSCalculationStep
    cvss_step = CVSSCalculationStep()
    engine = RiskEngine(default_criticality=AssetCriticality.MISSION_CRITICAL)
    step = RiskCalculationStep(risk_engine=engine)
    
    f1 = EnrichedFinding(
        plugin_id="ACT-XSS-001", title="Test", description="Test", severity=Severity.MEDIUM, confidence=Confidence.LOW, endpoint="https://example.com",
        intelligence=VulnerabilityIntelligence(cwe_id="CWE-79")
    )
    
    f1 = await cvss_step.process(f1)
    result = await step.process(f1)
    
    assert result.risk is not None
    assert result.risk.cvss.base_score == 6.5
    assert result.risk.epss.probability == 0.65
    assert result.risk.is_kev is False
    assert result.risk.asset_criticality == AssetCriticality.MISSION_CRITICAL
    assert result.risk.risk_breakdown is not None
    assert result.risk.risk_breakdown.impact > 0
    assert result.risk.risk_breakdown.exploitability > 0
    assert 0.0 <= result.risk.risk_breakdown.confidence <= 1.0
    assert result.risk.risk_breakdown.risk > 0
    assert "Likelihood" in result.risk.risk_breakdown.explanation
