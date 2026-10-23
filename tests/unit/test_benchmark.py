import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "src")))

from scanner.benchmarks.runner import run_benchmark_eval

def test_ground_truth_benchmark_metrics():
    """
    Evaluates the controlled ground-truth benchmark suite.
    Enforces high standards of precision, recall, CVSS calibration,
    confidence delta, technology fingerprinting, and attack chain synthesis.
    """
    metrics = run_benchmark_eval()

    # 1. Precision, Recall, F1 thresholds
    assert metrics["precision"] >= 0.75, f"Precision was too low: {metrics['precision']:.3f}"
    assert metrics["recall"] >= 0.75, f"Recall was too low: {metrics['recall']:.3f}"
    assert metrics["f1"] >= 0.75, f"F1 score was too low: {metrics['f1']:.3f}"

    # 2. Error rates (FPR and FNR)
    assert metrics["fpr"] <= 0.20, f"False Positive Rate too high: {metrics['fpr']:.3f}"
    assert metrics["fnr"] <= 0.15, f"False Negative Rate too high: {metrics['fnr']:.3f}"

    # 3. Calibration delta (Margin delta must be positive: TP confidence > FP confidence)
    conf_delta = metrics["avg_tp_confidence"] - metrics["avg_fp_confidence"]
    assert conf_delta > 0.10, f"Confidence Calibration delta must be significantly positive (margin: {conf_delta:.3f})"

    # 4. Severity and CVSS accuracy
    assert metrics["severity_accuracy"] >= 0.80, f"Severity Accuracy below threshold: {metrics['severity_accuracy']:.3f}"
    assert metrics["cvss_mae"] <= 1.0, f"CVSS Mean Absolute Error too high: {metrics['cvss_mae']:.3f}"

    # 5. Technology, Port, and Chain precision
    assert metrics["tech_precision"] >= 0.80, f"Technology precision below threshold: {metrics['tech_precision']:.3f}"
    assert metrics["port_accuracy"] >= 0.90, f"Port detection accuracy below threshold: {metrics['port_accuracy']:.3f}"
    assert metrics["chain_precision"] >= 0.80, f"Attack Chain synthesis precision below threshold: {metrics['chain_precision']:.3f}"
