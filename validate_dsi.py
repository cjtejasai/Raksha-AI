"""
Validation script for DSI detector
Tests against the comprehensive dataset and reports metrics
"""

import csv
import json
import time
from pathlib import Path
from collections import defaultdict
from raksha_ai import SecurityScanner
from raksha_ai.detectors.dsi import DSIDetector
from raksha_ai.core.models import ThreatLevel


def load_dataset(dataset_path):
    """Load DSI attack dataset"""
    attacks = []
    benign = []
    edge_cases = []

    with open(dataset_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row['attack_id'].startswith('DSI-'):
                attacks.append(row)
            elif row['attack_id'].startswith('BENIGN-'):
                benign.append(row)
            elif row['attack_id'].startswith('EDGE-'):
                edge_cases.append(row)

    return attacks, benign, edge_cases


def evaluate_attacks(scanner, attacks):
    """Evaluate DSI detector on attack dataset"""
    results = {
        'total': len(attacks),
        'detected': 0,
        'missed': 0,
        'by_variant': defaultdict(lambda: {'total': 0, 'detected': 0}),
        'by_severity': defaultdict(lambda: {'total': 0, 'detected': 0}),
        'false_negatives': [],
        'detection_times': []
    }

    print(f"\n{'='*70}")
    print(f"EVALUATING {len(attacks)} ATTACK CASES")
    print(f"{'='*70}")

    for attack in attacks:
        attack_id = attack['attack_id']
        variant = attack['variant']
        severity = attack['severity']
        payload = attack['payload']
        should_block = attack['should_block'].lower() == 'true'
        expected_detection = attack['expected_detection']

        # Track by variant and severity
        results['by_variant'][variant]['total'] += 1
        results['by_severity'][severity]['total'] += 1

        # Run detection
        start = time.time()
        result = scanner.scan_input(payload)
        elapsed = (time.time() - start) * 1000
        results['detection_times'].append(elapsed)

        # Check if detected
        detected = len(result.threats) > 0
        has_critical = result.has_critical_threats

        if detected and (has_critical or severity in ['MEDIUM', 'LOW']):
            results['detected'] += 1
            results['by_variant'][variant]['detected'] += 1
            results['by_severity'][severity]['detected'] += 1

            # Verify correct threat type
            threat_types = [t.threat_type.value for t in result.threats]
            if expected_detection != 'none' and expected_detection not in threat_types:
                print(f"⚠️  {attack_id}: Detected but wrong type (expected {expected_detection}, got {threat_types})")
        else:
            results['missed'] += 1
            results['false_negatives'].append({
                'id': attack_id,
                'variant': variant,
                'severity': severity,
                'payload': payload[:60],
                'score': result.score
            })

    return results


def evaluate_benign(scanner, benign):
    """Evaluate false positive rate on benign inputs"""
    results = {
        'total': len(benign),
        'false_positives': 0,
        'critical_fps': 0,
        'fps': []
    }

    print(f"\n{'='*70}")
    print(f"EVALUATING {len(benign)} BENIGN CASES")
    print(f"{'='*70}")

    for case in benign:
        payload = case['payload']
        result = scanner.scan_input(payload)

        # Count critical false positives
        critical_threats = [t for t in result.threats if t.level == ThreatLevel.CRITICAL]
        if critical_threats:
            results['critical_fps'] += 1
            results['fps'].append({
                'payload': payload[:60],
                'threats': [t.threat_type.value for t in critical_threats]
            })

        # Count any false positives (high or critical)
        high_threats = [t for t in result.threats if t.level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]]
        if high_threats:
            results['false_positives'] += 1

    return results


def print_results(attack_results, benign_results):
    """Print comprehensive evaluation results"""
    print(f"\n{'='*70}")
    print("VALIDATION RESULTS - PHASE 1")
    print(f"{'='*70}\n")

    # Attack Detection Metrics
    print("📊 ATTACK DETECTION METRICS")
    print("-" * 70)
    total = attack_results['total']
    detected = attack_results['detected']
    detection_rate = (detected / total * 100) if total > 0 else 0

    print(f"Total Attacks:       {total}")
    print(f"Detected:            {detected}")
    print(f"Missed:              {attack_results['missed']}")
    print(f"Detection Rate:      {detection_rate:.1f}%")

    # Performance
    times = attack_results['detection_times']
    avg_time = sum(times) / len(times) if times else 0
    p95_time = sorted(times)[int(len(times) * 0.95)] if times else 0

    print(f"\n⚡ PERFORMANCE METRICS")
    print("-" * 70)
    print(f"Average Time:        {avg_time:.2f}ms")
    print(f"P95 Time:            {p95_time:.2f}ms")
    print(f"Max Time:            {max(times):.2f}ms" if times else "N/A")

    # Detection by Variant
    print(f"\n🎯 DETECTION BY VARIANT")
    print("-" * 70)
    for variant, stats in sorted(attack_results['by_variant'].items()):
        if stats['total'] > 0:
            rate = stats['detected'] / stats['total'] * 100
            status = "✅" if rate >= 85 else "⚠️ " if rate >= 70 else "❌"
            print(f"{status} {variant:10} {rate:5.1f}%  ({stats['detected']}/{stats['total']})")

    # Detection by Severity
    print(f"\n🔥 DETECTION BY SEVERITY")
    print("-" * 70)
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        stats = attack_results['by_severity'][severity]
        if stats['total'] > 0:
            rate = stats['detected'] / stats['total'] * 100
            status = "✅" if rate >= 90 else "⚠️ " if rate >= 75 else "❌"
            print(f"{status} {severity:10} {rate:5.1f}%  ({stats['detected']}/{stats['total']})")

    # False Positives
    print(f"\n🎭 FALSE POSITIVE ANALYSIS")
    print("-" * 70)
    total_benign = benign_results['total']
    fps = benign_results['false_positives']
    critical_fps = benign_results['critical_fps']
    fp_rate = (fps / total_benign * 100) if total_benign > 0 else 0
    critical_fp_rate = (critical_fps / total_benign * 100) if total_benign > 0 else 0

    print(f"Total Benign Cases:  {total_benign}")
    print(f"False Positives:     {fps} ({fp_rate:.1f}%)")
    print(f"Critical FPs:        {critical_fps} ({critical_fp_rate:.1f}%)")

    status = "✅" if critical_fp_rate < 5 else "⚠️ " if critical_fp_rate < 10 else "❌"
    print(f"{status} FP Rate Status:    {'GOOD' if critical_fp_rate < 5 else 'ACCEPTABLE' if critical_fp_rate < 10 else 'NEEDS IMPROVEMENT'}")

    # Accuracy Metrics
    print(f"\n📈 ACCURACY METRICS")
    print("-" * 70)
    true_positives = detected
    false_negatives = attack_results['missed']
    false_positives = critical_fps
    true_negatives = total_benign - false_positives

    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    accuracy = (true_positives + true_negatives) / (total + total_benign) if (total + total_benign) > 0 else 0

    print(f"Precision:           {precision:.3f} (TP/(TP+FP))")
    print(f"Recall:              {recall:.3f} (TP/(TP+FN))")
    print(f"F1 Score:            {f1:.3f}")
    print(f"Accuracy:            {accuracy:.3f}")

    # Success Criteria
    print(f"\n✨ PHASE 1 SUCCESS CRITERIA")
    print("-" * 70)
    criteria = [
        ("Detection Rate > 85%", detection_rate > 85, detection_rate),
        ("False Positive Rate < 5%", critical_fp_rate < 5, critical_fp_rate),
        ("Precision > 0.90", precision > 0.90, precision),
        ("Recall > 0.85", recall > 0.85, recall),
        ("F1 Score > 0.85", f1 > 0.85, f1),
        ("Average Time < 20ms", avg_time < 20, avg_time),
    ]

    passed = 0
    for criterion, result, value in criteria:
        status = "✅ PASS" if result else "❌ FAIL"
        passed += 1 if result else 0
        if "%" in criterion or "Rate" in criterion:
            print(f"{status}  {criterion:30} ({value:.1f})")
        elif "Time" in criterion:
            print(f"{status}  {criterion:30} ({value:.2f}ms)")
        else:
            print(f"{status}  {criterion:30} ({value:.3f})")

    print(f"\n{'='*70}")
    overall_status = "✅ PHASE 1 COMPLETE" if passed >= 5 else "⚠️  PHASE 1 NEEDS IMPROVEMENT"
    print(f"{overall_status} - {passed}/6 criteria passed")
    print(f"{'='*70}\n")

    # Show some false negatives
    if attack_results['false_negatives']:
        print(f"\n❌ FALSE NEGATIVES (showing first 10):")
        print("-" * 70)
        for fn in attack_results['false_negatives'][:10]:
            print(f"  {fn['id']} ({fn['variant']}, {fn['severity']})")
            print(f"    Payload: {fn['payload']}")
            print(f"    Score: {fn['score']:.3f}\n")

    # Show some false positives
    if benign_results['fps']:
        print(f"\n⚠️  FALSE POSITIVES (showing first 5):")
        print("-" * 70)
        for fp in benign_results['fps'][:5]:
            print(f"    Payload: {fp['payload']}")
            print(f"    Threats: {fp['threats']}\n")

    return passed >= 5


def main():
    """Run full validation"""
    print("\n🔱 RAKSHA-AI DSI DETECTOR VALIDATION")
    print("="*70)

    # Load dataset
    dataset_path = Path("datasets/dsi_attacks.csv")
    if not dataset_path.exists():
        print(f"❌ Dataset not found at {dataset_path}")
        return False

    attacks, benign, edge_cases = load_dataset(dataset_path)
    print(f"\n📦 Dataset Loaded:")
    print(f"   - {len(attacks)} attack cases")
    print(f"   - {len(benign)} benign cases")
    print(f"   - {len(edge_cases)} edge cases")

    # Create scanner with DSI detector only
    scanner = SecurityScanner(detectors=[DSIDetector()], enable_logging=False)
    print(f"\n🔍 Scanner initialized with DSI detector")

    # Evaluate
    attack_results = evaluate_attacks(scanner, attacks)
    benign_results = evaluate_benign(scanner, benign)

    # Print results
    success = print_results(attack_results, benign_results)

    return success


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)