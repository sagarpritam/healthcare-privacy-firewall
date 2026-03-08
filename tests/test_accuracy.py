"""
Healthcare Privacy Firewall — Detection Accuracy Benchmark
===========================================================
Tests the detection engine against labeled ground-truth samples.
Measures Precision, Recall, F1-Score, and overall Accuracy.
"""

import sys
import os
from pathlib import Path

# Add project root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from workers.text_worker.regex_detector import RegexDetector

# ──────────────────────────────────────────────────────────────
# Ground Truth Test Dataset
# Each entry: (text, expected_entity_types)
# expected_entity_types = set of entity types that SHOULD be detected
# ──────────────────────────────────────────────────────────────

GROUND_TRUTH = [
    # ── True Positives: Text WITH known PHI ──
    {
        "text": "Patient John Doe, DOB: 01/15/1985, was admitted for chest pain.",
        "expected": {"DATE_OF_BIRTH"},
        "description": "DOB in MM/DD/YYYY format"
    },
    {
        "text": "Contact the patient at john.doe@hospital.com for follow-up.",
        "expected": {"EMAIL"},
        "description": "Email address"
    },
    {
        "text": "Patient SSN: 123-45-6789. Please verify insurance.",
        "expected": {"SSN"},
        "description": "Social Security Number"
    },
    {
        "text": "Medical Record Number: MRN-445566 for Alice Johnson.",
        "expected": {"MEDICAL_RECORD_NUMBER"},
        "description": "Medical Record Number"
    },
    {
        "text": "Patient born on 1990-03-22, diagnosed with Type 2 Diabetes.",
        "expected": {"DATE_OF_BIRTH"},
        "description": "DOB in YYYY-MM-DD format"
    },
    {
        "text": "Reach out to jane_smith@clinic.org regarding lab results.",
        "expected": {"EMAIL"},
        "description": "Email with underscore"
    },
    {
        "text": "File under MRN PT-112233. Prescribed metformin 500mg.",
        "expected": {"MEDICAL_RECORD_NUMBER"},
        "description": "MRN with PT- prefix"
    },
    {
        "text": "DOB is 11-22-1975. Patient reports chronic migraines.",
        "expected": {"DATE_OF_BIRTH"},
        "description": "DOB in MM-DD-YYYY format"
    },
    {
        "text": "SSN on file: 987-65-4321. Coverage under BlueCross.",
        "expected": {"SSN"},
        "description": "SSN with surrounding context"
    },
    {
        "text": "Patient DOB 05/30/92, email: bob.w@test.net, MRN MED-778899.",
        "expected": {"DATE_OF_BIRTH", "EMAIL", "MEDICAL_RECORD_NUMBER"},
        "description": "Multiple PHI types in one payload"
    },
    {
        "text": "Contact: alice@health.io. SSN: 555-44-3333. Born 1988-12-01.",
        "expected": {"EMAIL", "SSN", "DATE_OF_BIRTH"},
        "description": "Triple PHI payload"
    },
    {
        "text": "Billing for patient MRN-001122, DOB 07/04/1976.",
        "expected": {"MEDICAL_RECORD_NUMBER", "DATE_OF_BIRTH"},
        "description": "MRN + DOB combination"
    },

    # ── True Negatives: Text WITHOUT any PHI ──
    {
        "text": "The hospital cafeteria serves lunch from 12:00 to 2:00 PM.",
        "expected": set(),
        "description": "Clean text: cafeteria hours"
    },
    {
        "text": "Please ensure all staff complete the annual fire safety training.",
        "expected": set(),
        "description": "Clean text: staff training"
    },
    {
        "text": "The new MRI machine will be installed in Wing B next month.",
        "expected": set(),
        "description": "Clean text: equipment update"
    },
    {
        "text": "Board meeting scheduled for Q3 budget review.",
        "expected": set(),
        "description": "Clean text: meeting notice"
    },
    {
        "text": "Flu season advisory: wash hands frequently and wear masks.",
        "expected": set(),
        "description": "Clean text: health advisory"
    },
    {
        "text": "Parking lot A will be closed for maintenance this weekend.",
        "expected": set(),
        "description": "Clean text: parking notice"
    },
]


def run_accuracy_benchmark():
    """Run the benchmark and calculate detection metrics."""
    detector = RegexDetector()

    total_samples = len(GROUND_TRUTH)
    true_positives = 0    # Correctly detected PHI
    false_positives = 0   # Detected PHI where none exists
    true_negatives = 0    # Correctly identified clean text
    false_negatives = 0   # Missed PHI that was present
    
    # Per-entity tracking
    entity_tp = {}
    entity_fn = {}
    entity_fp = {}

    print("=" * 80)
    print("  HEALTHCARE PRIVACY FIREWALL — DETECTION ACCURACY BENCHMARK")
    print("=" * 80)
    print()

    for i, sample in enumerate(GROUND_TRUTH, 1):
        text = sample["text"]
        expected = sample["expected"]
        desc = sample["description"]

        # Run detection
        detections = detector.detect(text)
        detected_types = {d["entity_type"] for d in detections}

        # Calculate metrics for this sample
        correctly_found = expected & detected_types
        missed = expected - detected_types
        false_found = detected_types - expected

        # Aggregate
        true_positives += len(correctly_found)
        false_negatives += len(missed)
        false_positives += len(false_found)

        if not expected and not detected_types:
            true_negatives += 1

        # Per-entity stats
        for e in correctly_found:
            entity_tp[e] = entity_tp.get(e, 0) + 1
        for e in missed:
            entity_fn[e] = entity_fn.get(e, 0) + 1
        for e in false_found:
            entity_fp[e] = entity_fp.get(e, 0) + 1

        # Print result
        if missed:
            status = "[MISS]"
        elif false_found:
            status = "[FP!!]"
        else:
            status = "[PASS]"

        print(f"  [{i:2d}/{total_samples}] {status}  {desc}")
        if missed:
            print(f"           └─ Missing: {missed}")
        if false_found:
            print(f"           └─ False Positive: {false_found}")

    # ── Calculate Overall Metrics ──
    print()
    print("=" * 80)
    print("  RESULTS SUMMARY")
    print("=" * 80)

    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    # Accuracy: correct predictions / total predictions
    total_entity_checks = true_positives + false_positives + false_negatives + true_negatives
    accuracy = (true_positives + true_negatives) / total_entity_checks if total_entity_checks > 0 else 0

    print(f"""
  ┌─────────────────────────────────────────────────┐
  │  True Positives  (correctly detected PHI):  {true_positives:3d}  │
  │  True Negatives  (correctly clean text):    {true_negatives:3d}  │
  │  False Positives (phantom detections):      {false_positives:3d}  │
  │  False Negatives (missed PHI):              {false_negatives:3d}  │
  ├─────────────────────────────────────────────────┤
  │  Precision:   {precision:.1%}                              │
  │  Recall:      {recall:.1%}                              │
  │  F1-Score:    {f1:.1%}                              │
  │  Accuracy:    {accuracy:.1%}                              │
  └─────────────────────────────────────────────────┘
    """)

    # ── Per-Entity Breakdown ──
    all_entities = set(list(entity_tp.keys()) + list(entity_fn.keys()) + list(entity_fp.keys()))
    if all_entities:
        print("  Per-Entity Breakdown:")
        print("  " + "-" * 55)
        print(f"  {'Entity':<20} {'TP':>5} {'FN':>5} {'FP':>5} {'Recall':>10}")
        print("  " + "-" * 55)
        for entity in sorted(all_entities):
            tp = entity_tp.get(entity, 0)
            fn = entity_fn.get(entity, 0)
            fp = entity_fp.get(entity, 0)
            r = tp / (tp + fn) if (tp + fn) > 0 else 0
            print(f"  {entity:<20} {tp:>5} {fn:>5} {fp:>5} {r:>9.1%}")
        print("  " + "-" * 55)

    print()
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "true_positives": true_positives,
        "true_negatives": true_negatives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
    }


if __name__ == "__main__":
    results = run_accuracy_benchmark()
