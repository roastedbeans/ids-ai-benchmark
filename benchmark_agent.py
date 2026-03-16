#!/usr/bin/env python3
"""
Detection Agent Benchmark - Overhead Computation and Memory

Benchmarks the specification-based detection agent (BR-1 to BR-43) with
the same metrics and output format as the AI model benchmark.

Metrics measured:
- Detection latency (overhead computation)
- Memory usage (peak CPU memory)
- Accuracy (TP, TN, FP, FN, precision, recall, F1)

Usage:
    python benchmark_agent.py [--data-dir csv_spec] [--output-dir /path] [--num-runs 100]
"""

import argparse
import gc
import glob
import json
import os
import platform
import shutil
import tempfile
import time
import tracemalloc
from datetime import datetime
from typing import Dict, List, Optional

from detection_agent import DetectionAgent


# ======================================================
# Utility Functions
# ======================================================
def get_system_info() -> Dict:
    """Collect system information for benchmark context."""
    return {
        "timestamp": datetime.now().isoformat(),
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "cpu_count": os.cpu_count(),
    }


def _percentile(times: list, p: float) -> float:
    """Compute percentile (0-100)."""
    if not times:
        return 0.0
    if len(times) == 1:
        return float(times[0])
    idx = min(int(len(times) * p / 100), len(times) - 1)
    return float(sorted(times)[idx])


def measure_inference_time(
    agent: DetectionAgent,
    rows_by_file: List[tuple],
    num_runs: int = 100,
    warmup_runs: int = 10,
) -> Dict:
    """Measure inference-only time (no I/O), matching AI benchmark.

    Pre-loaded rows are analyzed repeatedly. Same scope as AI: pure
    inference on in-memory data.
    """
    # Warmup
    for _ in range(warmup_runs):
        for _, rows in rows_by_file:
            agent.analyze_rows(rows)

    # Per-sample (single file) timing - matches AI's per-sample metric
    per_sample_times = []
    for _, rows in rows_by_file:
        for _ in range(num_runs):
            start = time.perf_counter()
            agent.analyze_rows(rows)
            per_sample_times.append((time.perf_counter() - start) * 1000)

    # Batch timing (all files, one run)
    batch_times = []
    for _ in range(num_runs):
        start = time.perf_counter()
        for _, rows in rows_by_file:
            agent.analyze_rows(rows)
        batch_times.append((time.perf_counter() - start) * 1000)

    return {
        "avg_time_ms": float(sum(per_sample_times) / len(per_sample_times)),
        "std_time_ms": float((sum((t - sum(per_sample_times) / len(per_sample_times)) ** 2 for t in per_sample_times) / len(per_sample_times)) ** 0.5) if len(per_sample_times) > 1 else 0.0,
        "min_time_ms": float(min(per_sample_times)),
        "max_time_ms": float(max(per_sample_times)),
        "p50_time_ms": _percentile(per_sample_times, 50),
        "p95_time_ms": _percentile(per_sample_times, 95),
        "p99_time_ms": _percentile(per_sample_times, 99),
        "per_sample_avg_ms": float(sum(per_sample_times) / len(per_sample_times)),
        "batch_avg_ms": float(sum(batch_times) / len(batch_times)),
        "batch_std_ms": float((sum((t - sum(batch_times) / len(batch_times)) ** 2 for t in batch_times) / len(batch_times)) ** 0.5) if len(batch_times) > 1 else 0.0,
    }


def measure_full_pipeline_time(
    agent: DetectionAgent,
    csv_normal: str,
    csv_attack: str,
    num_runs: int = 100,
    warmup_runs: int = 10,
) -> Dict:
    """Measure full pipeline time (I/O + inference) for reference."""
    for _ in range(warmup_runs):
        agent.detect_all(csv_normal)
        agent.detect_all(csv_attack)

    times = []
    for _ in range(num_runs):
        start = time.perf_counter()
        agent.detect_all(csv_normal)
        agent.detect_all(csv_attack)
        times.append((time.perf_counter() - start) * 1000)

    return {
        "avg_time_ms": float(sum(times) / len(times)),
        "std_time_ms": float((sum((t - sum(times) / len(times)) ** 2 for t in times) / len(times)) ** 0.5) if len(times) > 1 else 0.0,
        "min_time_ms": float(min(times)),
        "max_time_ms": float(max(times)),
    }


def measure_memory_usage(agent: DetectionAgent, rows_by_file: List[tuple]) -> Dict:
    """Measure peak CPU memory during inference only (same as AI benchmark)."""
    gc.collect()
    tracemalloc.start()

    for _, rows in rows_by_file:
        agent.analyze_rows(rows)

    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return {
        "model_memory_mb": 0.0,  # No model weights for spec-based agent
        "peak_cpu_memory_mb": float(peak / (1024 ** 2)),
        "current_cpu_memory_mb": float(current / (1024 ** 2)),
    }


def measure_attack_detection_time(
    agent: DetectionAgent,
    csv_attack: str,
    num_runs: int = 50,
) -> Dict:
    """Measure per-file detection time on attack samples (same structure as AI benchmark)."""
    attack_files = sorted(glob.glob(os.path.join(csv_attack, "*.csv")))
    if not attack_files:
        return {"error": "No attack samples available"}

    # Limit samples for timing
    num_test = min(len(attack_files), num_runs * 2)
    test_files = attack_files[:num_test]

    detection_times = []
    predictions = []

    for path in test_files:
        start = time.perf_counter()
        result = agent.detect(path)
        elapsed = (time.perf_counter() - start) * 1000

        detection_times.append(elapsed)
        predictions.append(1 if result.get("verdict") == "ANOMALOUS" else 0)

    times_arr = detection_times
    attacks_detected = sum(predictions)
    detection_rate = attacks_detected / len(predictions) if predictions else 0.0

    return {
        "samples_tested": len(test_files),
        "avg_detection_time_ms": float(sum(times_arr) / len(times_arr)),
        "std_detection_time_ms": float((sum((t - sum(times_arr) / len(times_arr)) ** 2 for t in times_arr) / len(times_arr)) ** 0.5) if len(times_arr) > 1 else 0.0,
        "min_detection_time_ms": float(min(times_arr)),
        "max_detection_time_ms": float(max(times_arr)),
        "p95_detection_time_ms": float(sorted(times_arr)[int(len(times_arr) * 0.95)] if len(times_arr) > 1 else times_arr[0]),
        "p99_detection_time_ms": float(sorted(times_arr)[int(len(times_arr) * 0.99)] if len(times_arr) > 1 else times_arr[0]),
        "attacks_detected": attacks_detected,
        "detection_rate": detection_rate,
        "attack_types_tested": list(set(os.path.basename(f).split("_")[0] for f in test_files)),
    }


# ======================================================
# Main Benchmark
# ======================================================
def run_benchmarks(
    data_dir: str,
    output_dir: str,
    num_runs: int = 100,
) -> Dict:
    """Run overhead computation and memory benchmarks on detection agent."""
    print("=" * 70)
    print("Detection Agent Benchmark - Overhead Computation & Memory")
    print("=" * 70)

    data_dir = os.path.abspath(data_dir)
    if not os.path.isdir(data_dir):
        raise FileNotFoundError(f"Data directory not found: {data_dir}")

    # Split files: normal_data* = normal, else = attack
    all_csv = sorted(glob.glob(os.path.join(data_dir, "*.csv")))
    normal_files = [f for f in all_csv if os.path.basename(f).startswith("normal_data")]
    attack_files = [f for f in all_csv if f not in normal_files]

    if not normal_files or not attack_files:
        raise ValueError(f"Need both normal and attack files. Normal: {len(normal_files)}, Attack: {len(attack_files)}")

    # System info
    system_info = get_system_info()
    print(f"\nSystem Information:")
    print(f"  Platform: {system_info['platform']}")
    print(f"  Python: {system_info['python_version']}")
    print(f"  CPU Count: {system_info['cpu_count']}")
    print(f"\nData: {data_dir}  ({len(normal_files)} normal, {len(attack_files)} attack)")

    # Create temp dirs
    with tempfile.TemporaryDirectory() as tmp:
        csv_normal = os.path.join(tmp, "csv_normal")
        csv_attack = os.path.join(tmp, "csv_attack")
        os.makedirs(csv_normal)
        os.makedirs(csv_attack)
        for f in normal_files:
            shutil.copy(f, os.path.join(csv_normal, os.path.basename(f)))
        for f in attack_files:
            shutil.copy(f, os.path.join(csv_attack, os.path.basename(f)))

        agent = DetectionAgent()

        # Pre-load all rows (inference-only benchmark, like AI)
        rows_by_file: List[tuple] = []
        for p in sorted(glob.glob(os.path.join(csv_normal, "*.csv"))):
            rows_by_file.append((p, agent._read(p)))
        for p in sorted(glob.glob(os.path.join(csv_attack, "*.csv"))):
            rows_by_file.append((p, agent._read(p)))

        total_rows = sum(len(rows) for _, rows in rows_by_file)
        n_files = len(rows_by_file)

        # --- Accuracy ---
        print(f"\n{'='*60}")
        print("Accuracy Evaluation")
        print(f"{'='*60}")
        normal_results = agent.detect_all(csv_normal)
        attack_results = agent.detect_all(csv_attack)

        tp = sum(1 for r in attack_results if r.get("verdict") == "ANOMALOUS")
        tn = sum(1 for r in normal_results if r.get("verdict") == "NORMAL")
        fp = sum(1 for r in normal_results if r.get("verdict") == "ANOMALOUS")
        fn = sum(1 for r in attack_results if r.get("verdict") == "NORMAL")
        total = tp + tn + fp + fn

        acc = (tp + tn) / total if total else 0.0
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0

        accuracy_results = {
            "tp": tp, "tn": tn, "fp": fp, "fn": fn, "total": total,
            "accuracy": acc, "precision": prec, "recall": rec, "f1": f1,
        }
        print(f"  TP={tp}  TN={tn}  FP={fp}  FN={fn}  (total={total})")
        print(f"  Accuracy: {acc:.1%}  Precision: {prec:.1%}  Recall: {rec:.1%}  F1: {f1:.1%}")

        # --- Inference time (pure, no I/O - matches AI benchmark) ---
        print(f"\n{'='*60}")
        print("Measuring inference time (computation overhead, no I/O)...")
        print(f"{'='*60}")
        time_results = measure_inference_time(
            agent, rows_by_file,
            num_runs=num_runs, warmup_runs=10,
        )
        print(f"  Per-sample (single file) avg: {time_results['per_sample_avg_ms']:.4f} ms")
        print(f"  Std Dev: {time_results['std_time_ms']:.4f} ms")
        print(f"  P50: {time_results['p50_time_ms']:.4f} ms  P95: {time_results['p95_time_ms']:.4f} ms")
        print(f"  Batch ({n_files} files) avg: {time_results['batch_avg_ms']:.4f} ms")
        throughput = total_rows / (time_results["batch_avg_ms"] / 1000) if time_results["batch_avg_ms"] else 0
        print(f"  Throughput: {throughput:.0f} rows/sec")

        # --- Full pipeline time (I/O + inference) ---
        pipeline_results = measure_full_pipeline_time(
            agent, csv_normal, csv_attack,
            num_runs=min(num_runs, 20), warmup_runs=5,
        )
        print(f"  Full pipeline (I/O+inference): {pipeline_results['avg_time_ms']:.1f} ms")

        # --- Memory usage (inference only) ---
        print(f"\n{'='*60}")
        print("Measuring memory usage...")
        print(f"{'='*60}")
        memory_results = measure_memory_usage(agent, rows_by_file)
        print(f"  Peak CPU Memory: {memory_results['peak_cpu_memory_mb']:.4f} MB")

        # --- Attack detection time (per-file) ---
        print(f"\n{'='*60}")
        print("Measuring attack detection time on real dataset...")
        print(f"{'='*60}")
        detection_results = measure_attack_detection_time(
            agent, csv_attack, num_runs=min(num_runs, 50),
        )
        if "error" not in detection_results:
            print(f"  Samples tested: {detection_results['samples_tested']}")
            print(f"  Average detection time: {detection_results['avg_detection_time_ms']:.4f} ms")
            print(f"  Detection rate: {detection_results['detection_rate']:.4f}")

    # Build results (same structure as AI benchmark)
    all_results = {
        "system_info": system_info,
        "config": {
            "data_dir": data_dir,
            "num_files": n_files,
            "num_rows": total_rows,
            "num_inference_runs": num_runs,
        },
        "accuracy": accuracy_results,
        "inference_time": time_results,
        "full_pipeline_time": pipeline_results,
        "memory_usage": memory_results,
        "attack_detection": detection_results,
        "throughput_rows_per_sec": throughput,
    }

    # Save results
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    json_path = os.path.join(output_dir, f"agent_benchmark_results_{timestamp}.json")
    with open(json_path, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\nResults saved to: {json_path}")

    report_path = os.path.join(output_dir, f"agent_benchmark_report_{timestamp}.txt")
    generate_report(all_results, report_path)
    print(f"Report saved to: {report_path}")

    return all_results


def generate_report(results: Dict, output_path: str) -> None:
    """Generate human-readable benchmark report (same format as AI benchmark)."""
    lines = []
    lines.append("=" * 80)
    lines.append("DETECTION AGENT BENCHMARK REPORT")
    lines.append("Overhead Computation & Memory Analysis")
    lines.append("=" * 80)
    lines.append("")

    sys_info = results["system_info"]
    lines.append("SYSTEM INFORMATION")
    lines.append("-" * 40)
    lines.append(f"Timestamp: {sys_info['timestamp']}")
    lines.append(f"Platform: {sys_info['platform']}")
    lines.append(f"Python: {sys_info['python_version']}")
    lines.append(f"CPU Count: {sys_info['cpu_count']}")
    lines.append("")

    config = results["config"]
    lines.append("CONFIGURATION")
    lines.append("-" * 40)
    lines.append(f"Data Dir: {config['data_dir']}")
    lines.append(f"Files: {config['num_files']}  Rows: {config['num_rows']}")
    lines.append(f"Inference Runs: {config['num_inference_runs']}")
    lines.append("")

    acc = results["accuracy"]
    lines.append("ACCURACY")
    lines.append("-" * 40)
    lines.append(f"TP={acc['tp']}  TN={acc['tn']}  FP={acc['fp']}  FN={acc['fn']}  (total={acc['total']})")
    lines.append(f"Accuracy: {acc['accuracy']:.1%}  Precision: {acc['precision']:.1%}  Recall: {acc['recall']:.1%}  F1: {acc['f1']:.1%}")
    lines.append("")

    inf = results["inference_time"]
    lines.append("INFERENCE TIME (Computation Overhead, no I/O - matches AI)")
    lines.append("-" * 40)
    lines.append(f"  Per-sample (single file) avg: {inf['per_sample_avg_ms']:.4f} ms")
    lines.append(f"  Std Dev: {inf['std_time_ms']:.4f} ms")
    lines.append(f"  Min: {inf['min_time_ms']:.4f} ms  Max: {inf['max_time_ms']:.4f} ms")
    lines.append(f"  P50: {inf['p50_time_ms']:.4f} ms  P95: {inf['p95_time_ms']:.4f} ms  P99: {inf['p99_time_ms']:.4f} ms")
    lines.append(f"  Batch avg: {inf['batch_avg_ms']:.4f} ms")
    lines.append(f"  Throughput: {results.get('throughput_rows_per_sec', 0):.0f} rows/sec")
    if "full_pipeline_time" in results:
        fp = results["full_pipeline_time"]
        lines.append(f"  Full pipeline (I/O+inference): {fp['avg_time_ms']:.1f} ms")
    lines.append("")

    mem = results["memory_usage"]
    lines.append("MEMORY USAGE")
    lines.append("-" * 40)
    lines.append(f"  Peak CPU Memory: {mem['peak_cpu_memory_mb']:.4f} MB")
    lines.append("")

    if "attack_detection" in results and "error" not in results["attack_detection"]:
        ad = results["attack_detection"]
        lines.append("ATTACK DETECTION (Real Dataset)")
        lines.append("-" * 40)
        lines.append(f"  Samples Tested: {ad['samples_tested']}")
        lines.append(f"  Average Detection Time: {ad['avg_detection_time_ms']:.4f} ms")
        lines.append(f"  P95 Detection Time: {ad['p95_detection_time_ms']:.4f} ms")
        lines.append(f"  Attacks Detected: {ad['attacks_detected']}/{ad['samples_tested']}")
        lines.append(f"  Detection Rate: {ad['detection_rate']:.4f}")
        lines.append("")

    lines.append("=" * 80)
    lines.append("END OF REPORT")
    lines.append("=" * 80)

    with open(output_path, "w") as f:
        f.write("\n".join(lines))


# ======================================================
# Entry Point
# ======================================================
def main() -> int:
    parser = argparse.ArgumentParser(description="Detection Agent Benchmark")
    parser.add_argument(
        "--data-dir",
        default=os.path.join(os.path.dirname(__file__), "csv_spec"),
        help="Directory containing CSV files (default: ai-detection/csv_spec)",
    )
    parser.add_argument(
        "--output-dir",
        default="benchmark_results",
        help="Directory to save benchmark results (default: benchmark_results)",
    )
    parser.add_argument(
        "--num-runs",
        type=int,
        default=100,
        help="Number of inference runs for timing (default: 100)",
    )
    args = parser.parse_args()

    try:
        run_benchmarks(args.data_dir, args.output_dir, args.num_runs)
        print("\n" + "=" * 70)
        print("BENCHMARK COMPLETE")
        print("=" * 70)
        return 0
    except Exception as e:
        print(f"ERROR: {e}")
        return 1


if __name__ == "__main__":
    exit(main())
