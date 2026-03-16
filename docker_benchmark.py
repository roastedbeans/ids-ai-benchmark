#!/usr/bin/env python3
"""
FBS Detection Model Benchmark Script - Overhead Computation and Memory

This script benchmarks the FBS detection models (LSTM, GRU and CNN) for
overhead computation time and memory usage.

Metrics measured:
- Model inference latency (overhead computation)
- Memory usage (model size, peak memory)

Usage:
    python docker_benchmark.py [--output-dir /path/to/results] [--num-runs 100]
"""

import argparse
import gc
import glob
import json
import os
import platform
import sys
import time
import tracemalloc
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
import torch
import torch.nn as nn


# ======================================================
# Model Definitions (must match training definitions)
# ======================================================
class LSTMSeqClassifier(nn.Module):
    def __init__(self, feature_dim, hidden_dim=128, num_layers=2):
        super().__init__()
        self.lstm = nn.LSTM(
            input_size=feature_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=0.3,
            bidirectional=False
        )
        self.fc = nn.Sequential(
            nn.Linear(hidden_dim, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, 2)
        )

    def forward(self, x):
        out, (hn, cn) = self.lstm(x)
        last_hidden = hn[-1]
        return self.fc(last_hidden)


class GRUSeqClassifier(nn.Module):
    def __init__(self, feature_dim, hidden_dim=128, num_layers=2):
        super().__init__()
        self.gru = nn.GRU(
            input_size=feature_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=0.3,
            bidirectional=False
        )
        self.fc = nn.Sequential(
            nn.Linear(hidden_dim, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, 2)
        )

    def forward(self, x):
        out, hn = self.gru(x)
        last_hidden = hn[-1]
        return self.fc(last_hidden)


class CNN1DSeqClassifier(nn.Module):
    def __init__(self, input_channels, seq_length):
        super().__init__()

        self.conv_layers = nn.Sequential(
            nn.Conv1d(input_channels, 256, kernel_size=3, padding=1),
            nn.BatchNorm1d(256),
            nn.ReLU(),
            nn.MaxPool1d(kernel_size=2, stride=2),
            nn.Dropout(0.2),

            nn.Conv1d(256, 128, kernel_size=3, padding=1),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.MaxPool1d(kernel_size=2, stride=2),
            nn.Dropout(0.2),

            nn.Conv1d(128, 64, kernel_size=3, padding=1),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Dropout(0.2),
        )

        conv_output_size = seq_length // 4
        flattened_size = 64 * conv_output_size

        self.fc_layers = nn.Sequential(
            nn.Linear(flattened_size, 128),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, 2)
        )

    def forward(self, x):
        x = self.conv_layers(x)
        x = x.view(x.size(0), -1)
        x = self.fc_layers(x)
        return x


# ======================================================
# Configuration
# ======================================================
WINDOW_SIZE = 20
FEATURE_DIM = 1408
DATASET_PATH = os.path.join(os.path.dirname(__file__), "dataset", "csv_output")

MODELS = {
    "lstm": {
        "model_path": "/app/notebooks/fbsdetector_lstm.pth",
        "scaling_path": "/app/notebooks/scaling_parameters_lstm.json",
        "class": LSTMSeqClassifier,
        "type": "rnn"
    },
    "gru": {
        "model_path": "/app/notebooks/fbsdetector_gru.pth",
        "scaling_path": "/app/notebooks/scaling_parameters_gru.json",
        "class": GRUSeqClassifier,
        "type": "rnn"
    },
    "cnn": {
        "model_path": "/app/notebooks/fbsdetector_cnn.pth",
        "scaling_path": "/app/notebooks/scaling_parameters_cnn.json",
        "class": CNN1DSeqClassifier,
        "type": "cnn"
    }
}


# ======================================================
# Utility Functions
# ======================================================
def get_system_info() -> Dict:
    """Collect system information for benchmark context."""
    info = {
        "timestamp": datetime.now().isoformat(),
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "torch_version": torch.__version__,
        "cpu_count": os.cpu_count(),
        "torch_num_threads": torch.get_num_threads(),
    }

    # Get memory info from cgroup (Docker container limits)
    try:
        with open("/sys/fs/cgroup/memory/memory.limit_in_bytes", "r") as f:
            mem_limit = int(f.read().strip())
            info["container_memory_limit_gb"] = mem_limit / (1024**3)
    except (FileNotFoundError, PermissionError):
        # Try cgroup v2
        try:
            with open("/sys/fs/cgroup/memory.max", "r") as f:
                content = f.read().strip()
                if content != "max":
                    mem_limit = int(content)
                    info["container_memory_limit_gb"] = mem_limit / (1024**3)
        except (FileNotFoundError, PermissionError):
            info["container_memory_limit_gb"] = "unknown"

    # Get CPU quota from cgroup
    try:
        with open("/sys/fs/cgroup/cpu/cpu.cfs_quota_us", "r") as f:
            quota = int(f.read().strip())
        with open("/sys/fs/cgroup/cpu/cpu.cfs_period_us", "r") as f:
            period = int(f.read().strip())
        if quota > 0:
            info["container_cpu_limit"] = quota / period
    except (FileNotFoundError, PermissionError):
        # Try cgroup v2
        try:
            with open("/sys/fs/cgroup/cpu.max", "r") as f:
                content = f.read().strip().split()
                if content[0] != "max":
                    quota = int(content[0])
                    period = int(content[1])
                    info["container_cpu_limit"] = quota / period
        except (FileNotFoundError, PermissionError):
            info["container_cpu_limit"] = "unknown"

    return info


def get_model_size_mb(model: nn.Module) -> float:
    """Calculate model size in MB."""
    param_size = sum(p.nelement() * p.element_size() for p in model.parameters())
    buffer_size = sum(b.nelement() * b.element_size() for b in model.buffers())
    return (param_size + buffer_size) / (1024 ** 2)


def get_model_parameters(model: nn.Module) -> int:
    """Get total number of trainable parameters."""
    return sum(p.numel() for p in model.parameters() if p.requires_grad)


def scale_data(X: np.ndarray, feature_min: List[float], feature_max: List[float]) -> np.ndarray:
    """Scale data using saved min/max parameters."""
    feature_min = np.array(feature_min)
    feature_max = np.array(feature_max)
    range_vals = feature_max - feature_min
    range_vals[range_vals == 0] = 1
    X_scaled = (X - feature_min) / range_vals
    return np.clip(X_scaled, 0, 1)


def create_sliding_windows(X: np.ndarray, y: np.ndarray, window_size: int = 20) -> Tuple[np.ndarray, np.ndarray]:
    """Create sliding window sequences."""
    X_seq = []
    y_seq = []
    for i in range(len(X) - window_size):
        X_seq.append(X[i:i + window_size])
        y_seq.append(y[i + window_size])
    return np.array(X_seq), np.array(y_seq)


def load_attack_samples_for_detection(base_path: str, window_size: int = 20, max_samples: int = 100) -> Tuple[Optional[np.ndarray], Optional[np.ndarray], List[str]]:
    """Load real attack samples for detection timing measurement."""
    print(f"  Loading attack samples from {base_path}...")

    attack_samples = []
    attack_names = []

    # Look for attack folders (exclude normal data)
    if not os.path.exists(base_path):
        print(f"  WARNING: Dataset path not found: {base_path}")
        return None, None, attack_names

    subfolders = [f for f in os.listdir(base_path) if os.path.isdir(os.path.join(base_path, f)) and "normal" not in f.lower()]

    for folder in sorted(subfolders)[:5]:  # Limit to first 5 attack types for timing
        folder_path = os.path.join(base_path, folder)
        csv_files = glob.glob(os.path.join(folder_path, "*_essential.csv"))

        if not csv_files:
            continue

        try:
            df = pd.read_csv(csv_files[0])

            # Get features (exclude metadata columns)
            cols_to_remove = ["label", "source", "timestamp", "message_index", "packet_type", "direction", "info"]
            feature_cols = [col for col in df.columns if col not in cols_to_remove]
            X = df[feature_cols].values

            if len(X) <= window_size:
                continue

            # Create sliding windows
            X_seq, _ = create_sliding_windows(X, np.ones(len(X)), window_size=window_size)

            # Take a subset of samples from this attack type
            samples_to_take = min(max_samples // len(subfolders), len(X_seq))
            if samples_to_take > 0:
                selected_indices = np.random.choice(len(X_seq), samples_to_take, replace=False)
                attack_samples.extend(X_seq[selected_indices])
                attack_names.extend([folder] * samples_to_take)

        except Exception as e:
            print(f"  Error loading {folder}: {e}")
            continue

    if not attack_samples:
        print("  No attack samples loaded!")
        return None, None, attack_names

    X_attack = np.array(attack_samples)
    attack_names = attack_names[:len(X_attack)]  # Ensure names match samples

    print(f"  Loaded {len(X_attack)} attack samples from {len(set(attack_names))} attack types")
    print(f"  Attack types: {list(set(attack_names))}")

    return X_attack, np.ones(len(X_attack)), attack_names


# ======================================================
# Benchmark Functions
# ======================================================
def measure_inference_time(
    model: nn.Module,
    input_tensor: torch.Tensor,
    device: torch.device,
    num_runs: int = 100,
    warmup_runs: int = 10
) -> Dict:
    """Measure average inference time in milliseconds."""
    model.eval()
    input_tensor = input_tensor.to(device)

    # Warmup runs
    with torch.no_grad():
        for _ in range(warmup_runs):
            _ = model(input_tensor)

    # Measurement runs
    times = []
    with torch.no_grad():
        for _ in range(num_runs):
            start_time = time.perf_counter()
            _ = model(input_tensor)
            end_time = time.perf_counter()
            times.append((end_time - start_time) * 1000)  # Convert to ms

    return {
        "avg_time_ms": float(np.mean(times)),
        "std_time_ms": float(np.std(times)),
        "min_time_ms": float(np.min(times)),
        "max_time_ms": float(np.max(times)),
        "p50_time_ms": float(np.percentile(times, 50)),
        "p95_time_ms": float(np.percentile(times, 95)),
        "p99_time_ms": float(np.percentile(times, 99))
    }


def measure_memory_usage(model: nn.Module, input_tensor: torch.Tensor, device: torch.device) -> Dict:
    """Measure memory usage during inference."""
    model.eval()
    model_memory_mb = get_model_size_mb(model)

    # Measure CPU memory using tracemalloc
    gc.collect()
    tracemalloc.start()

    input_tensor = input_tensor.to(device)

    with torch.no_grad():
        _ = model(input_tensor)

    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return {
        "model_memory_mb": float(model_memory_mb),
        "peak_cpu_memory_mb": float(peak / (1024 ** 2)),
        "current_cpu_memory_mb": float(current / (1024 ** 2))
    }




def benchmark_model(
    model_name: str,
    model_config: Dict,
    device: torch.device,
    num_inference_runs: int = 100
) -> Dict:
    """Benchmark model for overhead computation and memory usage."""
    print(f"\n{'='*60}")
    print(f"Benchmarking {model_name.upper()} Model")
    print(f"{'='*60}")

    results = {"model_name": model_name}

    try:
        # Initialize model
        if model_config["type"] == "cnn":
            model = model_config["class"](input_channels=FEATURE_DIM, seq_length=WINDOW_SIZE)
            sample_input = torch.randn(1, FEATURE_DIM, WINDOW_SIZE)
        else:
            model = model_config["class"](feature_dim=FEATURE_DIM)
            sample_input = torch.randn(1, WINDOW_SIZE, FEATURE_DIM)

        # Load weights if available
        if os.path.exists(model_config["model_path"]):
            model.load_state_dict(torch.load(model_config["model_path"], map_location=device, weights_only=True))
            print(f"  Loaded weights from {model_config['model_path']}")
        else:
            print(f"  WARNING: Model weights not found at {model_config['model_path']}")
            print(f"  Using randomly initialized weights")

        model.to(device)
        model.eval()

        # Model info
        results["num_parameters"] = get_model_parameters(model)
        results["model_size_mb"] = get_model_size_mb(model)

        print(f"  Parameters: {results['num_parameters']:,}")
        print(f"  Model Size: {results['model_size_mb']:.4f} MB")

        # Inference time (overhead computation)
        print(f"  Measuring inference time (computation overhead)...")
        time_results = measure_inference_time(
            model, sample_input, device,
            num_runs=num_inference_runs, warmup_runs=10
        )
        results["inference_time"] = time_results
        print(f"    Average: {time_results['avg_time_ms']:.4f} ms")
        print(f"    P95: {time_results['p95_time_ms']:.4f} ms")

        # Memory usage
        print(f"  Measuring memory usage...")
        memory_results = measure_memory_usage(model, sample_input, device)
        results["memory_usage"] = memory_results
        print(f"    Model Memory: {memory_results['model_memory_mb']:.4f} MB")
        print(f"    Peak CPU Memory: {memory_results['peak_cpu_memory_mb']:.4f} MB")

        # Real dataset attack detection timing
        print(f"  Measuring attack detection time on real dataset...")
        detection_results = measure_attack_detection_time(
            model, model_config, device, num_runs=min(num_inference_runs, 50)
        )
        results["attack_detection"] = detection_results

        # Clean up
        del model
        del sample_input
        gc.collect()

    except Exception as e:
        print(f"  ERROR: {e}")
        results["error"] = str(e)

    return results


def measure_attack_detection_time(
    model: nn.Module,
    model_config: Dict,
    device: torch.device,
    num_runs: int = 50
) -> Dict:
    """Measure time to detect attacks using real dataset samples."""
    model.eval()

    # Load attack samples
    X_attack, _, attack_names = load_attack_samples_for_detection(
        DATASET_PATH, window_size=WINDOW_SIZE, max_samples=100
    )

    if X_attack is None or len(X_attack) == 0:
        return {"error": "No attack samples available"}

    # Load scaling parameters
    feature_min = None
    feature_max = None
    if os.path.exists(model_config["scaling_path"]):
        try:
            with open(model_config["scaling_path"], "r") as f:
                scaling_data = json.load(f)
            feature_min = scaling_data["feature_min"]
            feature_max = scaling_data["feature_max"]
            print(f"    Loaded scaling parameters from {model_config['scaling_path']}")
        except Exception as e:
            print(f"    WARNING: Could not load scaling parameters: {e}")

    # Prepare samples for testing
    num_test_samples = min(len(X_attack), num_runs * 5)  # Test on multiple samples
    test_indices = np.random.choice(len(X_attack), num_test_samples, replace=False)
    X_test = X_attack[test_indices]

    # Apply scaling if available
    if feature_min is not None and feature_max is not None:
        X_test_2d = X_test.reshape(-1, X_test.shape[2])
        X_test_2d_scaled = scale_data(X_test_2d, feature_min, feature_max)
        X_test_scaled = X_test_2d_scaled.reshape(X_test.shape)
    else:
        X_test_scaled = X_test
        print(f"    WARNING: No scaling parameters, using raw data")

    # Prepare tensor
    if model_config["type"] == "cnn":
        X_tensor = torch.tensor(X_test_scaled, dtype=torch.float32).permute(0, 2, 1)  # (batch, features, seq_len)
    else:
        X_tensor = torch.tensor(X_test_scaled, dtype=torch.float32)  # (batch, seq_len, features)

    # Run detection timing
    detection_times = []
    predictions = []

    with torch.no_grad():
        X_tensor = X_tensor.to(device)

        for i in range(len(X_tensor)):
            start_time = time.perf_counter()
            logits = model(X_tensor[i:i+1])  # Process one sample at a time
            end_time = time.perf_counter()

            detection_times.append((end_time - start_time) * 1000)  # Convert to ms
            pred = torch.argmax(logits, dim=1).cpu().numpy()[0]
            predictions.append(int(pred))

    # Calculate statistics
    detection_times = np.array(detection_times)
    predictions = np.array(predictions)

    attack_detected = np.sum(predictions == 1)  # Assuming 1 = attack
    detection_rate = attack_detected / len(predictions)

    results = {
        "samples_tested": len(X_test),
        "avg_detection_time_ms": float(np.mean(detection_times)),
        "std_detection_time_ms": float(np.std(detection_times)),
        "min_detection_time_ms": float(np.min(detection_times)),
        "max_detection_time_ms": float(np.max(detection_times)),
        "p95_detection_time_ms": float(np.percentile(detection_times, 95)),
        "p99_detection_time_ms": float(np.percentile(detection_times, 99)),
        "attacks_detected": int(attack_detected),
        "detection_rate": float(detection_rate),
        "attack_types_tested": list(set(attack_names))
    }

    print(f"    Tested on {len(X_test)} real attack samples")
    print(f"    Average detection time: {results['avg_detection_time_ms']:.4f} ms")
    print(f"    Attack detection rate: {results['detection_rate']:.4f}")
    print(f"    P95 detection time: {results['p95_detection_time_ms']:.4f} ms")

    return results


# ======================================================
# Main Benchmark Runner
# ======================================================
def run_benchmarks(output_dir: str, num_runs: int = 100) -> Dict:
    """Run overhead computation and memory benchmarks on all available models."""
    print("="*70)
    print("FBS Detection Model Benchmark - Overhead Computation & Memory")
    print("="*70)

    # System info
    system_info = get_system_info()
    print(f"\nSystem Information:")
    print(f"  Platform: {system_info['platform']}")
    print(f"  Python: {system_info['python_version']}")
    print(f"  PyTorch: {system_info['torch_version']}")
    print(f"  CPU Count: {system_info['cpu_count']}")
    print(f"  Torch Threads: {system_info['torch_num_threads']}")
    if isinstance(system_info.get('container_memory_limit_gb'), float):
        print(f"  Container Memory Limit: {system_info['container_memory_limit_gb']:.1f} GB")
    if isinstance(system_info.get('container_cpu_limit'), float):
        print(f"  Container CPU Limit: {system_info['container_cpu_limit']:.1f} cores")

    device = torch.device("cpu")  # Always CPU for Android simulation
    print(f"\nUsing device: {device}")

    # Check available models
    print(f"\n{'='*70}")
    print("Checking Available Models")
    print("="*70)
    available_models = {}
    for name, config in MODELS.items():
        if os.path.exists(config["model_path"]):
            available_models[name] = config
            print(f"  Found model: {name}")
        else:
            print(f"  Model not found: {name} (will use random weights)")
            available_models[name] = config  # Still benchmark with random weights

    # Run benchmarks
    all_results = {
        "system_info": system_info,
        "config": {
            "window_size": WINDOW_SIZE,
            "feature_dim": FEATURE_DIM,
            "num_inference_runs": num_runs
        },
        "models": {}
    }

    for model_name, model_config in available_models.items():
        result = benchmark_model(model_name, model_config, device, num_runs)
        all_results["models"][model_name] = result

    # Save results
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # JSON results
    json_path = os.path.join(output_dir, f"benchmark_results_{timestamp}.json")
    with open(json_path, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\nResults saved to: {json_path}")

    # Generate summary report
    report_path = os.path.join(output_dir, f"benchmark_report_{timestamp}.txt")
    generate_report(all_results, report_path)
    print(f"Report saved to: {report_path}")

    return all_results


def generate_report(results: Dict, output_path: str):
    """Generate a human-readable benchmark report."""
    lines = []
    lines.append("="*80)
    lines.append("FBS DETECTION MODEL BENCHMARK REPORT")
    lines.append("Overhead Computation & Memory Analysis")
    lines.append("="*80)
    lines.append("")

    # System info
    sys_info = results["system_info"]
    lines.append("SYSTEM INFORMATION")
    lines.append("-"*40)
    lines.append(f"Timestamp: {sys_info['timestamp']}")
    lines.append(f"Platform: {sys_info['platform']}")
    lines.append(f"Python: {sys_info['python_version']}")
    lines.append(f"PyTorch: {sys_info['torch_version']}")
    lines.append(f"CPU Count: {sys_info['cpu_count']}")
    lines.append(f"Torch Threads: {sys_info['torch_num_threads']}")
    if isinstance(sys_info.get('container_memory_limit_gb'), (int, float)):
        lines.append(f"Container Memory: {sys_info['container_memory_limit_gb']:.1f} GB")
    if isinstance(sys_info.get('container_cpu_limit'), (int, float)):
        lines.append(f"Container CPU: {sys_info['container_cpu_limit']:.1f} cores")
    lines.append("")

    # Configuration
    config = results["config"]
    lines.append("CONFIGURATION")
    lines.append("-"*40)
    lines.append(f"Window Size: {config['window_size']}")
    lines.append(f"Feature Dimension: {config['feature_dim']}")
    lines.append(f"Inference Runs: {config['num_inference_runs']}")
    lines.append("")

    # Model results
    for model_name, model_results in results["models"].items():
        lines.append("")
        lines.append(f"{'='*80}")
        lines.append(f"MODEL: {model_name.upper()}")
        lines.append(f"{'='*80}")

        if "error" in model_results:
            lines.append(f"ERROR: {model_results['error']}")
            continue

        lines.append(f"Parameters: {model_results['num_parameters']:,}")
        lines.append(f"Model Size: {model_results['model_size_mb']:.4f} MB")
        lines.append("")

        # Inference time (computation overhead)
        inf = model_results["inference_time"]
        lines.append("INFERENCE TIME (Computation Overhead)")
        lines.append("-"*40)
        lines.append(f"  Average: {inf['avg_time_ms']:.4f} ms")
        lines.append(f"  Std Dev: {inf['std_time_ms']:.4f} ms")
        lines.append(f"  Min: {inf['min_time_ms']:.4f} ms")
        lines.append(f"  Max: {inf['max_time_ms']:.4f} ms")
        lines.append(f"  P50: {inf['p50_time_ms']:.4f} ms")
        lines.append(f"  P95: {inf['p95_time_ms']:.4f} ms")
        lines.append(f"  P99: {inf['p99_time_ms']:.4f} ms")
        lines.append("")

        # Memory
        mem = model_results["memory_usage"]
        lines.append("MEMORY USAGE")
        lines.append("-"*40)
        lines.append(f"  Model Memory: {mem['model_memory_mb']:.4f} MB")
        lines.append(f"  Peak CPU Memory: {mem['peak_cpu_memory_mb']:.4f} MB")
        lines.append("")

        # Attack Detection (Real Dataset)
        if "attack_detection" in model_results:
            attack_det = model_results["attack_detection"]
            if "error" not in attack_det:
                lines.append("ATTACK DETECTION (Real Dataset)")
                lines.append("-"*40)
                lines.append(f"  Samples Tested: {attack_det['samples_tested']}")
                lines.append(f"  Average Detection Time: {attack_det['avg_detection_time_ms']:.4f} ms")
                lines.append(f"  Std Dev: {attack_det['std_detection_time_ms']:.4f} ms")
                lines.append(f"  Min Detection Time: {attack_det['min_detection_time_ms']:.4f} ms")
                lines.append(f"  Max Detection Time: {attack_det['max_detection_time_ms']:.4f} ms")
                lines.append(f"  P95 Detection Time: {attack_det['p95_detection_time_ms']:.4f} ms")
                lines.append(f"  P99 Detection Time: {attack_det['p99_detection_time_ms']:.4f} ms")
                lines.append(f"  Attacks Detected: {attack_det['attacks_detected']}/{attack_det['samples_tested']}")
                lines.append(f"  Detection Rate: {attack_det['detection_rate']:.4f}")
                lines.append(f"  Attack Types Tested: {', '.join(attack_det['attack_types_tested'][:3])}")  # Show first 3
                lines.append("")

    # Summary comparison
    lines.append("")
    lines.append("="*80)
    lines.append("SUMMARY COMPARISON")
    lines.append("="*80)

    models = results["models"]
    if len(models) > 1:
        # Find best performers
        fastest = min(models.items(),
                     key=lambda x: x[1].get("inference_time", {}).get("avg_time_ms", float('inf')))
        smallest = min(models.items(),
                      key=lambda x: x[1].get("model_size_mb", float('inf')))
        lowest_peak_memory = min(models.items(),
                                key=lambda x: x[1].get("memory_usage", {}).get("peak_cpu_memory_mb", float('inf')))

        # Find fastest attack detection
        models_with_detection = {k: v for k, v in models.items() if "attack_detection" in v and "error" not in v["attack_detection"]}
        fastest_detection = None
        if models_with_detection:
            fastest_detection = min(models_with_detection.items(),
                                   key=lambda x: x[1]["attack_detection"]["avg_detection_time_ms"])

        lines.append("Performance Metrics:")
        lines.append(f"  Fastest Inference: {fastest[0].upper()} ({fastest[1]['inference_time']['avg_time_ms']:.4f} ms)")
        lines.append(f"  Smallest Model: {smallest[0].upper()} ({smallest[1]['model_size_mb']:.4f} MB)")
        lines.append(f"  Lowest Peak Memory: {lowest_peak_memory[0].upper()} ({lowest_peak_memory[1]['memory_usage']['peak_cpu_memory_mb']:.4f} MB)")
        if fastest_detection:
            lines.append(f"  Fastest Attack Detection: {fastest_detection[0].upper()} ({fastest_detection[1]['attack_detection']['avg_detection_time_ms']:.4f} ms)")
        lines.append("")

        # Comparison table
        lines.append("Model Comparison Table:")
        lines.append("-"*100)
        header = f"{'Model':<10} {'Parameters':<12} {'Model Size(MB)':<14} {'Avg Latency(ms)':<15} {'Peak Mem(MB)':<13} {'Attack Det(ms)':<15}"
        lines.append(header)
        lines.append("-"*100)
        for name, m in models.items():
            if "error" not in m:
                params = m["num_parameters"]
                size = m["model_size_mb"]
                lat = m["inference_time"]["avg_time_ms"]
                peak_mem = m["memory_usage"]["peak_cpu_memory_mb"]
                attack_det_time = "N/A"
                if "attack_detection" in m and "error" not in m["attack_detection"]:
                    attack_det_time = f"{m['attack_detection']['avg_detection_time_ms']:.2f}"
                lines.append(f"{name.upper():<10} {params:<12,} {size:<14.4f} {lat:<15.4f} {peak_mem:<13.4f} {attack_det_time:<15}")
        lines.append("-"*100)

    lines.append("")
    lines.append("="*80)
    lines.append("END OF REPORT")
    lines.append("="*80)

    with open(output_path, "w") as f:
        f.write("\n".join(lines))


# ======================================================
# Entry Point
# ======================================================
def main():
    parser = argparse.ArgumentParser(description="FBS Detection Model Benchmark")
    parser.add_argument("--output-dir", type=str, default="/app/benchmark_results",
                       help="Directory to save benchmark results")
    parser.add_argument("--num-runs", type=int, default=100,
                       help="Number of inference runs for timing")
    args = parser.parse_args()

    results = run_benchmarks(args.output_dir, args.num_runs)

    print("\n" + "="*70)
    print("BENCHMARK COMPLETE")
    print("="*70)


if __name__ == "__main__":
    main()
