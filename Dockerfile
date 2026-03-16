# Dockerfile for Android-like Environment Simulation
# Simulates constrained mobile device environment for FBS detection benchmarking

FROM python:3.10-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
# Using CPU-only PyTorch to match mobile device constraints
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir torch torchvision --index-url https://download.pytorch.org/whl/cpu && \
    pip install --no-cache-dir -r requirements.txt

# Copy the entire ai-detection project
COPY . .

# Create output directory for benchmark results
RUN mkdir -p /app/benchmark_results

# Copy benchmark script
COPY docker_benchmark.py /app/docker_benchmark.py

# Set the entrypoint
ENTRYPOINT ["python", "/app/docker_benchmark.py"]
