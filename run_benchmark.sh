#!/bin/bash
# FBS Detection Model Benchmark Runner
# Runs benchmarks in Docker containers simulating Android device constraints

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}FBS Detection Model Benchmark${NC}"
echo -e "${BLUE}Android Environment Simulation${NC}"
echo -e "${BLUE}========================================${NC}"

# Default values
PROFILE="standard"
NUM_RUNS=100
BUILD_ONLY=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --profile|-p)
            PROFILE="$2"
            shift 2
            ;;
        --runs|-r)
            NUM_RUNS="$2"
            shift 2
            ;;
        --build-only)
            BUILD_ONLY=true
            shift
            ;;
        --help|-h)
            echo ""
            echo "Usage: ./run_benchmark.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -p, --profile PROFILE  Device profile to simulate (default: standard)"
            echo "                         - standard: 8GB RAM, 8 cores (high-end Android)"
            echo "                         - midrange: 4GB RAM, 4 cores (typical mid-range)"
            echo "                         - lowend: 2GB RAM, 2 cores (budget device)"
            echo "                         - all: Run all profiles sequentially"
            echo "  -r, --runs NUM         Number of inference runs (default: 100)"
            echo "  --build-only           Only build the Docker image, don't run"
            echo "  -h, --help             Show this help message"
            echo ""
            echo "Examples:"
            echo "  ./run_benchmark.sh                     # Run with default settings"
            echo "  ./run_benchmark.sh -p midrange         # Simulate mid-range device"
            echo "  ./run_benchmark.sh -p all -r 50        # Run all profiles with 50 runs"
            echo ""
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Create results directory
mkdir -p benchmark_results

# Build Docker image
echo -e "\n${YELLOW}Building Docker image...${NC}"
docker-compose build fbs-benchmark

if [ "$BUILD_ONLY" = true ]; then
    echo -e "\n${GREEN}Build complete.${NC}"
    exit 0
fi

# Function to run benchmark for a specific profile
run_profile() {
    local profile=$1
    local service_name=""
    local description=""

    case $profile in
        standard)
            service_name="fbs-benchmark"
            description="High-end Android (8GB RAM, 8 cores)"
            ;;
        midrange)
            service_name="fbs-benchmark-constrained"
            description="Mid-range Android (4GB RAM, 4 cores)"
            ;;
        lowend)
            service_name="fbs-benchmark-lowend"
            description="Budget Android (2GB RAM, 2 cores)"
            ;;
        *)
            echo -e "${RED}Unknown profile: $profile${NC}"
            return 1
            ;;
    esac

    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${BLUE}Running benchmark: ${description}${NC}"
    echo -e "${BLUE}========================================${NC}"

    # Run the container
    docker-compose run --rm \
        -e NUM_RUNS=$NUM_RUNS \
        $service_name \
        --num-runs $NUM_RUNS \
        --output-dir /app/benchmark_results

    echo -e "${GREEN}Benchmark complete for profile: $profile${NC}"
}

# Run benchmark(s)
if [ "$PROFILE" = "all" ]; then
    echo -e "\n${YELLOW}Running all device profiles...${NC}"
    for p in standard midrange lowend; do
        run_profile $p
    done
else
    run_profile $PROFILE
fi

# Show results
echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}All benchmarks complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "\nResults saved to: ${BLUE}benchmark_results/${NC}"
echo -e "\nLatest results:"
ls -la benchmark_results/ | tail -5

echo -e "\n${YELLOW}To view the latest report:${NC}"
echo "cat benchmark_results/benchmark_report_*.txt | head -100"
