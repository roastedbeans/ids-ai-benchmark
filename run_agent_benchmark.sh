#!/bin/bash
# Detection Agent Benchmark — runs in Docker
set -e
cd "$(dirname "$0")"
docker-compose run --rm agent-benchmark "$@"
