#!/bin/bash

# Performance Testing Script for Custom IP/TCP Implementation
# Compares against Go standard library

set -e

echo "🚀 Starting Performance Tests..."
echo "=================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Create results directory
mkdir -p results

# Function to run benchmark and save results
run_benchmark() {
    local name=$1
    local pattern=$2
    local output_file="results/${name}_$(date +%Y%m%d_%H%M%S).txt"
    
    echo -e "${BLUE}Running ${name}...${NC}"
    go test -bench="$pattern" -benchmem -count=5 ./benchmarks > "$output_file" 2>&1
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ ${name} completed${NC}"
        echo "Results saved to: $output_file"
        
        # Show summary
        echo -e "${YELLOW}Summary:${NC}"
        tail -n 10 "$output_file"
        echo ""
    else
        echo -e "${RED}✗ ${name} failed${NC}"
    fi
}

# Function to compare results
compare_results() {
    local custom_file=$1
    local stdlib_file=$2
    local comparison_file="results/comparison_$(date +%Y%m%d_%H%M%S).txt"
    
    echo -e "${BLUE}Comparing results...${NC}"
    
    # Extract key metrics
    echo "Performance Comparison Report" > "$comparison_file"
    echo "Generated: $(date)" >> "$comparison_file"
    echo "==================================" >> "$comparison_file"
    echo "" >> "$comparison_file"
    
    # Extract and compare metrics
    if [ -f "$custom_file" ] && [ -f "$stdlib_file" ]; then
        echo "Custom Implementation:" >> "$comparison_file"
        grep -E "(BenchmarkIPMarshal|BenchmarkTCPMarshal|BenchmarkChecksum)" "$custom_file" >> "$comparison_file"
        echo "" >> "$comparison_file"
        echo "Standard Library:" >> "$comparison_file"
        grep -E "(BenchmarkTCPConnection)" "$stdlib_file" >> "$comparison_file"
    fi
    
    echo -e "${GREEN}Comparison saved to: $comparison_file${NC}"
}

# Run individual benchmarks
echo -e "${YELLOW}Phase 1: Core Function Benchmarks${NC}"
run_benchmark "IP_Marshal" "BenchmarkIPMarshal"
run_benchmark "TCP_Marshal" "BenchmarkTCPMarshal"
run_benchmark "Checksum" "BenchmarkChecksum"
run_benchmark "IP_Parse" "BenchmarkIPParse"

echo -e "${YELLOW}Phase 2: Memory Allocation Tests${NC}"
run_benchmark "Memory_Allocs" "Benchmark.*Allocs"

echo -e "${YELLOW}Phase 3: Throughput Tests${NC}"
run_benchmark "Throughput" "BenchmarkThroughput"

echo -e "${YELLOW}Phase 4: Latency Tests${NC}"
run_benchmark "Latency" "BenchmarkLatency"

echo -e "${YELLOW}Phase 5: Standard Library Comparison${NC}"
run_benchmark "StdLib_TCP" "BenchmarkTCPConnection_StdLib"

# Generate performance report
echo -e "${BLUE}Generating Performance Report...${NC}"
cat > "results/performance_report_$(date +%Y%m%d_%H%M%S).md" << EOF
# Performance Test Report

## Test Environment
- Date: $(date)
- Go Version: $(go version)
- OS: $(uname -a)
- CPU: $(lscpu | grep "Model name" | head -1 | cut -d: -f2 | xargs)

## Test Results

### Core Functions
\`\`\`
$(find results -name "*IP_Marshal*" -o -name "*TCP_Marshal*" | head -1 | xargs cat 2>/dev/null || echo "No results yet")
\`\`\`

### Memory Usage
\`\`\`
$(find results -name "*Memory_Allocs*" | head -1 | xargs cat 2>/dev/null || echo "No results yet")
\`\`\`

### Throughput
\`\`\`
$(find results -name "*Throughput*" | head -1 | xargs cat 2>/dev/null || echo "No results yet")
\`\`\`

## Recommendations
- Review memory allocation patterns
- Consider optimizations for hot paths
- Compare with standard library performance
EOF

echo -e "${GREEN}🎉 Performance testing completed!${NC}"
echo -e "${BLUE}Check the 'results/' directory for detailed reports${NC}"

# Show quick summary
echo -e "${YELLOW}Quick Summary:${NC}"
echo "Files generated:"
ls -la results/ 