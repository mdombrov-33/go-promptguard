# Benchmarks

Performance and accuracy benchmarks for go-promptguard.

## Running Benchmarks

### Performance Benchmarks

```bash
# Run all performance benchmarks
go test -bench=. -benchmem ./benchmarks

# Run specific benchmark
go test -bench=BenchmarkDetectPatternOnly -benchmem ./benchmarks

# Run with CPU profiling
go test -bench=. -benchmem -cpuprofile=cpu.prof ./benchmarks

# Run with memory profiling
go test -bench=. -benchmem -memprofile=mem.prof ./benchmarks

# Compare before/after changes
go test -bench=. -benchmem ./benchmarks | tee old.txt
# Make changes...
go test -bench=. -benchmem ./benchmarks | tee new.txt
benchstat old.txt new.txt
```

### Accuracy Tests

```bash
# Run accuracy metrics
go test -v -run=TestDetectionAccuracy ./benchmarks

# Test consistency
go test -v -run=TestDetectionConsistency ./benchmarks

# Test threshold sensitivity
go test -v -run=TestThresholdSensitivity ./benchmarks
```

## Benchmark Scenarios

### Performance Tests

| Benchmark | Description |
|-----------|-------------|
| `BenchmarkDetectPatternOnly` | Pattern matching only (fastest) |
| `BenchmarkDetectAllDetectors` | All detectors enabled (default) |
| `BenchmarkDetectLongInput` | Longer input (~250 chars) |
| `BenchmarkDetectConcurrent` | Parallel requests simulation |
| `BenchmarkDetectMixedWorkload` | Mixed normal/attack inputs |
| `BenchmarkHighThroughput` | 100 concurrent goroutines |
| `BenchmarkDetectMemory` | Memory allocation analysis |

### Accuracy Tests

| Test | Description |
|------|-------------|
| `TestDetectionAccuracy` | Precision/recall on known samples |
| `TestDetectionConsistency` | Deterministic results check |
| `TestThresholdSensitivity` | Threshold impact analysis |

## Understanding Results

### Performance Metrics

```
BenchmarkDetectPatternOnly-8    1500000    750 ns/op    320 B/op    8 allocs/op
```

- `1500000` - iterations run
- `750 ns/op` - nanoseconds per operation (0.75 µs = 0.00075 ms)
- `320 B/op` - bytes allocated per operation
- `8 allocs/op` - allocations per operation

**Throughput calculation:**
```
1 second = 1,000,000,000 ns
ops/sec = 1,000,000,000 / ns_per_op

Example: 1,000,000,000 / 750 = 1,333,333 ops/sec
```

### Accuracy Metrics

- **Precision**: Of inputs marked unsafe, how many were actually attacks?
- **Recall**: Of actual attacks, how many did we detect?
- **F1 Score**: Harmonic mean of precision and recall
- **Accuracy**: Overall correct classifications

## Expected Performance

Based on default configuration:

- **Latency**: <1ms per detection (pattern + statistical analysis)
- **Throughput**: 10k+ req/s on modern hardware
- **Memory**: <50MB at 1k req/s sustained load
- **Accuracy**: >90% overall, >85% recall on known attacks

## Hardware Reference

Benchmarks will vary by hardware. Include your specs when sharing results:

```bash
go test -bench=. -benchmem ./benchmarks

# System info
uname -a
lscpu | grep "Model name"
free -h
```
