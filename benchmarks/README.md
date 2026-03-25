# Benchmarks

Performance benchmarks and evaluation framework for go-promptguard.

## Evaluation

### Pattern-only evaluation

```bash
go test -v -run TestEvaluation ./benchmarks/
```

Runs against 145 labeled samples (70 attacks, 75 benign) and prints:
- Overall precision, recall, F1, accuracy
- Per-category recall breakdown
- Per-category false positive rate
- Confusion matrix
- False positive and false negative listings with scores

### Threshold sweep

```bash
go test -v -run TestThresholdSweep ./benchmarks/
```

Shows precision/recall/F1 at thresholds 0.5 → 0.9. Useful for tuning the threshold for your use case.

### Per-category precision

```bash
go test -v -run TestPerCategoryPrecision ./benchmarks/
```

Recall and precision broken down by attack category (role_injection, prompt_leak, instruction_override, obfuscation, normalization, delimiter, multi_vector).

### LLM evaluation (requires Ollama)

```bash
go test -v -run TestEvaluationWithLLM -timeout 10m ./benchmarks/
```

Runs the same dataset with `LLMFallback` mode using `llama3.1:8b`. Prints a side-by-side comparison of pattern-only vs pattern+LLM metrics. Auto-skips if Ollama is not running at `localhost:11434`.

## Current Metrics

At default threshold `0.7`:

| Mode | Precision | Recall | F1 | FP | FN |
|---|---|---|---|---|---|
| Pattern-only | 93.5% | 88.6% | 91.2% | 4 | 8 |
| Pattern + LLM | 89.5% | 97.1% | 93.2% | 8 | 2 |

## Dataset

Located in `testdata/`:

| File | Contents |
|---|---|
| `attacks.json` | 70 labeled attack samples across 7 categories |
| `benign.json` | 75 labeled safe samples including 35 edge cases |

Attack categories: `role_injection`, `prompt_leak`, `instruction_override`, `obfuscation`, `normalization`, `delimiter`, `multi_vector`

## Performance Benchmarks

```bash
# Run all
go test -bench=. -benchmem ./benchmarks/

# Specific benchmark
go test -bench=BenchmarkDetectPatternOnly -benchmem ./benchmarks/

# With CPU profiling
go test -bench=. -benchmem -cpuprofile=cpu.prof ./benchmarks/

# Compare before/after changes
go test -bench=. -benchmem ./benchmarks/ | tee old.txt
# make changes...
go test -bench=. -benchmem ./benchmarks/ | tee new.txt
benchstat old.txt new.txt
```

| Benchmark | Description |
|---|---|
| `BenchmarkDetectPatternOnly` | Pattern matching only |
| `BenchmarkDetectAllDetectors` | All detectors enabled (default) |
| `BenchmarkDetectLongInput` | Longer input (~250 chars) |
| `BenchmarkDetectConcurrent` | Parallel requests simulation |
| `BenchmarkDetectMixedWorkload` | Mixed normal/attack inputs |
| `BenchmarkHighThroughput` | 100 concurrent goroutines |
| `BenchmarkDetectMemory` | Memory allocation analysis |

### Reading benchmark output

```
BenchmarkDetectPatternOnly-8    1500000    750 ns/op    320 B/op    8 allocs/op
```

- `750 ns/op` — nanoseconds per detection (0.75µs)
- `320 B/op` — bytes allocated per detection
- `8 allocs/op` — heap allocations per detection

### Expected performance

- Latency: <1ms per detection (pattern + statistical)
- Throughput: 10k+ req/s on modern hardware
- Memory: <50MB at 1k req/s sustained load
