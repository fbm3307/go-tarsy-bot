package benchmarks

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// PerformanceAnalyzer provides tools for running and analyzing performance benchmarks
type PerformanceAnalyzer struct {
	outputDir  string
	iterations int
	cpuProfile bool
	memProfile bool
}

// BenchmarkResult represents the result of a single benchmark run
type BenchmarkResult struct {
	Name            string  `json:"name"`
	Iterations      int64   `json:"iterations"`
	NsPerOp         int64   `json:"ns_per_op"`
	AllocsPerOp     int64   `json:"allocs_per_op"`
	BytesPerOp      int64   `json:"bytes_per_op"`
	MBPerSec        float64 `json:"mb_per_sec,omitempty"`
	Duration        string  `json:"duration"`
	MemoryFootprint int64   `json:"memory_footprint,omitempty"`
}

// PerformanceReport contains comprehensive performance analysis
type PerformanceReport struct {
	Timestamp    time.Time          `json:"timestamp"`
	GoVersion    string             `json:"go_version"`
	Platform     string             `json:"platform"`
	Benchmarks   []*BenchmarkResult `json:"benchmarks"`
	Summary      *PerformanceSummary `json:"summary"`
	Comparisons  []*Comparison       `json:"comparisons,omitempty"`
}

// PerformanceSummary provides high-level performance metrics
type PerformanceSummary struct {
	TotalBenchmarks       int     `json:"total_benchmarks"`
	FastestOperation      string  `json:"fastest_operation"`
	SlowestOperation      string  `json:"slowest_operation"`
	HighestMemoryUsage    string  `json:"highest_memory_usage"`
	AverageNsPerOp        float64 `json:"average_ns_per_op"`
	TotalAllocations      int64   `json:"total_allocations"`
	TotalBytesAllocated   int64   `json:"total_bytes_allocated"`
	RecommendedOptimizations []string `json:"recommended_optimizations"`
}

// Comparison represents a performance comparison between operations
type Comparison struct {
	Baseline    string  `json:"baseline"`
	Comparison  string  `json:"comparison"`
	SpeedupX    float64 `json:"speedup_x"`
	MemoryRatio float64 `json:"memory_ratio"`
	Analysis    string  `json:"analysis"`
}

// NewPerformanceAnalyzer creates a new performance analyzer
func NewPerformanceAnalyzer(outputDir string) *PerformanceAnalyzer {
	return &PerformanceAnalyzer{
		outputDir:  outputDir,
		iterations: 5,
		cpuProfile: true,
		memProfile: true,
	}
}

// SetIterations sets the number of benchmark iterations
func (pa *PerformanceAnalyzer) SetIterations(iterations int) {
	pa.iterations = iterations
}

// EnableProfiling enables CPU and memory profiling
func (pa *PerformanceAnalyzer) EnableProfiling(cpu, mem bool) {
	pa.cpuProfile = cpu
	pa.memProfile = mem
}

// RunBenchmarks executes all benchmarks and generates a performance report
func (pa *PerformanceAnalyzer) RunBenchmarks() (*PerformanceReport, error) {
	// Ensure output directory exists
	if err := os.MkdirAll(pa.outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	// Run benchmarks
	results, err := pa.executeBenchmarks()
	if err != nil {
		return nil, fmt.Errorf("failed to execute benchmarks: %w", err)
	}

	// Generate report
	report := &PerformanceReport{
		Timestamp:  time.Now(),
		GoVersion:  pa.getGoVersion(),
		Platform:   pa.getPlatform(),
		Benchmarks: results,
		Summary:    pa.generateSummary(results),
	}

	// Add comparisons
	report.Comparisons = pa.generateComparisons(results)

	// Save report
	if err := pa.saveReport(report); err != nil {
		return nil, fmt.Errorf("failed to save report: %w", err)
	}

	return report, nil
}

// executeBenchmarks runs the Go benchmark tests
func (pa *PerformanceAnalyzer) executeBenchmarks() ([]*BenchmarkResult, error) {
	// Prepare benchmark command
	args := []string{"test", "-bench=.", "-benchmem", "-count=" + strconv.Itoa(pa.iterations)}

	if pa.cpuProfile {
		args = append(args, "-cpuprofile="+filepath.Join(pa.outputDir, "cpu.prof"))
	}

	if pa.memProfile {
		args = append(args, "-memprofile="+filepath.Join(pa.outputDir, "mem.prof"))
	}

	// Add the package path
	args = append(args, "./internal/benchmarks")

	// Execute benchmark
	cmd := exec.Command("go", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("benchmark execution failed: %w\nOutput: %s", err, string(output))
	}

	// Parse results
	return pa.parseBenchmarkOutput(string(output))
}

// parseBenchmarkOutput parses Go benchmark output into structured results
func (pa *PerformanceAnalyzer) parseBenchmarkOutput(output string) ([]*BenchmarkResult, error) {
	lines := strings.Split(output, "\n")
	var results []*BenchmarkResult

	// Regex to parse benchmark lines
	benchmarkRegex := regexp.MustCompile(`^(Benchmark\w+(?:/\w+)*)\s+(\d+)\s+(\d+(?:\.\d+)?)\s+ns/op(?:\s+(\d+)\s+B/op)?(?:\s+(\d+)\s+allocs/op)?`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Benchmark") {
			matches := benchmarkRegex.FindStringSubmatch(line)
			if len(matches) >= 4 {
				result := &BenchmarkResult{
					Name: matches[1],
				}

				// Parse iterations
				if iterations, err := strconv.ParseInt(matches[2], 10, 64); err == nil {
					result.Iterations = iterations
				}

				// Parse ns/op
				if nsPerOp, err := strconv.ParseFloat(matches[3], 64); err == nil {
					result.NsPerOp = int64(nsPerOp)
				}

				// Parse bytes per op (if present)
				if len(matches) > 4 && matches[4] != "" {
					if bytesPerOp, err := strconv.ParseInt(matches[4], 10, 64); err == nil {
						result.BytesPerOp = bytesPerOp
					}
				}

				// Parse allocs per op (if present)
				if len(matches) > 5 && matches[5] != "" {
					if allocsPerOp, err := strconv.ParseInt(matches[5], 10, 64); err == nil {
						result.AllocsPerOp = allocsPerOp
					}
				}

				// Calculate duration
				totalNs := result.NsPerOp * result.Iterations
				result.Duration = time.Duration(totalNs).String()

				results = append(results, result)
			}
		}
	}

	return results, nil
}

// generateSummary creates a performance summary from benchmark results
func (pa *PerformanceAnalyzer) generateSummary(results []*BenchmarkResult) *PerformanceSummary {
	if len(results) == 0 {
		return &PerformanceSummary{}
	}

	summary := &PerformanceSummary{
		TotalBenchmarks: len(results),
	}

	var totalNsPerOp int64
	var totalAllocations int64
	var totalBytesAllocated int64
	var fastestOp, slowestOp, highestMemOp *BenchmarkResult

	for _, result := range results {
		// Track totals
		totalNsPerOp += result.NsPerOp
		totalAllocations += result.AllocsPerOp * result.Iterations
		totalBytesAllocated += result.BytesPerOp * result.Iterations

		// Find fastest operation
		if fastestOp == nil || result.NsPerOp < fastestOp.NsPerOp {
			fastestOp = result
		}

		// Find slowest operation
		if slowestOp == nil || result.NsPerOp > slowestOp.NsPerOp {
			slowestOp = result
		}

		// Find highest memory usage
		if highestMemOp == nil || result.BytesPerOp > highestMemOp.BytesPerOp {
			highestMemOp = result
		}
	}

	// Set summary fields
	if fastestOp != nil {
		summary.FastestOperation = fastestOp.Name
	}
	if slowestOp != nil {
		summary.SlowestOperation = slowestOp.Name
	}
	if highestMemOp != nil {
		summary.HighestMemoryUsage = highestMemOp.Name
	}

	summary.AverageNsPerOp = float64(totalNsPerOp) / float64(len(results))
	summary.TotalAllocations = totalAllocations
	summary.TotalBytesAllocated = totalBytesAllocated

	// Generate optimization recommendations
	summary.RecommendedOptimizations = pa.generateOptimizationRecommendations(results)

	return summary
}

// generateOptimizationRecommendations analyzes results and suggests optimizations
func (pa *PerformanceAnalyzer) generateOptimizationRecommendations(results []*BenchmarkResult) []string {
	var recommendations []string

	for _, result := range results {
		// High memory allocation recommendations
		if result.AllocsPerOp > 100 {
			recommendations = append(recommendations,
				fmt.Sprintf("%s: Consider reducing allocations (currently %d allocs/op)", result.Name, result.AllocsPerOp))
		}

		// High memory usage recommendations
		if result.BytesPerOp > 10000 {
			recommendations = append(recommendations,
				fmt.Sprintf("%s: Consider reducing memory usage (currently %d bytes/op)", result.Name, result.BytesPerOp))
		}

		// Slow operation recommendations
		if result.NsPerOp > 1000000 { // More than 1ms
			recommendations = append(recommendations,
				fmt.Sprintf("%s: Consider performance optimization (currently %d ns/op)", result.Name, result.NsPerOp))
		}

		// Context operations that might need optimization
		if strings.Contains(result.Name, "Context") && result.AllocsPerOp > 10 {
			recommendations = append(recommendations,
				fmt.Sprintf("%s: Context operations should minimize allocations", result.Name))
		}

		// Agent routing optimizations
		if strings.Contains(result.Name, "Routing") && result.NsPerOp > 10000 {
			recommendations = append(recommendations,
				fmt.Sprintf("%s: Consider caching or indexing for faster routing", result.Name))
		}
	}

	// Deduplicate recommendations
	seen := make(map[string]bool)
	var unique []string
	for _, rec := range recommendations {
		if !seen[rec] {
			seen[rec] = true
			unique = append(unique, rec)
		}
	}

	return unique
}

// generateComparisons creates performance comparisons between related operations
func (pa *PerformanceAnalyzer) generateComparisons(results []*BenchmarkResult) []*Comparison {
	var comparisons []*Comparison

	// Group related benchmarks
	groups := make(map[string][]*BenchmarkResult)
	for _, result := range results {
		// Extract base name (remove specific test variations)
		baseName := pa.extractBaseName(result.Name)
		groups[baseName] = append(groups[baseName], result)
	}

	// Generate comparisons within groups
	for groupName, groupResults := range groups {
		if len(groupResults) > 1 {
			// Sort by performance
			sort.Slice(groupResults, func(i, j int) bool {
				return groupResults[i].NsPerOp < groupResults[j].NsPerOp
			})

			// Compare fastest vs slowest
			if len(groupResults) >= 2 {
				fastest := groupResults[0]
				slowest := groupResults[len(groupResults)-1]

				speedup := float64(slowest.NsPerOp) / float64(fastest.NsPerOp)
				memoryRatio := float64(slowest.BytesPerOp) / float64(fastest.BytesPerOp)
				if fastest.BytesPerOp == 0 {
					memoryRatio = 0
				}

				analysis := pa.generateComparisonAnalysis(fastest, slowest, speedup, memoryRatio)

				comparisons = append(comparisons, &Comparison{
					Baseline:    fastest.Name,
					Comparison:  slowest.Name,
					SpeedupX:    speedup,
					MemoryRatio: memoryRatio,
					Analysis:    analysis,
				})
			}
		}
		_ = groupName // Use groupName to avoid unused variable
	}

	return comparisons
}

// extractBaseName extracts the base benchmark name for grouping
func (pa *PerformanceAnalyzer) extractBaseName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) > 0 {
		return parts[0]
	}
	return fullName
}

// generateComparisonAnalysis generates analysis text for a comparison
func (pa *PerformanceAnalyzer) generateComparisonAnalysis(fastest, slowest *BenchmarkResult, speedup, memoryRatio float64) string {
	analysis := fmt.Sprintf("%s is %.2fx faster than %s", fastest.Name, speedup, slowest.Name)

	if memoryRatio > 1.5 {
		analysis += fmt.Sprintf(" and uses %.2fx less memory", memoryRatio)
	} else if memoryRatio < 0.7 {
		analysis += fmt.Sprintf(" but uses %.2fx more memory", 1/memoryRatio)
	}

	if speedup > 10 {
		analysis += ". Consider using the faster approach for performance-critical paths."
	} else if speedup > 2 {
		analysis += ". The performance difference is significant."
	}

	return analysis
}

// saveReport saves the performance report to disk
func (pa *PerformanceAnalyzer) saveReport(report *PerformanceReport) error {
	// Save JSON report
	jsonPath := filepath.Join(pa.outputDir, "performance_report.json")
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}

	if err := os.WriteFile(jsonPath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write JSON report: %w", err)
	}

	// Save human-readable report
	textPath := filepath.Join(pa.outputDir, "performance_report.txt")
	if err := pa.saveTextReport(report, textPath); err != nil {
		return fmt.Errorf("failed to write text report: %w", err)
	}

	return nil
}

// saveTextReport saves a human-readable performance report
func (pa *PerformanceAnalyzer) saveTextReport(report *PerformanceReport, path string) error {
	var content strings.Builder

	content.WriteString(fmt.Sprintf("Performance Analysis Report\n"))
	content.WriteString(fmt.Sprintf("Generated: %s\n", report.Timestamp.Format("2006-01-02 15:04:05")))
	content.WriteString(fmt.Sprintf("Go Version: %s\n", report.GoVersion))
	content.WriteString(fmt.Sprintf("Platform: %s\n\n", report.Platform))

	// Summary
	content.WriteString("SUMMARY\n")
	content.WriteString("=======\n")
	content.WriteString(fmt.Sprintf("Total Benchmarks: %d\n", report.Summary.TotalBenchmarks))
	content.WriteString(fmt.Sprintf("Fastest Operation: %s\n", report.Summary.FastestOperation))
	content.WriteString(fmt.Sprintf("Slowest Operation: %s\n", report.Summary.SlowestOperation))
	content.WriteString(fmt.Sprintf("Highest Memory Usage: %s\n", report.Summary.HighestMemoryUsage))
	content.WriteString(fmt.Sprintf("Average ns/op: %.2f\n", report.Summary.AverageNsPerOp))
	content.WriteString(fmt.Sprintf("Total Allocations: %d\n", report.Summary.TotalAllocations))
	content.WriteString(fmt.Sprintf("Total Bytes Allocated: %d\n\n", report.Summary.TotalBytesAllocated))

	// Detailed results
	content.WriteString("DETAILED RESULTS\n")
	content.WriteString("================\n")
	for _, result := range report.Benchmarks {
		content.WriteString(fmt.Sprintf("%-50s %10d iterations %10d ns/op %8d B/op %6d allocs/op\n",
			result.Name, result.Iterations, result.NsPerOp, result.BytesPerOp, result.AllocsPerOp))
	}
	content.WriteString("\n")

	// Comparisons
	if len(report.Comparisons) > 0 {
		content.WriteString("PERFORMANCE COMPARISONS\n")
		content.WriteString("=======================\n")
		for _, comp := range report.Comparisons {
			content.WriteString(fmt.Sprintf("- %s\n", comp.Analysis))
		}
		content.WriteString("\n")
	}

	// Recommendations
	if len(report.Summary.RecommendedOptimizations) > 0 {
		content.WriteString("OPTIMIZATION RECOMMENDATIONS\n")
		content.WriteString("============================\n")
		for _, rec := range report.Summary.RecommendedOptimizations {
			content.WriteString(fmt.Sprintf("- %s\n", rec))
		}
	}

	return os.WriteFile(path, []byte(content.String()), 0644)
}

// getGoVersion returns the Go version
func (pa *PerformanceAnalyzer) getGoVersion() string {
	cmd := exec.Command("go", "version")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(output))
}

// getPlatform returns platform information
func (pa *PerformanceAnalyzer) getPlatform() string {
	cmd := exec.Command("uname", "-a")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(output))
}

// GenerateProfileAnalysis analyzes CPU and memory profiles if available
func (pa *PerformanceAnalyzer) GenerateProfileAnalysis() error {
	cpuProfilePath := filepath.Join(pa.outputDir, "cpu.prof")
	memProfilePath := filepath.Join(pa.outputDir, "mem.prof")

	// Analyze CPU profile
	if _, err := os.Stat(cpuProfilePath); err == nil {
		if err := pa.analyzeCPUProfile(cpuProfilePath); err != nil {
			return fmt.Errorf("failed to analyze CPU profile: %w", err)
		}
	}

	// Analyze memory profile
	if _, err := os.Stat(memProfilePath); err == nil {
		if err := pa.analyzeMemoryProfile(memProfilePath); err != nil {
			return fmt.Errorf("failed to analyze memory profile: %w", err)
		}
	}

	return nil
}

// analyzeCPUProfile generates CPU profile analysis
func (pa *PerformanceAnalyzer) analyzeCPUProfile(profilePath string) error {
	outputPath := filepath.Join(pa.outputDir, "cpu_analysis.txt")

	cmd := exec.Command("go", "tool", "pprof", "-text", "-cum", profilePath)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to analyze CPU profile: %w", err)
	}

	return os.WriteFile(outputPath, output, 0644)
}

// analyzeMemoryProfile generates memory profile analysis
func (pa *PerformanceAnalyzer) analyzeMemoryProfile(profilePath string) error {
	outputPath := filepath.Join(pa.outputDir, "memory_analysis.txt")

	cmd := exec.Command("go", "tool", "pprof", "-text", "-alloc_space", profilePath)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to analyze memory profile: %w", err)
	}

	return os.WriteFile(outputPath, output, 0644)
}