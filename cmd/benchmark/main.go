package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/codeready/go-tarsy-bot/internal/benchmarks"
)

func main() {
	var (
		outputDir  = flag.String("output", "./benchmark-results", "Output directory for benchmark results")
		iterations = flag.Int("iterations", 3, "Number of benchmark iterations")
		cpuProfile = flag.Bool("cpuprofile", true, "Enable CPU profiling")
		memProfile = flag.Bool("memprofile", true, "Enable memory profiling")
		help       = flag.Bool("help", false, "Show help message")
	)
	flag.Parse()

	if *help {
		fmt.Println("TARSy-bot Performance Benchmark Tool")
		fmt.Println("=====================================")
		fmt.Println()
		fmt.Println("This tool runs comprehensive performance benchmarks for the TARSy-bot agent system")
		fmt.Println("and generates detailed performance analysis reports.")
		fmt.Println()
		fmt.Println("Usage:")
		flag.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  # Run basic benchmarks")
		fmt.Println("  go run cmd/benchmark/main.go")
		fmt.Println()
		fmt.Println("  # Run with custom settings")
		fmt.Println("  go run cmd/benchmark/main.go -output ./my-results -iterations 5")
		fmt.Println()
		fmt.Println("  # Run without profiling")
		fmt.Println("  go run cmd/benchmark/main.go -cpuprofile=false -memprofile=false")
		return
	}

	fmt.Println("🚀 TARSy-bot Performance Benchmark Tool")
	fmt.Println("========================================")
	fmt.Println()

	// Create absolute output directory path
	absOutputDir, err := filepath.Abs(*outputDir)
	if err != nil {
		log.Fatalf("❌ Failed to get absolute path for output directory: %v", err)
	}

	fmt.Printf("📁 Output Directory: %s\n", absOutputDir)
	fmt.Printf("🔄 Iterations: %d\n", *iterations)
	fmt.Printf("🔍 CPU Profiling: %v\n", *cpuProfile)
	fmt.Printf("💾 Memory Profiling: %v\n", *memProfile)
	fmt.Println()

	// Create performance analyzer
	analyzer := benchmarks.NewPerformanceAnalyzer(absOutputDir)
	analyzer.SetIterations(*iterations)
	analyzer.EnableProfiling(*cpuProfile, *memProfile)

	fmt.Println("⏳ Running performance benchmarks...")
	fmt.Println("   This may take several minutes depending on the number of iterations.")
	fmt.Println()

	// Run benchmarks
	report, err := analyzer.RunBenchmarks()
	if err != nil {
		log.Fatalf("❌ Failed to run benchmarks: %v", err)
	}

	// Display summary
	fmt.Println("✅ Benchmarks completed successfully!")
	fmt.Println()
	fmt.Println("📊 PERFORMANCE SUMMARY")
	fmt.Println("======================")
	fmt.Printf("Total Benchmarks: %d\n", report.Summary.TotalBenchmarks)
	fmt.Printf("Fastest Operation: %s\n", report.Summary.FastestOperation)
	fmt.Printf("Slowest Operation: %s\n", report.Summary.SlowestOperation)
	fmt.Printf("Average ns/op: %.2f\n", report.Summary.AverageNsPerOp)
	fmt.Printf("Total Allocations: %d\n", report.Summary.TotalAllocations)
	fmt.Printf("Total Bytes Allocated: %d\n", report.Summary.TotalBytesAllocated)
	fmt.Println()

	// Show top performing benchmarks
	if len(report.Benchmarks) > 0 {
		fmt.Println("🏆 TOP PERFORMING OPERATIONS")
		fmt.Println("============================")

		// Sort benchmarks by performance (fastest first)
		sortedBenchmarks := make([]*benchmarks.BenchmarkResult, len(report.Benchmarks))
		copy(sortedBenchmarks, report.Benchmarks)

		// Simple bubble sort for demonstration
		for i := 0; i < len(sortedBenchmarks)-1; i++ {
			for j := 0; j < len(sortedBenchmarks)-i-1; j++ {
				if sortedBenchmarks[j].NsPerOp > sortedBenchmarks[j+1].NsPerOp {
					sortedBenchmarks[j], sortedBenchmarks[j+1] = sortedBenchmarks[j+1], sortedBenchmarks[j]
				}
			}
		}

		// Show top 5 fastest operations
		maxShow := 5
		if len(sortedBenchmarks) < maxShow {
			maxShow = len(sortedBenchmarks)
		}

		for i := 0; i < maxShow; i++ {
			bench := sortedBenchmarks[i]
			fmt.Printf("%d. %-40s %8d ns/op %6d B/op %4d allocs/op\n",
				i+1, bench.Name, bench.NsPerOp, bench.BytesPerOp, bench.AllocsPerOp)
		}
		fmt.Println()
	}

	// Show performance comparisons
	if len(report.Comparisons) > 0 {
		fmt.Println("⚖️  PERFORMANCE COMPARISONS")
		fmt.Println("===========================")
		for _, comp := range report.Comparisons {
			fmt.Printf("• %s\n", comp.Analysis)
		}
		fmt.Println()
	}

	// Show optimization recommendations
	if len(report.Summary.RecommendedOptimizations) > 0 {
		fmt.Println("💡 OPTIMIZATION RECOMMENDATIONS")
		fmt.Println("================================")
		for i, rec := range report.Summary.RecommendedOptimizations {
			fmt.Printf("%d. %s\n", i+1, rec)
		}
		fmt.Println()
	}

	// Generate profile analysis if profiling was enabled
	if *cpuProfile || *memProfile {
		fmt.Println("🔍 Generating profile analysis...")
		if err := analyzer.GenerateProfileAnalysis(); err != nil {
			fmt.Printf("⚠️  Warning: Failed to generate profile analysis: %v\n", err)
		} else {
			fmt.Println("✅ Profile analysis completed!")
		}
		fmt.Println()
	}

	// Show output files
	fmt.Println("📄 OUTPUT FILES")
	fmt.Println("===============")
	fmt.Printf("Performance Report (JSON): %s\n", filepath.Join(absOutputDir, "performance_report.json"))
	fmt.Printf("Performance Report (Text): %s\n", filepath.Join(absOutputDir, "performance_report.txt"))

	if *cpuProfile {
		cpuProfilePath := filepath.Join(absOutputDir, "cpu.prof")
		cpuAnalysisPath := filepath.Join(absOutputDir, "cpu_analysis.txt")
		if _, err := os.Stat(cpuProfilePath); err == nil {
			fmt.Printf("CPU Profile: %s\n", cpuProfilePath)
		}
		if _, err := os.Stat(cpuAnalysisPath); err == nil {
			fmt.Printf("CPU Analysis: %s\n", cpuAnalysisPath)
		}
	}

	if *memProfile {
		memProfilePath := filepath.Join(absOutputDir, "mem.prof")
		memAnalysisPath := filepath.Join(absOutputDir, "memory_analysis.txt")
		if _, err := os.Stat(memProfilePath); err == nil {
			fmt.Printf("Memory Profile: %s\n", memProfilePath)
		}
		if _, err := os.Stat(memAnalysisPath); err == nil {
			fmt.Printf("Memory Analysis: %s\n", memAnalysisPath)
		}
	}

	fmt.Println()
	fmt.Println("🎉 Performance analysis complete!")
	fmt.Printf("📁 All results saved to: %s\n", absOutputDir)
	fmt.Println()
	fmt.Println("💻 To view detailed results:")
	fmt.Printf("   cat %s\n", filepath.Join(absOutputDir, "performance_report.txt"))

	if *cpuProfile {
		fmt.Println()
		fmt.Println("🔥 To view CPU profile interactively:")
		fmt.Printf("   go tool pprof %s\n", filepath.Join(absOutputDir, "cpu.prof"))
	}

	if *memProfile {
		fmt.Println()
		fmt.Println("💾 To view memory profile interactively:")
		fmt.Printf("   go tool pprof %s\n", filepath.Join(absOutputDir, "mem.prof"))
	}
}