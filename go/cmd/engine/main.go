// Rule engine  — this is where you build your solution.
//
// Expected usage:
//
//	go run ./cmd/engine --rules ../../rules --spec ../../sample_specs/petstore.yaml
package main

import (
	"flag"
	"fmt"
	"os"

	"interview/internal/executor"
	"interview/internal/result"
	"interview/internal/rules"
	"interview/pkg/specparser"
)

func main() {
	rulesDir := flag.String("rules", "", "Path to rules directory")
	specPath := flag.String("spec", "", "Path to OpenAPI spec file")
	outputPath := flag.String("output", "", "Optional JSON output file path")
	recursive := flag.Bool("recursive", false, "Recursively search the rules directory")
	sendRequests := flag.Bool("send", false, "Send requests to the endpoints (not implemented)")
	flag.Parse()

	if *rulesDir == "" || *specPath == "" {
		fmt.Fprintln(os.Stderr, "Usage: engine --rules <dir> --spec <file> [--output <file>]")
		os.Exit(2)
	}

	endpoints, err := specparser.ParseSpec(*specPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to parse spec:", err)
		os.Exit(2)
	}

	loadedRules, loadErrors, err := rules.LoadRulesFromDir(*rulesDir, *recursive)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to load rules:", err)
		os.Exit(2)
	}

	for _, loadErr := range loadErrors {
		fmt.Fprintf(os.Stderr, "warning: %s\n", loadErr)
	}

	runOpts := executor.RunOptions{
		SendRequests:          *sendRequests,
		DefaultPathParamValue: "42",
	}
	results := executor.Run(loadedRules, endpoints, runOpts)

	var outFile *os.File
	if *outputPath != "" {
		outFile, err = os.Create(*outputPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "failed to create output file:", err)
			os.Exit(2)
		}
		defer outFile.Close()
	}

	writer := os.Stdout
	if outFile != nil {
		writer = outFile
	}

	if err := result.PrintJSON(results, writer); err != nil {
		fmt.Fprintln(os.Stderr, "failed to write results:", err)
		os.Exit(2)
	}

	exitCode := 0
	for _, res := range results {
		if res.Status == "vulnerable" {
			exitCode = 1
			break
		}
	}
	os.Exit(exitCode)
}
