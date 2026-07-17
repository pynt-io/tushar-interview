// Rule engine — loads YAML attack signatures, matches OpenAPI endpoints,
// applies mutations, and prints structured results.
//
// Expected usage:
//
//	go run ./cmd/engine --rules ../rules --spec ../sample_specs/petstore.yaml
package main

import (
	"flag"
	"fmt"
	"os"

	"interview/internal/config"
	"interview/internal/engine"
	"interview/internal/mutation"
	"interview/internal/output"
)

func main() {
	rulesDir := flag.String("rules", "", "Path to rules directory")
	specPath := flag.String("spec", "", "Path to OpenAPI spec file")
	flag.Parse()

	if *rulesDir == "" || *specPath == "" {
		fmt.Fprintln(os.Stderr, "Usage: engine --rules <dir> --spec <file>")
		os.Exit(1)
	}

	eng := engine.New(mutation.DefaultRegistry())
	summary, err := eng.Run(config.Options{
		RulesDir: *rulesDir,
		SpecPath: *specPath,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if err := output.WriteHuman(os.Stdout, summary, summary.Warnings); err != nil {
		fmt.Fprintf(os.Stderr, "error writing output: %v\n", err)
		os.Exit(1)
	}
}
