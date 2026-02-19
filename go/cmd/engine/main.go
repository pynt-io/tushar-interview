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
)

func main() {
	rulesDir := flag.String("rules", "", "Path to rules directory")
	specPath := flag.String("spec", "", "Path to OpenAPI spec file")
	flag.Parse()

	if *rulesDir == "" || *specPath == "" {
		fmt.Fprintln(os.Stderr, "Usage: engine --rules <dir> --spec <file>")
		os.Exit(1)
	}

	// TODO: implement your rule engine here
	fmt.Printf("Rules dir: %s\n", *rulesDir)
	fmt.Printf("Spec file: %s\n", *specPath)
}