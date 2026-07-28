// Rule engine — externalizes attack patterns into configurable YAML rules.
//
// It loads rules from a directory, matches them against the endpoints of an
// OpenAPI spec, and generates mutated ("attack") requests. With --send it also
// dispatches those requests (against an in-process mock target by default) and
// runs detection to flag likely-vulnerable endpoints. It runs once and exits.
//
// Expected usage:
//
//	go run ./cmd/engine --rules ../rules --spec ../sample_specs/petstore.yaml
//	go run ./cmd/engine --rules ../rules --spec ../sample_specs/petstore.yaml --send
package main

import (
	"flag"
	"fmt"
	"os"

	"interview/pkg/detect"
	"interview/pkg/engine"
	"interview/pkg/mocktarget"
	"interview/pkg/report"
	"interview/pkg/rule"
	"interview/pkg/sender"
	"interview/pkg/specparser"
	"interview/pkg/valueprovider"
)

func main() {
	rulesDir := flag.String("rules", "", "Path to rules directory")
	specPath := flag.String("spec", "", "Path to OpenAPI spec file")
	send := flag.Bool("send", false, "Send mutated requests and run detection")
	target := flag.String("target", "", "Target base URL (defaults to an in-process mock)")
	concurrency := flag.Int("concurrency", 5, "Max concurrent in-flight requests when sending")
	flag.Parse()

	if *rulesDir == "" || *specPath == "" {
		fmt.Fprintln(os.Stderr, "Usage: engine --rules <dir> --spec <file> [--send] [--target url] [--concurrency n]")
		os.Exit(1)
	}

	// 1. Load endpoints from the OpenAPI spec (provided parser).
	endpoints, err := specparser.ParseSpec(*specPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse spec: %v\n", err)
		os.Exit(1)
	}

	// 2. Load + validate rules; invalid ones are skipped, not fatal.
	rules, loadErrs := rule.LoadRules(*rulesDir)
	fmt.Printf("Loaded %d rule(s) from %s\n", len(rules), *rulesDir)
	for _, e := range loadErrs {
		fmt.Printf("  skipped invalid rule: %s\n", e.Error())
	}

	// 3. Match + mutate (the core pipeline).
	vp := valueprovider.DefaultProvider{}
	attacks, warnings := engine.Run(rules, endpoints, vp)
	for _, w := range warnings {
		fmt.Printf("  warning [%s]: %s\n", w.RuleID, w.Message)
	}
	fmt.Printf("Matched rules against %d endpoint(s); generated %d attack request(s).\n", len(endpoints), len(attacks))

	report.PrintAttacks(os.Stdout, attacks)

	// 4. (Nice-to-have) Send + detect.
	if !*send {
		return
	}

	base := *target
	if base == "" {
		srv := mocktarget.New()
		defer srv.Close()
		base = srv.URL
		fmt.Printf("\nNo --target given; using in-process mock target at %s\n", base)
	}

	responses := sender.Send(attacks, base, *concurrency)
	results := detect.Correlate(attacks, responses, rules)
	report.PrintResults(os.Stdout, results)
}
