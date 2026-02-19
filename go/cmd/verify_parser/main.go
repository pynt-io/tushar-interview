package main

import (
	"fmt"
	"log"

	"interview/pkg/specparser"
)

func main() {
	endpoints, err := specparser.ParseSpec("../sample_specs/petstore.yaml")
	if err != nil {
		log.Fatalf("Failed to parse spec: %v", err)
	}

	fmt.Printf("Parsed %d endpoints:\n", len(endpoints))
	for _, ep := range endpoints {
		fmt.Printf("  %s\n", ep)
	}
}