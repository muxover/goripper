// Package main is a minimal fixture binary used by GoRipper integration tests.
// It imports net/http so behavior tags fire, and embeds a URL constant so string
// classification is exercised.
package main

import (
	"fmt"
	"net/http"
	"os"
)

const apiURL = "https://example.com/api/v1"

func fetchData(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	fmt.Fprintf(os.Stdout, "status: %s\n", resp.Status)
	return nil
}

func main() {
	if err := fetchData(apiURL); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
