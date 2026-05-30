package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"github.com/muxover/goripper/internal/output"
	"github.com/muxover/goripper/internal/trace"
)

func mergeTraceData(result *output.AnalysisResult, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open trace data file: %w", err)
	}
	defer f.Close()

	var events []trace.Event
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev trace.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			return fmt.Errorf("parse event line: %w", err)
		}
		events = append(events, ev)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read trace file: %w", err)
	}

	trace.Merge(result, events)
	return nil
}
