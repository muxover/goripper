package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// WriteJSON marshals the AnalysisResult to JSON and writes it to w.
func WriteJSON(result *AnalysisResult, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// WriteJSONFile writes the AnalysisResult as JSON to a file in outDir.
// The filename is derived from the binary name.
func WriteJSONFile(result *AnalysisResult, outDir string) error {
	base := filepath.Base(result.BinaryInfo.Path)
	outPath := filepath.Join(outDir, base+".json")

	f, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer f.Close()

	return WriteJSON(result, f)
}
