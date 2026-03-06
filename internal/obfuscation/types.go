package obfuscation

// Result holds the full obfuscation assessment for a binary.
type Result struct {
	Score      float64  // 0.0 (clean) – 1.0 (fully obfuscated)
	Level      string   // "none" | "low" | "medium" | "high"
	Indicators []string // human-readable reasons that raised the score
}

// StubMatch describes a suspected string-decryption stub function.
type StubMatch struct {
	FuncName  string // function name (may be garbled)
	FuncAddr  uint64
	CallerCount int    // how many functions call this stub
	XORKey    byte   // non-zero if a single-byte XOR key was detected
	HasXORKey bool
}
