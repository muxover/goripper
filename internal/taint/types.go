package taint

type source struct {
	name    string
	pattern string // call target prefix
}

type sink struct {
	name    string
	pattern string
}

// TaintFlow describes one source-to-sink reachability path.
type TaintFlow struct {
	Source     string   `json:"source"`      // e.g. "os.Args"
	SourceFunc string   `json:"source_func"` // function that reads the source
	Sink       string   `json:"sink"`        // e.g. "os/exec.Command"
	SinkFunc   string   `json:"sink_func"`   // function that calls the sink
	Path       []string `json:"path"`        // call chain from source_func to sink_func
	Confidence string   `json:"confidence"`  // "high" | "medium" | "low"
}
