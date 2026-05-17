package classify

import "testing"

func TestClassify_RAT(t *testing.T) {
	in := Input{
		BehaviorTags:   []string{"NETWORK", "EXECUTION", "FILE_READ"},
		HasConcurrency: true,
		HasNetwork:     true,
		HasExecution:   true,
		HasFileRead:    true,
	}
	r := Classify(in)
	if r.Class != ClassRAT {
		t.Errorf("class = %q, want RAT", r.Class)
	}
}

func TestClassify_Downloader(t *testing.T) {
	in := Input{
		BehaviorTags: []string{"NETWORK", "FILE_WRITE"},
		HasNetwork:   true,
		HasFileWrite: true,
		URLCount:     3,
	}
	r := Classify(in)
	if r.Class != ClassDownloader {
		t.Errorf("class = %q, want DOWNLOADER", r.Class)
	}
}

func TestClassify_Ransomware(t *testing.T) {
	in := Input{
		BehaviorTags: []string{"CRYPTO", "FILE_WRITE"},
		HasCrypto:    true,
		HasFileWrite: true,
		StringValues: []string{".docx", ".xlsx", ".pdf"},
	}
	r := Classify(in)
	if r.Class != ClassRansomware {
		t.Errorf("class = %q, want RANSOMWARE", r.Class)
	}
}

func TestClassify_Tool(t *testing.T) {
	in := Input{
		BehaviorTags: []string{},
	}
	r := Classify(in)
	if r.Class != ClassTool {
		t.Errorf("class = %q, want TOOL", r.Class)
	}
}

func TestClassify_Unknown(t *testing.T) {
	in := Input{
		BehaviorTags: []string{"NETWORK", "MEMORY"},
		HasNetwork:   true,
		HasMemory:    true,
	}
	r := Classify(in)
	if r.Class != ClassUnknown {
		t.Errorf("class = %q, want UNKNOWN", r.Class)
	}
}

func TestClassify_Cryptominer(t *testing.T) {
	in := Input{
		BehaviorTags: []string{"NETWORK"},
		HasNetwork:   true,
		StringValues: []string{"stratum+tcp://pool.minexmr.com:4444"},
	}
	r := Classify(in)
	if r.Class != ClassCryptominer {
		t.Errorf("class = %q, want CRYPTOMINER", r.Class)
	}
}
