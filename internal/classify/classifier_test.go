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
		// No NETWORK — ransomware is typically offline after payload drop.
		BehaviorTags: []string{"CRYPTO", "FILE_WRITE", "FILE_READ"},
		HasCrypto:    true,
		HasFileWrite: true,
		HasFileRead:  true,
		ObfScore:     0.7, // ransomware is heavily obfuscated
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
		// MINER tag is produced by the behavior tagger when mining pool calls are found.
		BehaviorTags: []string{"NETWORK", "MINER"},
		HasNetwork:   true,
	}
	r := Classify(in)
	if r.Class != ClassCryptominer {
		t.Errorf("class = %q, want CRYPTOMINER", r.Class)
	}
}
