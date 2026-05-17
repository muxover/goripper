package binary_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/muxover/goripper/internal/binary"
)

func machoFixture(t *testing.T) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	path := filepath.Join(repoRoot, "testdata", "fixture_macho_amd64")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("Mach-O fixture not found (%s); build it with testdata/build_macho_fixture.sh first", path)
	}
	return path
}

func TestMachoMagic_Detection(t *testing.T) {
	// Open a temp file with each valid Mach-O magic and verify the error is NOT "unknown binary format".
	// We expect a Mach-O parse error (not enough data), not a format-unknown error.
	cases := []struct {
		name  string
		magic []byte
	}{
		{"64-bit LE", []byte{0xCF, 0xFA, 0xED, 0xFE}},
		{"32-bit LE", []byte{0xCE, 0xFA, 0xED, 0xFE}},
		{"64-bit BE", []byte{0xFE, 0xED, 0xFA, 0xCF}},
		{"32-bit BE", []byte{0xFE, 0xED, 0xFA, 0xCE}},
		{"fat binary", []byte{0xCA, 0xFE, 0xBA, 0xBE}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.CreateTemp("", "goripper-macho-*.bin")
			if err != nil {
				t.Fatalf("CreateTemp: %v", err)
			}
			defer os.Remove(f.Name())
			// Write magic + 60 zero bytes so macho.Open has something to chew on.
			f.Write(tc.magic)
			f.Write(make([]byte, 60))
			f.Close()

			_, err = binary.Open(f.Name())
			// We expect either success or a Mach-O-specific error.
			// What we must NOT get is "unknown binary format".
			if err != nil {
				msg := err.Error()
				for _, bad := range []string{"unknown binary format"} {
					if len(msg) >= len(bad) && msg[:len(bad)] == bad {
						t.Errorf("magic %s was classified as unknown format: %v", tc.name, err)
					}
				}
			}
		})
	}
}

func TestOpen_ELF_NotMacho(t *testing.T) {
	// ELF magic must not be mistaken for Mach-O.
	f, err := os.CreateTemp("", "goripper-elf-*.bin")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer os.Remove(f.Name())
	f.Write([]byte{0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00})
	f.Close()

	_, err = binary.Open(f.Name())
	// ELF Open may fail (truncated), but must not be "unknown binary format".
	if err != nil {
		msg := err.Error()
		if len(msg) > 22 && msg[:22] == "unknown binary format" {
			t.Errorf("ELF binary was incorrectly classified as unknown: %v", err)
		}
	}
}

func TestMachoFixture_Open(t *testing.T) {
	path := machoFixture(t)
	bin, err := binary.Open(path)
	if err != nil {
		t.Fatalf("binary.Open Mach-O fixture: %v", err)
	}
	defer bin.Close()

	if bin.Format() != "Mach-O" {
		t.Errorf("Format = %q, want Mach-O", bin.Format())
	}
	arch := bin.Arch()
	if arch != "x86_64" && arch != "arm64" {
		t.Errorf("Arch = %q, want x86_64 or arm64", arch)
	}
	if bin.Size() <= 0 {
		t.Error("Size should be positive")
	}
}

func TestMachoFixture_Sections(t *testing.T) {
	path := machoFixture(t)
	bin, err := binary.Open(path)
	if err != nil {
		t.Fatalf("binary.Open: %v", err)
	}
	defer bin.Close()

	data, err := bin.Section(".text")
	if err != nil {
		t.Fatalf("Section(.text): %v", err)
	}
	if len(data) == 0 {
		t.Error("Section(.text) returned empty data")
	}

	va, err := bin.SectionVA(".text")
	if err != nil {
		t.Fatalf("SectionVA(.text): %v", err)
	}
	if va == 0 {
		t.Error("SectionVA(.text) returned 0")
	}
}

func TestMachoFixture_FindGopclntab(t *testing.T) {
	path := machoFixture(t)
	bin, err := binary.Open(path)
	if err != nil {
		t.Fatalf("binary.Open: %v", err)
	}
	defer bin.Close()

	data, va, err := bin.FindGopclntab()
	if err != nil {
		t.Fatalf("FindGopclntab: %v", err)
	}
	if len(data) == 0 {
		t.Error("FindGopclntab returned empty data")
	}
	if va == 0 {
		t.Error("FindGopclntab returned VA=0")
	}
	magic := uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
	if !binary.IsPclntabMagic(magic) {
		t.Errorf("Mach-O gopclntab magic %#x is not valid", magic)
	}
}

func TestMachoFixture_ImageBase(t *testing.T) {
	path := machoFixture(t)
	bin, err := binary.Open(path)
	if err != nil {
		t.Fatalf("binary.Open: %v", err)
	}
	defer bin.Close()

	base := bin.ImageBase()
	if base == 0 {
		t.Error("ImageBase() returned 0 for Mach-O")
	}
}
