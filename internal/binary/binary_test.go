package binary_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/muxover/goripper/internal/binary"
)

// elfFixture returns the path to the pre-built linux/amd64 ELF fixture,
// skipping the test if the file does not exist.
func elfFixture(t *testing.T) string {
	t.Helper()
	// Locate testdata relative to this test file's directory.
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	path := filepath.Join(repoRoot, "testdata", "fixture_linux_amd64")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("ELF fixture not found (%s); run testdata/build_elf_fixture.sh first", path)
	}
	return path
}

func TestOpen_OnTestBinary(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	bin, err := binary.Open(exe)
	if err != nil {
		t.Fatalf("binary.Open: %v", err)
	}
	defer bin.Close()

	wantFormat := "PE"
	if runtime.GOOS != "windows" {
		wantFormat = "ELF"
	}
	if bin.Format() != wantFormat {
		t.Errorf("Format = %q, want %q", bin.Format(), wantFormat)
	}
	if bin.Arch() != "x86_64" {
		t.Errorf("Arch = %q, want x86_64", bin.Arch())
	}
	if bin.Size() <= 0 {
		t.Error("Size should be positive")
	}
}

func TestSectionVA_Rodata(t *testing.T) {
	exe, _ := os.Executable()
	bin, err := binary.Open(exe)
	if err != nil {
		t.Fatalf("binary.Open: %v", err)
	}
	defer bin.Close()

	section := ".rdata"
	if runtime.GOOS != "windows" {
		section = ".rodata"
	}
	va, err := bin.SectionVA(section)
	if err != nil {
		t.Fatalf("SectionVA(%s): %v", section, err)
	}
	if va == 0 {
		t.Errorf("SectionVA(%s) returned 0", section)
	}
}

func TestSectionData_Roundtrip(t *testing.T) {
	exe, _ := os.Executable()
	bin, err := binary.Open(exe)
	if err != nil {
		t.Fatalf("binary.Open: %v", err)
	}
	defer bin.Close()

	section := ".rdata"
	if runtime.GOOS != "windows" {
		section = ".rodata"
	}
	data, err := bin.Section(section)
	if err != nil {
		t.Fatalf("Section(%s): %v", section, err)
	}
	if len(data) == 0 {
		t.Errorf("Section(%s) returned empty slice", section)
	}
}

func TestIsPclntabMagic_KnownGoodMagics(t *testing.T) {
	good := []uint32{0xFFFFFFFB, 0xFFFFFFFA, 0xFFFFFFF0, 0xFFFFFFF1}
	for _, m := range good {
		if !binary.IsPclntabMagic(m) {
			t.Errorf("IsPclntabMagic(%#x) = false, want true", m)
		}
	}

	bad := []uint32{0x00000000, 0xDEADBEEF, 0xFFFFFFFE, 0x4D5A9000}
	for _, m := range bad {
		if binary.IsPclntabMagic(m) {
			t.Errorf("IsPclntabMagic(%#x) = true, want false", m)
		}
	}
}

func TestPclntabNfunc_BelowThreshold(t *testing.T) {
	// Craft a minimal 12-byte pclntab header: magic(4) + pad(2) + minLC(1) + ptrSize(1) + nfunc_lo32(4)
	// We use Go1.20+ magic 0xFFFFFFF1 with nfunc=5 (below the ScanForPclntab threshold of 10)
	hdr := []byte{
		0xF1, 0xFF, 0xFF, 0xFF, // magic (LE)
		0x00, 0x00,             // pad
		0x01,                   // minLC (x86=1)
		0x08,                   // ptrSize=8
		0x05, 0x00, 0x00, 0x00, // nfunc=5 (LE uint32)
	}
	// ScanForPclntab should NOT find it (nfunc < 10 threshold)
	idx := binary.ScanForPclntab(hdr)
	if idx != -1 {
		t.Errorf("ScanForPclntab found header with nfunc=5 at %d, expected -1", idx)
	}

	// With nfunc=50, it should be found at offset 0
	hdr[8] = 50
	idx = binary.ScanForPclntab(hdr)
	if idx != 0 {
		t.Errorf("ScanForPclntab with nfunc=50: got %d, want 0", idx)
	}
}

func TestBinaryMetadata(t *testing.T) {
	exe, _ := os.Executable()
	bin, err := binary.Open(exe)
	if err != nil {
		t.Fatalf("binary.Open: %v", err)
	}
	defer bin.Close()

	if bin.Path() != exe {
		t.Errorf("Path() = %q, want %q", bin.Path(), exe)
	}
	if bin.ImageBase() == 0 {
		t.Error("ImageBase() returned 0")
	}
	_ = bin.GoVersion() // must not panic; may be empty if buildinfo stripped
}

func TestTextSectionRange(t *testing.T) {
	exe, _ := os.Executable()
	bin, err := binary.Open(exe)
	if err != nil {
		t.Fatalf("binary.Open: %v", err)
	}
	defer bin.Close()

	start, end, err := bin.TextSectionRange()
	if err != nil {
		t.Fatalf("TextSectionRange: %v", err)
	}
	if start == 0 {
		t.Error("TextSectionRange start is 0")
	}
	if end <= start {
		t.Errorf("TextSectionRange end (%#x) <= start (%#x)", end, start)
	}
}

func TestFindGopclntab(t *testing.T) {
	exe, _ := os.Executable()
	bin, err := binary.Open(exe)
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
		t.Errorf("FindGopclntab magic %#x is not a valid pclntab magic", magic)
	}
}

func TestOpen_NonBinary_ReturnsError(t *testing.T) {
	// Write random non-binary content to a temp file
	f, err := os.CreateTemp("", "goripper-test-*.bin")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer os.Remove(f.Name())
	f.Write([]byte("this is not a binary file, just plain text"))
	f.Close()

	bin, err := binary.Open(f.Name())
	if err == nil {
		bin.Close()
		t.Error("expected error opening non-binary file, got nil")
	}
}

// --- ELF fixture tests (platform-agnostic: debug/elf parses on any OS) ---

func TestELFFixture_Open(t *testing.T) {
	path := elfFixture(t)
	bin, err := binary.Open(path)
	if err != nil {
		t.Fatalf("binary.Open ELF fixture: %v", err)
	}
	defer bin.Close()

	if bin.Format() != "ELF" {
		t.Errorf("Format = %q, want ELF", bin.Format())
	}
	if bin.Arch() != "x86_64" {
		t.Errorf("Arch = %q, want x86_64", bin.Arch())
	}
	if bin.Size() <= 0 {
		t.Error("Size should be positive")
	}
	if bin.Path() != path {
		t.Errorf("Path = %q, want %q", bin.Path(), path)
	}
}

func TestELFFixture_Sections(t *testing.T) {
	path := elfFixture(t)
	bin, err := binary.Open(path)
	if err != nil {
		t.Fatalf("binary.Open: %v", err)
	}
	defer bin.Close()

	data, err := bin.Section(".rodata")
	if err != nil {
		t.Fatalf("Section(.rodata): %v", err)
	}
	if len(data) == 0 {
		t.Error("Section(.rodata) returned empty data")
	}

	va, err := bin.SectionVA(".rodata")
	if err != nil {
		t.Fatalf("SectionVA(.rodata): %v", err)
	}
	if va == 0 {
		t.Error("SectionVA(.rodata) returned 0")
	}
}

func TestELFFixture_TextRange(t *testing.T) {
	path := elfFixture(t)
	bin, err := binary.Open(path)
	if err != nil {
		t.Fatalf("binary.Open: %v", err)
	}
	defer bin.Close()

	start, end, err := bin.TextSectionRange()
	if err != nil {
		t.Fatalf("TextSectionRange: %v", err)
	}
	if start == 0 {
		t.Error("TextSectionRange start is 0")
	}
	if end <= start {
		t.Errorf("TextSectionRange end (%#x) <= start (%#x)", end, start)
	}
}

func TestELFFixture_FindGopclntab(t *testing.T) {
	path := elfFixture(t)
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
		t.Errorf("ELF gopclntab magic %#x is not valid", magic)
	}
}

func TestELFFixture_Metadata(t *testing.T) {
	path := elfFixture(t)
	bin, err := binary.Open(path)
	if err != nil {
		t.Fatalf("binary.Open: %v", err)
	}
	defer bin.Close()

	if bin.ImageBase() == 0 {
		t.Error("ImageBase() returned 0 for ELF")
	}
	_ = bin.GoVersion() // must not panic
}
