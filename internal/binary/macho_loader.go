package binary

import (
	"debug/buildinfo"
	"debug/macho"
	"fmt"
	"os"
)

type MachoBinary struct {
	file      *macho.File
	path      string
	size      int64
	arch      string
	goVersion string
}

func openMacho(path string) (*MachoBinary, error) {
	// Try fat binary first (universal binary with multiple arch slices).
	fat, err := macho.OpenFat(path)
	if err == nil {
		defer fat.Close()
		// Prefer amd64, then arm64.
		for _, want := range []macho.Cpu{macho.CpuAmd64, macho.CpuArm64} {
			for _, arch := range fat.Arches {
				if arch.Cpu == want {
					return newMachoBinary(arch.File, path)
				}
			}
		}
		return nil, fmt.Errorf("no supported arch in fat binary")
	}

	f, err := macho.Open(path)
	if err != nil {
		return nil, fmt.Errorf("macho.Open %s: %w", path, err)
	}
	return newMachoBinary(f, path)
}

func newMachoBinary(f *macho.File, path string) (*MachoBinary, error) {
	info, err := os.Stat(path)
	if err != nil {
		f.Close()
		return nil, err
	}
	arch := "x86_64"
	if f.Cpu == macho.CpuArm64 {
		arch = "arm64"
	}
	b := &MachoBinary{file: f, path: path, size: info.Size(), arch: arch}
	b.goVersion = b.detectGoVersion()
	return b, nil
}

func (b *MachoBinary) detectGoVersion() string {
	bi, err := buildinfo.ReadFile(b.path)
	if err == nil && bi.GoVersion != "" {
		return bi.GoVersion
	}
	return ""
}

// machoSection maps canonical GoRipper section names to Mach-O section names.
// Mach-O sections are identified by their section name (without segment prefix).
var machoSectionMap = map[string][]string{
	".text":      {"__text"},
	".rodata":    {"__rodata", "__const"},
	".gopclntab": {"__gopclntab"},
	".typelinks": {"__typelinks"},
	".itablink":  {"__itablink"},
	".noptrdata": {"__noptrdata"},
	".data":      {"__data"},
	".bss":       {"__bss"},
}

func (b *MachoBinary) findSection(name string) *macho.Section {
	candidates, ok := machoSectionMap[name]
	if !ok {
		// Try direct lookup as-is (already a Mach-O name like "__text").
		if s := b.file.Section(name); s != nil {
			return s
		}
		return nil
	}
	for _, candidate := range candidates {
		if s := b.file.Section(candidate); s != nil {
			return s
		}
	}
	return nil
}

func (b *MachoBinary) Section(name string) ([]byte, error) {
	s := b.findSection(name)
	if s == nil {
		return nil, fmt.Errorf("section %q not found", name)
	}
	data, err := s.Data()
	if err != nil {
		return nil, fmt.Errorf("read section %q: %w", name, err)
	}
	return data, nil
}

func (b *MachoBinary) SectionVA(name string) (uint64, error) {
	s := b.findSection(name)
	if s == nil {
		return 0, fmt.Errorf("section %q not found", name)
	}
	return s.Addr, nil
}

func (b *MachoBinary) TextSectionRange() (uint64, uint64, error) {
	s := b.file.Section("__text")
	if s == nil {
		return 0, 0, fmt.Errorf("no __text section")
	}
	return s.Addr, s.Addr + s.Size, nil
}

func (b *MachoBinary) ImageBase() uint64 {
	// Mach-O load address comes from the first LC_SEGMENT_64 with vmaddr > 0.
	for _, load := range b.file.Loads {
		if seg, ok := load.(*macho.Segment); ok && seg.Name == "__TEXT" {
			return seg.Addr
		}
	}
	return 0
}

func (b *MachoBinary) SectionNames() []string {
	names := make([]string, 0, len(b.file.Sections))
	for _, s := range b.file.Sections {
		names = append(names, s.Name)
	}
	return names
}

func (b *MachoBinary) GoVersion() string { return b.goVersion }
func (b *MachoBinary) Format() string    { return "Mach-O" }
func (b *MachoBinary) Arch() string      { return b.arch }
func (b *MachoBinary) Size() int64       { return b.size }
func (b *MachoBinary) Path() string      { return b.path }

func (b *MachoBinary) FindGopclntab() ([]byte, uint64, error) {
	if s := b.file.Section("__gopclntab"); s != nil {
		data, err := s.Data()
		if err != nil {
			return nil, 0, err
		}
		return data, s.Addr, nil
	}

	for _, secName := range []string{"__text", "__rodata", "__data"} {
		s := b.file.Section(secName)
		if s == nil {
			continue
		}
		data, err := s.Data()
		if err != nil {
			continue
		}
		off := ScanForPclntab(data)
		if off >= 0 {
			return data[off:], s.Addr + uint64(off), nil
		}
	}

	return nil, 0, fmt.Errorf("gopclntab not found in Mach-O binary")
}

func (b *MachoBinary) Close() error {
	return b.file.Close()
}

func (b *MachoBinary) TypeLinks() ([]byte, uint64, error) {
	s := b.file.Section("__typelinks")
	if s == nil {
		return nil, 0, fmt.Errorf("no __typelinks section")
	}
	data, err := s.Data()
	if err != nil {
		return nil, 0, err
	}
	return data, s.Addr, nil
}
