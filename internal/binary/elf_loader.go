package binary

import (
	"debug/buildinfo"
	"debug/elf"
	"fmt"
	"os"
)

type ELFBinary struct {
	file      *elf.File
	path      string
	size      int64
	arch      string
	goVersion string
}

func openELF(path string) (*ELFBinary, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("elf.Open %s: %w", path, err)
	}

	info, err := os.Stat(path)
	if err != nil {
		f.Close()
		return nil, err
	}

	b := &ELFBinary{file: f, path: path, size: info.Size(), arch: elfArch(f)}
	b.goVersion = b.detectGoVersion()
	return b, nil
}

func elfArch(f *elf.File) string {
	switch f.Machine {
	case elf.EM_AARCH64:
		return "arm64"
	case elf.EM_ARM:
		return "arm"
	case elf.EM_386:
		return "x86"
	default:
		return "x86_64"
	}
}

func (b *ELFBinary) detectGoVersion() string {
	bi, err := buildinfo.ReadFile(b.path)
	if err == nil && bi.GoVersion != "" {
		return bi.GoVersion
	}
	return ""
}

func (b *ELFBinary) Section(name string) ([]byte, error) {
	s := b.file.Section(name)
	if s == nil {
		return nil, fmt.Errorf("section %q not found", name)
	}
	data, err := s.Data()
	if err != nil {
		return nil, fmt.Errorf("read section %q: %w", name, err)
	}
	return data, nil
}

func (b *ELFBinary) SectionVA(name string) (uint64, error) {
	s := b.file.Section(name)
	if s == nil {
		return 0, fmt.Errorf("section %q not found", name)
	}
	return s.Addr, nil
}

func (b *ELFBinary) TextSectionRange() (uint64, uint64, error) {
	s := b.file.Section(".text")
	if s == nil {
		return 0, 0, fmt.Errorf("no .text section")
	}
	return s.Addr, s.Addr + s.Size, nil
}

func (b *ELFBinary) ImageBase() uint64 {
	// PIE ELF has load address 0; non-PIE reports the min PT_LOAD vaddr.
	for _, prog := range b.file.Progs {
		if prog.Type == elf.PT_LOAD && prog.Flags&elf.PF_X != 0 {
			return prog.Vaddr - prog.Off
		}
	}
	return 0
}

func (b *ELFBinary) SectionNames() []string {
	names := make([]string, 0, len(b.file.Sections))
	for _, s := range b.file.Sections {
		names = append(names, s.Name)
	}
	return names
}

func (b *ELFBinary) GoVersion() string { return b.goVersion }
func (b *ELFBinary) Format() string    { return "ELF" }
func (b *ELFBinary) Arch() string      { return b.arch }
func (b *ELFBinary) Size() int64       { return b.size }
func (b *ELFBinary) Path() string      { return b.path }

func (b *ELFBinary) FindGopclntab() ([]byte, uint64, error) {
	if s := b.file.Section(".gopclntab"); s != nil {
		data, err := s.Data()
		if err != nil {
			return nil, 0, err
		}
		return data, s.Addr, nil
	}

	for _, secName := range []string{".text", ".rodata", ".data"} {
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

	return nil, 0, fmt.Errorf("gopclntab not found in ELF binary")
}

func (b *ELFBinary) Close() error {
	return b.file.Close()
}

func (b *ELFBinary) DynSymbols() map[uint64]string {
	result := make(map[uint64]string)
	syms, err := b.file.DynamicSymbols()
	if err != nil {
		return result
	}
	for _, sym := range syms {
		if sym.Value != 0 {
			result[sym.Value] = sym.Name
		}
	}
	return result
}

func (b *ELFBinary) TypeLinks() ([]byte, uint64, error) {
	s := b.file.Section(".typelinks")
	if s == nil {
		return nil, 0, fmt.Errorf("no .typelinks section")
	}
	data, err := s.Data()
	if err != nil {
		return nil, 0, err
	}
	return data, s.Addr, nil
}
