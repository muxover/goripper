package binary

import (
	"debug/buildinfo"
	"debug/elf"
	"fmt"
	"os"
)

// ELFBinary implements Binary for Linux ELF files.
type ELFBinary struct {
	file      *elf.File
	path      string
	size      int64
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

	b := &ELFBinary{file: f, path: path, size: info.Size()}
	b.goVersion = b.detectGoVersion()
	return b, nil
}

func (b *ELFBinary) detectGoVersion() string {
	bi, err := buildinfo.ReadFile(b.path)
	if err == nil && bi.GoVersion != "" {
		return bi.GoVersion
	}
	return ""
}

func (b *ELFBinary) Section(name string) ([]byte, error) {
	// ELF uses .rodata, PE uses .rdata — handle both names
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
	// For PIE ELF binaries the load address is 0; for non-PIE it's the min PT_LOAD addr.
	for _, prog := range b.file.Progs {
		if prog.Type == elf.PT_LOAD && prog.Flags&elf.PF_X != 0 {
			return prog.Vaddr - prog.Off
		}
	}
	return 0
}

func (b *ELFBinary) GoVersion() string { return b.goVersion }
func (b *ELFBinary) Format() string    { return "ELF" }
func (b *ELFBinary) Arch() string      { return "x86_64" }
func (b *ELFBinary) Size() int64       { return b.size }
func (b *ELFBinary) Path() string      { return b.path }

func (b *ELFBinary) FindGopclntab() ([]byte, uint64, error) {
	// ELF: try .gopclntab section first
	if s := b.file.Section(".gopclntab"); s != nil {
		data, err := s.Data()
		if err != nil {
			return nil, 0, err
		}
		return data, s.Addr, nil
	}

	// Fallback: scan .text and .rodata for magic
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

// DynSymbols returns name->addr map of dynamic symbols (for PLT resolution).
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

// TypeLinks returns the raw bytes of the .typelinks section, if present.
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
