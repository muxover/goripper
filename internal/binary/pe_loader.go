package binary

import (
	"debug/buildinfo"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
)

// PEBinary implements Binary for Windows PE files.
type PEBinary struct {
	file      *pe.File
	path      string
	size      int64
	imgBase   uint64
	goVersion string
}

func openPE(path string) (*PEBinary, error) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, fmt.Errorf("pe.Open %s: %w", path, err)
	}

	info, err := os.Stat(path)
	if err != nil {
		f.Close()
		return nil, err
	}

	b := &PEBinary{file: f, path: path, size: info.Size()}
	b.imgBase = b.detectImageBase()
	b.goVersion = b.detectGoVersion()
	return b, nil
}

func (b *PEBinary) detectImageBase() uint64 {
	switch oh := b.file.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return uint64(oh.ImageBase)
	case *pe.OptionalHeader64:
		return oh.ImageBase
	}
	return 0x400000
}

func (b *PEBinary) detectGoVersion() string {
	bi, err := buildinfo.ReadFile(b.path)
	if err == nil && bi.GoVersion != "" {
		return bi.GoVersion
	}
	return ""
}

func (b *PEBinary) sectionByName(name string) *pe.Section {
	for _, s := range b.file.Sections {
		if s.Name == name {
			return s
		}
	}
	return nil
}

func (b *PEBinary) Section(name string) ([]byte, error) {
	// Map ELF-style names to PE equivalents
	peName := name
	if name == ".rodata" {
		peName = ".rdata"
	}

	s := b.sectionByName(peName)
	if s == nil {
		s = b.sectionByName(name)
	}
	if s == nil {
		return nil, fmt.Errorf("section %q not found", name)
	}
	data, err := s.Data()
	if err != nil {
		return nil, fmt.Errorf("read section %q: %w", name, err)
	}
	return data, nil
}

func (b *PEBinary) SectionVA(name string) (uint64, error) {
	peName := name
	if name == ".rodata" {
		peName = ".rdata"
	}

	s := b.sectionByName(peName)
	if s == nil {
		s = b.sectionByName(name)
	}
	if s == nil {
		return 0, fmt.Errorf("section %q not found", name)
	}
	return b.imgBase + uint64(s.VirtualAddress), nil
}

func (b *PEBinary) TextSectionRange() (uint64, uint64, error) {
	s := b.sectionByName(".text")
	if s == nil {
		return 0, 0, fmt.Errorf("no .text section")
	}
	start := b.imgBase + uint64(s.VirtualAddress)
	end := start + uint64(s.VirtualSize)
	return start, end, nil
}

func (b *PEBinary) ImageBase() uint64 { return b.imgBase }
func (b *PEBinary) GoVersion() string { return b.goVersion }
func (b *PEBinary) Format() string    { return "PE" }
func (b *PEBinary) Arch() string      { return "x86_64" }
func (b *PEBinary) Size() int64       { return b.size }
func (b *PEBinary) Path() string      { return b.path }

func (b *PEBinary) FindGopclntab() ([]byte, uint64, error) {
	// Scan all sections for gopclntab magic with header validation
	for _, s := range b.file.Sections {
		data, err := s.Data()
		if err != nil {
			continue
		}

		for i := 0; i+8 <= len(data); i += 4 {
			v := binary.LittleEndian.Uint32(data[i : i+4])
			if IsPclntabMagic(v) && isValidPclntabHeader(data[i:]) {
				sectionVA := b.imgBase + uint64(s.VirtualAddress)
				return data[i:], sectionVA + uint64(i), nil
			}
		}
	}

	return nil, 0, fmt.Errorf("gopclntab not found in PE binary")
}

func (b *PEBinary) Close() error {
	return b.file.Close()
}
