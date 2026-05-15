package types

import (
	"encoding/binary"

	gobinary "github.com/muxover/goripper/internal/binary"
)

type InterfaceImpl struct {
	Interface string `json:"interface"`
	Concrete  string `json:"concrete"`
	ItabAddr  uint64 `json:"itab_addr"`
}

// Each entry in .itablink is a pointer to an itab struct:
//
//	itab { inter *interfacetype; _type *_type; hash uint32; _ [4]byte; fun [1]uintptr }
func RecoverItabs(bin gobinary.Binary) ([]InterfaceImpl, error) {
	itablinkData, err := bin.Section(".itablink")
	if err != nil || len(itablinkData) == 0 {
		return nil, nil
	}

	// Build a VA→data map from all sections we can read.
	secMap := buildSectionMap(bin)

	order := binary.LittleEndian
	var result []InterfaceImpl
	seen := make(map[uint64]bool)

	for i := 0; i+8 <= len(itablinkData); i += 8 {
		itabVA := order.Uint64(itablinkData[i : i+8])
		if itabVA == 0 || seen[itabVA] {
			continue
		}
		seen[itabVA] = true

		// itab: [0:8] inter *interfacetype, [8:16] _type *_type
		itabBytes, itabOff, ok := resolveVA(itabVA, secMap)
		if !ok || itabOff+16 > len(itabBytes) {
			continue
		}

		interPtr := order.Uint64(itabBytes[itabOff : itabOff+8])
		typePtr := order.Uint64(itabBytes[itabOff+8 : itabOff+16])

		ifaceName := resolveRtypeName(interPtr, secMap, order)
		concreteName := resolveRtypeName(typePtr, secMap, order)

		if ifaceName == "" || concreteName == "" {
			continue
		}

		result = append(result, InterfaceImpl{
			Interface: ifaceName,
			Concrete:  concreteName,
			ItabAddr:  itabVA,
		})
	}

	return result, nil
}

type sectionSpan struct {
	data []byte
	va   uint64
}

func buildSectionMap(bin gobinary.Binary) []sectionSpan {
	var spans []sectionSpan
	for _, name := range []string{".rodata", ".rdata", ".data", ".noptrdata", "__rodata", "__data", "__noptrdata"} {
		data, err := bin.Section(name)
		if err != nil || len(data) == 0 {
			continue
		}
		va, err := bin.SectionVA(name)
		if err != nil {
			continue
		}
		spans = append(spans, sectionSpan{data: data, va: va})
	}
	return spans
}

func resolveVA(va uint64, spans []sectionSpan) ([]byte, int, bool) {
	for _, sp := range spans {
		if va >= sp.va && va < sp.va+uint64(len(sp.data)) {
			return sp.data, int(va - sp.va), true
		}
	}
	return nil, 0, false
}

func resolveRtypeName(ptr uint64, spans []sectionSpan, order binary.ByteOrder) string {
	for _, sp := range spans {
		if ptr < sp.va || ptr >= sp.va+uint64(len(sp.data)) {
			continue
		}
		off := int(ptr - sp.va)
		rt, err := parseRType(sp.data, off, 8, order, sp.va)
		if err != nil {
			continue
		}
		return rt.Name
	}
	return ""
}
