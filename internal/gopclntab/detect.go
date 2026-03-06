package gopclntab

import (
	"encoding/binary"
	"fmt"
)

// Magic constants from src/internal/abi/symtab.go in the Go standard library.
const (
	magic12  = 0xFFFFFFFB // Go 1.2–1.15
	magic116 = 0xFFFFFFFA // Go 1.16–1.17
	magic118 = 0xFFFFFFF0 // Go 1.18–1.19
	magic120 = 0xFFFFFFF1 // Go 1.20+
)

// detectVersion reads the 4-byte magic and returns the version and byte order.
func detectVersion(data []byte) (PclntabVersion, binary.ByteOrder, error) {
	if len(data) < 8 {
		return VersionUnknown, nil, fmt.Errorf("data too short")
	}

	le := binary.LittleEndian.Uint32(data[0:4])
	be := binary.BigEndian.Uint32(data[0:4])

	for _, candidate := range []struct {
		val   uint32
		order binary.ByteOrder
	}{
		{le, binary.LittleEndian},
		{be, binary.BigEndian},
	} {
		switch candidate.val {
		case magic12:
			return Version12, candidate.order, nil
		case magic116:
			return Version116, candidate.order, nil
		case magic118:
			return Version118, candidate.order, nil
		case magic120:
			return Version120, candidate.order, nil
		}
	}

	return VersionUnknown, nil, fmt.Errorf("unknown pclntab magic: %08x", le)
}

// readUintPtr reads a pointer-sized integer at offset.
func readUintPtr(data []byte, off int, ptrSize uint8, order binary.ByteOrder) uint64 {
	if ptrSize == 8 {
		if off+8 > len(data) {
			return 0
		}
		return order.Uint64(data[off : off+8])
	}
	if off+4 > len(data) {
		return 0
	}
	return uint64(order.Uint32(data[off : off+4]))
}

func readUint32(data []byte, off int, order binary.ByteOrder) uint32 {
	if off+4 > len(data) {
		return 0
	}
	return order.Uint32(data[off : off+4])
}

func readUint64(data []byte, off int, order binary.ByteOrder) uint64 {
	if off+8 > len(data) {
		return 0
	}
	return order.Uint64(data[off : off+8])
}

func readNullString(data []byte, off int) string {
	if off < 0 || off >= len(data) {
		return ""
	}
	end := off
	for end < len(data) && data[end] != 0 {
		end++
	}
	return string(data[off:end])
}
