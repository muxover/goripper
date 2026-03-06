package types

// TypeKind describes what kind of Go type was recovered.
type TypeKind string

const (
	KindStruct    TypeKind = "struct"
	KindInterface TypeKind = "interface"
	KindSlice     TypeKind = "slice"
	KindMap       TypeKind = "map"
	KindPtr       TypeKind = "ptr"
	KindFunc      TypeKind = "func"
	KindBasic     TypeKind = "basic"
	KindArray     TypeKind = "array"
	KindChan      TypeKind = "chan"
)

// FieldDescriptor describes a single field in a struct or interface.
type FieldDescriptor struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Offset uint32 `json:"offset"`
}

// RecoveredType represents a Go type recovered from binary reflection metadata.
type RecoveredType struct {
	Name   string            `json:"name"`
	Kind   TypeKind          `json:"kind"`
	Fields []FieldDescriptor `json:"fields,omitempty"`
	Size   uint32            `json:"size"`
	Addr   uint64            `json:"addr"` // VA of the rtype descriptor
}

// Go reflect kind constants (matches reflect.Kind in the standard library).
const (
	kindInvalid       = 0
	kindBool          = 1
	kindInt           = 2
	kindInt8          = 3
	kindInt16         = 4
	kindInt32         = 5
	kindInt64         = 6
	kindUint          = 7
	kindUint8         = 8
	kindUint16        = 9
	kindUint32        = 10
	kindUint64        = 11
	kindUintptr       = 12
	kindFloat32       = 13
	kindFloat64       = 14
	kindComplex64     = 15
	kindComplex128    = 16
	kindArray         = 17
	kindChan          = 18
	kindFunc          = 19
	kindInterface     = 20
	kindMap           = 21
	kindPointer       = 22
	kindSlice         = 23
	kindString        = 24
	kindStruct        = 25
	kindUnsafePointer = 26
	kindMask          = (1 << 5) - 1
)

func kindFromByte(k uint8) TypeKind {
	switch k & kindMask {
	case kindStruct:
		return KindStruct
	case kindInterface:
		return KindInterface
	case kindSlice:
		return KindSlice
	case kindMap:
		return KindMap
	case kindPointer:
		return KindPtr
	case kindFunc:
		return KindFunc
	case kindArray:
		return KindArray
	case kindChan:
		return KindChan
	default:
		return KindBasic
	}
}
