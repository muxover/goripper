package entropy

import "math"

type SectionInfo struct {
	Name    string  `json:"name"`
	Entropy float64 `json:"entropy"`
	Size    uint64  `json:"size"`
	Verdict string  `json:"verdict"` // "normal", "compressed", "encrypted", "packed"
}

func Calculate(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]int
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	var h float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func Verdict(e float64) string {
	switch {
	case e < 1.0:
		return "packed"
	case e <= 6.5:
		return "normal"
	case e <= 7.2:
		return "compressed"
	default:
		return "encrypted"
	}
}

var packerSignatures = map[string]string{
	"UPX0":    "UPX",
	"UPX1":    "UPX",
	"UPX2":    "UPX",
	"MPRESS1": "MPRESS",
	"MPRESS2": "MPRESS",
	".packed":  "unknown_packer",
	".themida": "unknown_packer",
}

func DetectPacker(sectionNames []string) string {
	for _, name := range sectionNames {
		if p, ok := packerSignatures[name]; ok {
			return p
		}
	}
	return ""
}
