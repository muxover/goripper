package constants

import (
	"github.com/muxover/goripper/internal/functions"
	"golang.org/x/arch/x86/x86asm"
)

var knownPorts = map[int64]struct{}{
	21: {}, 22: {}, 23: {}, 25: {}, 53: {}, 80: {}, 110: {}, 143: {},
	443: {}, 445: {}, 993: {}, 995: {}, 1433: {}, 1080: {}, 3306: {},
	4444: {}, 5432: {}, 6379: {}, 8080: {}, 8443: {}, 27017: {}, 31337: {},
}

var magicNumbers = map[int64]struct{}{
	0x5A4D:       {}, // PE MZ header
	0x4D5A:       {}, // PE MZ header (reversed)
	0x7F454C46:   {}, // ELF magic
	0x504B0304:   {}, // ZIP PK
	0xCAFEBABE:   {}, // Mach-O fat / Java class
	0xFEEDFACE:   {}, // Mach-O 32-bit
	0xFEEDFACF:   {}, // Mach-O 64-bit
	0x89504E47:   {}, // PNG
	0xFFD8FFE0:   {}, // JPEG
	0x25504446:   {}, // PDF (%PDF)
	0xD0CF11E0:   {}, // OLE2 (Office)
	0x526172211B: {}, // RAR
}

// AES/SHA key and block sizes near crypto calls
var cryptoKeySizes = map[int64]struct{}{
	16: {}, 24: {}, 32: {}, 48: {}, 64: {},
}

// Only runs on x86_64; ARM64 is skipped (immediates harder to distinguish from arithmetic).
func Extract(fn functions.Function, textData []byte, textVA uint64) []functions.ConstantInfo {
	if fn.Addr < textVA || fn.Size == 0 {
		return nil
	}
	off := fn.Addr - textVA
	if off >= uint64(len(textData)) {
		return nil
	}
	end := off + fn.Size
	if end > uint64(len(textData)) {
		end = uint64(len(textData))
	}

	isCrypto := false
	for _, tag := range fn.Tags {
		if tag == "CRYPTO" {
			isCrypto = true
			break
		}
	}

	data := textData[off:end]
	seen := make(map[int64]bool)
	var result []functions.ConstantInfo

	pos := 0
	for pos < len(data) {
		inst, err := x86asm.Decode(data[pos:], 64)
		if err != nil {
			pos++
			continue
		}
		for _, arg := range inst.Args {
			if arg == nil {
				continue
			}
			imm, ok := arg.(x86asm.Imm)
			if !ok {
				continue
			}
			v := int64(imm)
			if v <= 0 || seen[v] {
				continue
			}
			if ci := classify(v, isCrypto); ci != nil {
				seen[v] = true
				result = append(result, *ci)
			}
		}
		pos += inst.Len
	}
	return result
}

func classify(v int64, isCrypto bool) *functions.ConstantInfo {
	if _, ok := magicNumbers[v]; ok {
		return &functions.ConstantInfo{Value: v, Category: "magic", Confidence: "high"}
	}
	if v >= 1 && v <= 65535 {
		if _, ok := knownPorts[v]; ok {
			return &functions.ConstantInfo{Value: v, Category: "port", Confidence: "high"}
		}
	}
	if isCrypto {
		if _, ok := cryptoKeySizes[v]; ok {
			return &functions.ConstantInfo{Value: v, Category: "crypto_key_size", Confidence: "medium"}
		}
	}
	return nil
}
