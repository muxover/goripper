package disasm_test

import (
	"testing"

	"github.com/muxover/goripper/internal/disasm"
)

func TestNew_DefaultsToX86(t *testing.T) {
	d := disasm.New("unknown_arch")
	if d.Arch() != "x86_64" {
		t.Errorf("Arch() = %q, want x86_64", d.Arch())
	}
}

func TestNew_ARM64(t *testing.T) {
	d := disasm.New("arm64")
	if d.Arch() != "arm64" {
		t.Errorf("Arch() = %q, want arm64", d.Arch())
	}
	d2 := disasm.New("aarch64")
	if d2.Arch() != "arm64" {
		t.Errorf("Arch() for aarch64 = %q, want arm64", d2.Arch())
	}
}

// --- x86_64 decoder tests ---

func TestX86_Call_Direct(t *testing.T) {
	// CALL rel32 0 → target = va + 5 + 0 = 0x1000 + 5
	data := []byte{0xE8, 0x00, 0x00, 0x00, 0x00}
	d := disasm.New("x86_64")
	instr, err := d.Decode(data, 0x1000)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if instr.Op != disasm.OpCall {
		t.Errorf("Op = %d, want OpCall", instr.Op)
	}
	if instr.Target != 0x1005 {
		t.Errorf("Target = %#x, want 0x1005", instr.Target)
	}
	if instr.Indirect {
		t.Error("Indirect should be false for direct CALL")
	}
}

func TestX86_Call_Indirect(t *testing.T) {
	// CALL [RBX] = FF 13
	data := []byte{0xFF, 0x13}
	d := disasm.New("x86_64")
	instr, err := d.Decode(data, 0x2000)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if instr.Op != disasm.OpCall {
		t.Errorf("Op = %d, want OpCall", instr.Op)
	}
	if !instr.Indirect {
		t.Error("Indirect should be true for CALL [mem]")
	}
}

func TestX86_Ret(t *testing.T) {
	// RET = C3
	d := disasm.New("x86_64")
	instr, err := d.Decode([]byte{0xC3}, 0x3000)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if instr.Op != disasm.OpRet {
		t.Errorf("Op = %d, want OpRet", instr.Op)
	}
}

func TestX86_CondBranch_JNE(t *testing.T) {
	// JNE rel8 +5 → target = va + 2 + 5 = 0x1007
	data := []byte{0x75, 0x05}
	d := disasm.New("x86_64")
	instr, err := d.Decode(data, 0x1000)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if instr.Op != disasm.OpCondBranch {
		t.Errorf("Op = %d, want OpCondBranch", instr.Op)
	}
	if instr.Target != 0x1007 {
		t.Errorf("Target = %#x, want 0x1007", instr.Target)
	}
}

func TestX86_UncondBranch_JMP(t *testing.T) {
	// JMP rel8 +10 → target = va + 2 + 10 = 0x100C
	data := []byte{0xEB, 0x0A}
	d := disasm.New("x86_64")
	instr, err := d.Decode(data, 0x1000)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if instr.Op != disasm.OpUncondBranch {
		t.Errorf("Op = %d, want OpUncondBranch", instr.Op)
	}
	if instr.Target != 0x100C {
		t.Errorf("Target = %#x, want 0x100C", instr.Target)
	}
}

func TestX86_LEA_RIP(t *testing.T) {
	// LEA RAX, [RIP + 0x10] = 48 8D 05 10 00 00 00
	// AddrRef = va + 7 + 0x10 = 0x1000 + 7 + 16 = 0x1017
	data := []byte{0x48, 0x8D, 0x05, 0x10, 0x00, 0x00, 0x00}
	d := disasm.New("x86_64")
	instr, err := d.Decode(data, 0x1000)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if instr.Op != disasm.OpAddrLoad {
		t.Errorf("Op = %d, want OpAddrLoad", instr.Op)
	}
	if instr.AddrRef != 0x1017 {
		t.Errorf("AddrRef = %#x, want 0x1017", instr.AddrRef)
	}
}

func TestX86_Other_NOP(t *testing.T) {
	// NOP = 90
	d := disasm.New("x86_64")
	instr, err := d.Decode([]byte{0x90}, 0x1000)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if instr.Op != disasm.OpOther {
		t.Errorf("NOP Op = %d, want OpOther", instr.Op)
	}
	if instr.Len != 1 {
		t.Errorf("NOP Len = %d, want 1", instr.Len)
	}
}

func TestX86_EmptyData_Error(t *testing.T) {
	d := disasm.New("x86_64")
	_, err := d.Decode([]byte{}, 0x1000)
	if err == nil {
		t.Error("expected error decoding empty data")
	}
}

// --- ARM64 decoder tests ---

func TestARM64_BL(t *testing.T) {
	// BL #0 encodes as 0x94000000 (offset 0 → target = va)
	// BL #+4 = branch to next word: 0x94000001
	data := []byte{0x01, 0x00, 0x00, 0x94} // little-endian BL #+4
	d := disasm.New("arm64")
	instr, err := d.Decode(data, 0x1000)
	if err != nil {
		t.Fatalf("Decode BL: %v", err)
	}
	if instr.Op != disasm.OpCall {
		t.Errorf("BL Op = %d, want OpCall", instr.Op)
	}
	if instr.Indirect {
		t.Error("BL should not be indirect")
	}
	if instr.Len != 4 {
		t.Errorf("BL Len = %d, want 4", instr.Len)
	}
}

func TestARM64_RET(t *testing.T) {
	// RET = 0xD65F03C0
	data := []byte{0xC0, 0x03, 0x5F, 0xD6}
	d := disasm.New("arm64")
	instr, err := d.Decode(data, 0x2000)
	if err != nil {
		t.Fatalf("Decode RET: %v", err)
	}
	if instr.Op != disasm.OpRet {
		t.Errorf("RET Op = %d, want OpRet", instr.Op)
	}
}

func TestARM64_BLR(t *testing.T) {
	// BLR X0 = 0xD63F0000
	data := []byte{0x00, 0x00, 0x3F, 0xD6}
	d := disasm.New("arm64")
	instr, err := d.Decode(data, 0x3000)
	if err != nil {
		t.Fatalf("Decode BLR: %v", err)
	}
	if instr.Op != disasm.OpCall {
		t.Errorf("BLR Op = %d, want OpCall", instr.Op)
	}
	if !instr.Indirect {
		t.Error("BLR should be indirect")
	}
}

func TestARM64_TooShort_Error(t *testing.T) {
	d := disasm.New("arm64")
	_, err := d.Decode([]byte{0x00, 0x01}, 0x1000)
	if err == nil {
		t.Error("expected error for < 4 bytes")
	}
}
