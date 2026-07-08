package pipeline

import (
	"fmt"

	gobinary "github.com/muxover/goripper/internal/binary"
	"github.com/muxover/goripper/internal/cfg"
	"github.com/muxover/goripper/internal/disasm"
	"github.com/muxover/goripper/internal/functions"
	"github.com/muxover/goripper/internal/gopclntab"
	"github.com/muxover/goripper/internal/ir"
)

// LiftBinary lifts every user-defined function in a Go binary to IR.
// maxFuncs caps the count (0 = all). Functions that cannot be CFG-built yield a
// single-comment stub so the result stays 1:1 with the user function list.
func LiftBinary(binaryPath string, maxFuncs int) ([]*ir.IRFunc, error) {
	bin, err := gobinary.Open(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("open binary: %w", err)
	}
	defer bin.Close()

	arch := bin.Arch()
	d := disasm.New(arch)

	pclntabData, _, err := bin.FindGopclntab()
	if err != nil {
		return nil, fmt.Errorf("find pclntab: %w", err)
	}
	parsed, err := gopclntab.Parse(pclntabData, bin.ImageBase())
	if err != nil {
		return nil, fmt.Errorf("parse pclntab: %w", err)
	}

	allFuncs := functions.Classify(functions.Extract(parsed.Funcs))

	var userFuncs []functions.Function
	for _, fn := range allFuncs {
		if fn.PackageKind == functions.PackageUser {
			userFuncs = append(userFuncs, fn)
		}
	}
	if maxFuncs > 0 && len(userFuncs) > maxFuncs {
		userFuncs = userFuncs[:maxFuncs]
	}

	textData, err := bin.Section(".text")
	if err != nil {
		return nil, fmt.Errorf("read .text section: %w", err)
	}
	textVA, err := bin.SectionVA(".text")
	if err != nil {
		return nil, fmt.Errorf("get .text VA: %w", err)
	}

	addrToName := make(map[uint64]string, len(allFuncs))
	for _, fn := range allFuncs {
		addrToName[fn.Addr] = fn.Name
	}

	irFuncs := make([]*ir.IRFunc, 0, len(userFuncs))
	for _, fn := range userFuncs {
		c, cfgErr := cfg.Build(fn, textData, textVA, d)
		if cfgErr != nil || c == nil || len(c.Blocks) == 0 {
			irFuncs = append(irFuncs, liftStub(fn, cfgErr))
			continue
		}
		f := ir.LiftArch(fn, c, textData, textVA, addrToName, arch)
		ir.FilterBoilerplate(f)
		ir.ReconstructFrame(f)
		ir.RenameVars(f)
		ir.RecoverVars(f)
		ir.PropTypes(f, nil)
		irFuncs = append(irFuncs, f)
	}
	return irFuncs, nil
}

func liftStub(fn functions.Function, cfgErr error) *ir.IRFunc {
	return &ir.IRFunc{
		Name:    fn.Name,
		Package: fn.Package,
		Addr:    fn.Addr,
		Vars:    map[string]string{},
		Blocks: []*ir.IRBlock{{
			Label:  "L0",
			Instrs: []ir.IRInstr{{Op: ir.OpComment, Meta: fmt.Sprintf("could not lift: %v", cfgErr)}},
		}},
	}
}
