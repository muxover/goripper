//go:build windows

package trace

import (
	"fmt"
	"time"
	"unsafe"

	"github.com/muxover/goripper/internal/functions"
	"golang.org/x/sys/windows"
)

type windowsTracer struct{}

func New() Tracer { return &windowsTracer{} }

// Windows Debug API constants not exported by golang.org/x/sys/windows.
const (
	debugProcessFlag   = 0x00000001
	createNewConsole   = 0x00000010
	exceptionBP        = uint32(0x80000003)
	exceptionSS        = uint32(0x80000004)
	dbgContinue        = uint32(0x00010002)
	dbgExcNotHandled   = uint32(0x80010001)
	debugEventException    = uint32(1)
	debugEventCreateProcess = uint32(3)
	debugEventExitProcess  = uint32(5)
	// CONTEXT_FULL for x86-64: architecture flag (0x00100000) | integer (0x2) | control (0x1) | float (0x8)
	contextFull = uint32(0x0010003b)
	trapFlagBit = uint32(0x100)
)

// contextAMD64 must be exactly 1232 bytes and 16-byte aligned to match the
// Windows CONTEXT structure for AMD64 (winnt.h).  We only read/write
// ContextFlags (offset 48) and EFlags (offset 72); everything else is padding.
//
// Layout verified against winnt.h (CONTEXT for AMD64):
//   offset   0: P1Home–P6Home           6×8 =  48
//   offset  48: ContextFlags+MxCsr      2×4 =   8
//   offset  56: SegCs–SegSs             6×2 =  12
//   offset  68: EFlags                      =   4
//   offset  72: Dr0–Dr3, Dr6, Dr7       6×8 =  48
//   offset 120: Rax–Rip                17×8 = 136
//   offset 256: FltSave (XSAVE_FORMAT)      = 512
//   offset 768: VectorRegister         26×16= 416
//   offset 1184: VectorControl+DebugControl = 16
//   offset 1200: LastBranch*            4×8 =  32
//   total: 1232
type contextAMD64 struct {
	P1Home   uint64
	P2Home   uint64
	P3Home   uint64
	P4Home   uint64
	P5Home   uint64
	P6Home   uint64
	// offset 48
	ContextFlags uint32
	MxCsr        uint32
	// offset 56
	SegCs  uint16
	SegDs  uint16
	SegEs  uint16
	SegFs  uint16
	SegGs  uint16
	SegSs  uint16
	EFlags uint32
	// offset 72 — debug registers
	Dr0 uint64
	Dr1 uint64
	Dr2 uint64
	Dr3 uint64
	Dr6 uint64
	Dr7 uint64
	// offset 120 — integer registers
	Rax uint64
	Rcx uint64
	Rdx uint64
	Rbx uint64
	Rsp uint64
	Rbp uint64
	Rsi uint64
	Rdi uint64
	R8  uint64
	R9  uint64
	R10 uint64
	R11 uint64
	R12 uint64
	R13 uint64
	R14 uint64
	R15 uint64
	Rip uint64
	// offset 256 — FltSave (XSAVE_FORMAT, 512 bytes)
	_flt [64]uint64
	// offset 768 — VectorRegister (26 × M128A = 416 bytes)
	_vec [52]uint64
	// offset 1184 — VectorControl(8) + DebugControl(8) + LastBranch×4(32) = 48
	_tail [6]uint64
}

// Total size: 4+4+4+4 + 160 = 176 bytes, union is the largest member (EXCEPTION_DEBUG_INFO = 160).
type debugEvent struct {
	DebugEventCode uint32
	ProcessId      uint32
	ThreadId       uint32
	_              uint32
	U              [160]byte
}

func exceptionCode(ev *debugEvent) uint32 {
	return *(*uint32)(unsafe.Pointer(&ev.U[0]))
}

// ExceptionAddress is at offset 16 in EXCEPTION_RECORD on AMD64 (after Code, Flags, NextRecord*).
func exceptionAddress(ev *debugEvent) uint64 {
	return *(*uint64)(unsafe.Pointer(&ev.U[16]))
}

// createProcessBaseOfImage returns the actual load address of the image from a
// CREATE_PROCESS_DEBUG_EVENT.  In CREATE_PROCESS_DEBUG_INFO, lpBaseOfImage is at
// byte offset 24 (after three 8-byte HANDLEs).
func createProcessBaseOfImage(ev *debugEvent) uint64 {
	return *(*uint64)(unsafe.Pointer(&ev.U[24]))
}

var (
	modKernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	procWaitForDebugEvent        = modKernel32.NewProc("WaitForDebugEvent")
	procContinueDebugEvent       = modKernel32.NewProc("ContinueDebugEvent")
	procGetThreadContext          = modKernel32.NewProc("GetThreadContext")
	procSetThreadContext          = modKernel32.NewProc("SetThreadContext")
	procOpenThread                = modKernel32.NewProc("OpenThread")
	procFlushInstructionCache     = modKernel32.NewProc("FlushInstructionCache")
)

func (t *windowsTracer) Trace(binaryPath string, args []string, funcs []functions.Function, opts Options, out chan<- Event) error {
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	cmdLine := binaryPath
	for _, a := range args {
		cmdLine += " " + a
	}
	cmdLinePtr, err := windows.UTF16PtrFromString(cmdLine)
	if err != nil {
		return fmt.Errorf("encode command line: %w", err)
	}
	exePath, err := windows.UTF16PtrFromString(binaryPath)
	if err != nil {
		return fmt.Errorf("encode exe path: %w", err)
	}

	var si windows.StartupInfo
	var pi windows.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))

	if err := windows.CreateProcess(
		exePath, cmdLinePtr,
		nil, nil, false,
		debugProcessFlag|createNewConsole,
		nil, nil,
		&si, &pi,
	); err != nil {
		return fmt.Errorf("CreateProcess: %w", err)
	}
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)

	type bpInfo struct {
		name     string
		origByte byte
		set      bool
	}
	// Static map from preferred-VA to bpInfo; will be remapped after we learn the
	// actual load address from the CREATE_PROCESS event (ASLR adjustment).
	staticAddrToFunc := make(map[uint64]*bpInfo, len(funcs))
	for i := range funcs {
		fn := &funcs[i]
		if fn.PackageKind != functions.PackageUser {
			continue
		}
		staticAddrToFunc[fn.Addr] = &bpInfo{name: fn.Name}
	}
	// runtimeAddrToFunc is populated after ASLR slide is computed.
	var addrToFunc map[uint64]*bpInfo

	// pendingSingleStep: threadHandle → bp address we temporarily removed.
	pendingSingleStep := make(map[windows.Handle]uint64)

	count := 0
	deadline := time.Now().Add(timeout)
	proc := pi.Process

	writeMemByte := func(addr uint64, b byte) error {
		buf := []byte{b}
		var written uintptr
		return windows.WriteProcessMemory(proc, uintptr(addr), &buf[0], 1, &written)
	}
	readMemByte := func(addr uint64) (byte, error) {
		var buf [1]byte
		var read uintptr
		err := windows.ReadProcessMemory(proc, uintptr(addr), &buf[0], 1, &read)
		return buf[0], err
	}

	setBreakpoint := func(info *bpInfo, addr uint64) {
		if info.set {
			return
		}
		orig, err := readMemByte(addr)
		if err != nil {
			return
		}
		if writeMemByte(addr, 0xCC) != nil {
			return
		}
		// Flush the CPU instruction cache so the patched byte takes effect.
		procFlushInstructionCache.Call(uintptr(proc), uintptr(addr), 1)
		info.origByte = orig
		info.set = true
	}

	waitForDebugEvent := func() (*debugEvent, error) {
		var ev debugEvent
		// WaitForDebugEvent(LPDEBUG_EVENT, DWORD) — two args only; no process handle.
		r1, _, lastErr := procWaitForDebugEvent.Call(
			uintptr(unsafe.Pointer(&ev)),
			1000, // millisecond timeout so we can check the deadline
		)
		if r1 == 0 {
			if lastErr == windows.ERROR_SEM_TIMEOUT {
				return nil, nil
			}
			return nil, lastErr
		}
		return &ev, nil
	}

	continueDebug := func(pid, tid, status uint32) {
		procContinueDebugEvent.Call(uintptr(pid), uintptr(tid), uintptr(status))
	}

loop:
	for {
		if time.Now().After(deadline) || (opts.MaxEvents > 0 && count >= opts.MaxEvents) {
			windows.TerminateProcess(proc, 0)
			break
		}

		ev, err := waitForDebugEvent()
		if err != nil {
			break
		}
		if ev == nil {
			continue
		}

		switch ev.DebugEventCode {
		case debugEventCreateProcess:
			if addrToFunc != nil {
				// Already processed this event (DEBUG_PROCESS causes one event per
				// child process; only handle the first — our main process).
				continueDebug(ev.ProcessId, ev.ThreadId, dbgContinue)
				break
			}
			// Compute ASLR slide: actual load address minus preferred image base.
			actualBase := createProcessBaseOfImage(ev)
			var slide int64
			if opts.PreferredBase != 0 && actualBase != 0 {
				slide = int64(actualBase) - int64(opts.PreferredBase)
			}
			// Build runtime address map with ASLR-adjusted addresses.
			addrToFunc = make(map[uint64]*bpInfo, len(staticAddrToFunc))
			for staticAddr, info := range staticAddrToFunc {
				runtimeAddr := uint64(int64(staticAddr) + slide)
				addrToFunc[runtimeAddr] = info
			}
			for addr, info := range addrToFunc {
				setBreakpoint(info, addr)
			}
			continueDebug(ev.ProcessId, ev.ThreadId, dbgContinue)

		case debugEventExitProcess:
			continueDebug(ev.ProcessId, ev.ThreadId, dbgContinue)
			break loop

		case debugEventException:
			code := exceptionCode(ev)
			addr := exceptionAddress(ev)
			if addrToFunc == nil {
				continueDebug(ev.ProcessId, ev.ThreadId, dbgContinue)
				break
			}

			switch code {
			case exceptionBP:
				if info, ok := addrToFunc[addr]; ok && info.set {
					tsNs := time.Now().UnixNano()
					out <- Event{
						Type: EventCall,
						Func: info.name,
						Addr: fmt.Sprintf("0x%x", addr),
						TsNs: tsNs,
					}
					count++

					writeMemByte(addr, info.origByte)
					procFlushInstructionCache.Call(uintptr(proc), uintptr(addr), 1)
					info.set = false

					// Open the thread to set the trap flag for single-stepping.
					// The CONTEXT buffer must be 16-byte aligned; heap-allocate with
					// padding to guarantee alignment regardless of stack layout.
					threadAccess := uint32(windows.THREAD_GET_CONTEXT | windows.THREAD_SET_CONTEXT)
					th, _, _ := procOpenThread.Call(uintptr(threadAccess), 0, uintptr(ev.ThreadId))
					if th != 0 {
						const ctxSize = unsafe.Sizeof(contextAMD64{})
						buf := make([]byte, ctxSize+16)
						// Align buf to 16-byte boundary.
						offset := uintptr(unsafe.Pointer(&buf[0])) & 15
						if offset != 0 {
							buf = buf[16-offset:]
						}
						ctx := (*contextAMD64)(unsafe.Pointer(&buf[0]))
						ctx.ContextFlags = contextFull
						r1, _, _ := procGetThreadContext.Call(th, uintptr(unsafe.Pointer(ctx)))
						if r1 != 0 {
							ctx.EFlags |= trapFlagBit
							procSetThreadContext.Call(th, uintptr(unsafe.Pointer(ctx)))
						}
						pendingSingleStep[windows.Handle(th)] = addr
					}
					continueDebug(ev.ProcessId, ev.ThreadId, dbgContinue)

				} else {
					// Initial system breakpoint or unknown — pass through.
					continueDebug(ev.ProcessId, ev.ThreadId, dbgContinue)
				}

			case exceptionSS:
				// Re-set the breakpoint we temporarily removed.
				for th, bpAddr := range pendingSingleStep {
					if info, ok := addrToFunc[bpAddr]; ok {
						setBreakpoint(info, bpAddr)
					}
					windows.CloseHandle(th)
					delete(pendingSingleStep, th)
					break // only one pending per event
				}
				continueDebug(ev.ProcessId, ev.ThreadId, dbgContinue)

			default:
				continueDebug(ev.ProcessId, ev.ThreadId, dbgExcNotHandled)
			}

		default:
			continueDebug(ev.ProcessId, ev.ThreadId, dbgContinue)
		}
	}

	for th := range pendingSingleStep {
		windows.CloseHandle(th)
	}
	return nil
}
