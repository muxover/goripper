package concurrency

// PatternKind describes what kind of concurrency pattern was detected.
type PatternKind string

const (
	PatternGoroutineSpawn PatternKind = "goroutine_spawn"
	PatternChanSend       PatternKind = "chan_send"
	PatternChanRecv       PatternKind = "chan_recv"
	PatternChanMake       PatternKind = "chan_make"
	PatternSelect         PatternKind = "select"
	PatternSyncMutex      PatternKind = "sync_mutex"
	PatternWaitGroup      PatternKind = "waitgroup"
	PatternSyncOnce       PatternKind = "sync_once"
	PatternAtomicOp       PatternKind = "atomic"
)

// ConcurrencyPattern is a detected concurrency usage within a function.
type ConcurrencyPattern struct {
	Kind     PatternKind
	FuncName string // function in which the pattern was detected
	CallSite uint64 // VA of the CALL instruction (0 if unknown)
}
