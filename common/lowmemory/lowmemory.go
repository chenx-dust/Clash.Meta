package lowmemory

import (
	"runtime"
	"runtime/debug"
	"sync/atomic"
)

var enabled atomic.Bool

func init() {
	SetEnabled(defaultEnabled)
}

func Enabled() bool {
	return enabled.Load()
}

func SetEnabled(value bool) {
	enabled.Store(value)
	if value {
		debug.SetGCPercent(20)
		debug.SetMemoryLimit(32 * 1024 * 1024)
	}
}

func GC() {
	if !Enabled() {
		return
	}
	runtime.GC()
	debug.FreeOSMemory()
}
