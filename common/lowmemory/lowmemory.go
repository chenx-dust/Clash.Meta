package lowmemory

import (
	"runtime"
	"runtime/debug"
	"sync/atomic"
)

var enabled atomic.Bool

func Enabled() bool {
	return enabled.Load()
}

func SetEnabled(value bool) {
	enabled.Store(value)
}

func GC() {
	if !Enabled() {
		return
	}
	runtime.GC()
	debug.FreeOSMemory()
}
