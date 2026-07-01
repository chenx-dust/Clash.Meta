package executor

import "github.com/metacubex/mihomo/common/lowmemory"

func getConcurrentCount() int {
	if lowmemory.Enabled() {
		return 5
	}
	return concurrentCount
}
