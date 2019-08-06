package collector

import (
	"context"

	"github.com/m-lab/tcp-info/netlink"
	"github.com/m-lab/tcp-info/saver"
)

// Run does nothing, but needed for compiling on Darwin.
func Run(ctx context.Context, reps int, svrChan chan<- netlink.MessageBlock, cl saver.CacheLogger, skipLocal bool) (localCount, errCount int) {
	// Does notihg in Darwin
	return 0, 0
}
