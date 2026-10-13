//go:build !linux

package auditforward

import (
	"context"
	"net"
	"time"
)

// waitAcknowledged cannot read the receiver's TCP acknowledgement outside
// Linux, so a syslog batch counts as delivered once it is written. The hub is
// deployed on Linux; this keeps the package building elsewhere, and the
// weaker guarantee is documented with the syslog sink.
func waitAcknowledged(ctx context.Context, _ *net.TCPConn, _ time.Time) error {
	return ctx.Err()
}
