//go:build linux

package auditforward

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// tcpEstablished is TCP_ESTABLISHED from include/net/tcp_states.h.
const tcpEstablished = 1

// waitAcknowledged returns once the receiver's TCP stack has acknowledged
// every byte written to tcp — SIOCOUTQ, the bytes in the send queue the peer
// has not acknowledged, is zero — on a connection still ESTABLISHED. A
// receiver that closed the connection, or reset it, fails the wait however
// few bytes are outstanding: a reset purges the send queue, and an empty
// queue on a dead connection would otherwise read as everything delivered.
// SIOCOUTQ rather than TCP_INFO's counters for the bytes, because before
// Linux 4.6 TCP_INFO has no count of bytes held back unsent.
//
// This is the strongest acknowledgement RFC 5425 allows: the protocol has none
// of its own, so a receiver that crashes holding acknowledged bytes loses
// them. The https sink is the one whose acknowledgement comes from the
// collector itself.
func waitAcknowledged(ctx context.Context, tcp *net.TCPConn, deadline time.Time) error {
	if tcp == nil {
		return fmt.Errorf("the connection is not TCP, so its acknowledgement cannot be read")
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return fmt.Errorf("read the connection's TCP state: %w", err)
	}
	delay := 200 * time.Microsecond
	for {
		var (
			info    *unix.TCPInfo
			pending int
			serr    error
		)
		if err := raw.Control(func(fd uintptr) {
			info, serr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
			if serr == nil {
				pending, serr = unix.IoctlGetInt(int(fd), unix.SIOCOUTQ)
			}
		}); err != nil {
			return fmt.Errorf("read the connection's TCP state: %w", err)
		}
		if serr != nil {
			return fmt.Errorf("read the connection's TCP state: %w", serr)
		}
		if info.State != tcpEstablished {
			return fmt.Errorf("the receiver closed the connection before acknowledging the batch (TCP state %d)", info.State)
		}
		if pending == 0 && info.Unacked == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the receiver did not acknowledge the batch in time (%d byte(s) unacknowledged)", pending)
		}
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
		if delay < 20*time.Millisecond {
			delay *= 2
		}
	}
}
