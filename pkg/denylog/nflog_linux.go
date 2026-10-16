//go:build linux

package denylog

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// nflog_linux.go binds an NFLOG group with a NETLINK_NETFILTER socket — the
// protocol libnetfilter_log speaks, in a hundred lines rather than a cgo
// dependency.
//
// The socket is opened in this process, never in a child, because binding a
// group needs CAP_NET_ADMIN and an executor agent holds that capability only
// for itself (pkg/caps): nothing it starts inherits it, so a helper process
// could not do this, and the agent needs nothing beyond what --packet-filter
// already grants — the capability and AF_NETLINK. The socket is close-on-exec,
// so no workload the process starts afterwards inherits it either.

// netlink and nfnetlink_log configuration constants (linux/netlink.h,
// linux/netfilter/nfnetlink_log.h).
const (
	nlmFRequest = 0x1
	nlmFAck     = 0x4

	nfulaCfgCmd     = 1
	nfulaCfgMode    = 2
	nfulaCfgTimeout = 4
	nfulaCfgQthresh = 5

	nfulnlCfgCmdBind = 1
	nfulnlCopyPacket = 2

	// copyRange matches the rules' snaplen: the kernel copies the smaller of
	// the two, and asking for no more than the rules allow keeps this end
	// honest about what it can see.
	copyRange = 80
	// flushTimeout is how long, in hundredths of a second, the kernel holds
	// log lines to batch them. A fifth of a second keeps a refusal's journey
	// to the dashboard short and the wakeups few.
	flushTimeout = 20
	// queueThreshold flushes a batch early once this many lines are queued.
	queueThreshold = 32
	// rcvBuf is the socket's receive buffer. A burst past it is an overrun:
	// the kernel discards lines, the reader counts it, nothing blocks.
	rcvBuf = 1 << 20
)

// Group selection. A group is one socket's: a second process binding the same
// number gets EBUSY. So the base is configurable for a host that already uses
// NFLOG, and each process takes the first free group of a small range — an
// agent and a hub, or two agents, on one host each get their own.
const (
	defaultBaseGroup = 27437
	groupTries       = 32
	// EnvBaseGroup overrides the first group tried.
	EnvBaseGroup = "CLOOP_DENIAL_LOG_GROUP"
)

func baseGroup() uint16 {
	if v := strings.TrimSpace(os.Getenv(EnvBaseGroup)); v != "" {
		if n, err := strconv.ParseUint(v, 10, 16); err == nil && n+groupTries <= 65535 {
			return uint16(n)
		}
	}
	return defaultBaseGroup
}

type nflogSource struct {
	fd  int
	grp uint16
	seq uint32
}

// openSource binds the first free group in [base, base+tries).
func openSource(base uint16, tries int) (source, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		if errors.Is(err, unix.EAFNOSUPPORT) {
			return nil, fmt.Errorf("denylog: this process may not open a netlink socket (its service allows "+
				"no AF_NETLINK), so it cannot read the packet log: %w", err)
		}
		return nil, fmt.Errorf("denylog: open a netfilter netlink socket: %w", err)
	}
	s := &nflogSource{fd: fd}
	ok := false
	defer func() {
		if !ok {
			unix.Close(fd)
		}
	}()
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("denylog: bind the netlink socket: %w", err)
	}
	// Best effort: the default is enough for the rates the rules allow.
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, rcvBuf)
	// A receive timeout is how a blocked read notices the monitor closing.
	tv := unix.NsecToTimeval(int64(500 * time.Millisecond))
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return nil, fmt.Errorf("denylog: set the socket's receive timeout: %w", err)
	}

	var lastErr error
	for i := 0; i < tries; i++ {
		g := base + uint16(i)
		err := s.config(g, attr(nfulaCfgCmd, []byte{nfulnlCfgCmdBind}))
		if err == nil {
			s.grp = g
			break
		}
		lastErr = err
		if errors.Is(err, unix.EBUSY) {
			continue // another socket's; try the next
		}
		if errors.Is(err, unix.EPERM) {
			return nil, fmt.Errorf("denylog: binding NFLOG group %d needs CAP_NET_ADMIN, which this process "+
				"(uid %d) does not hold — the same capability installing its firewall needs: %w",
				g, os.Geteuid(), err)
		}
		return nil, fmt.Errorf("denylog: bind NFLOG group %d: %w", g, err)
	}
	if s.grp == 0 && lastErr != nil {
		return nil, fmt.Errorf("denylog: NFLOG groups %d to %d are all held by other processes; set %s "+
			"to a free range: %w", base, base+uint16(tries)-1, EnvBaseGroup, lastErr)
	}

	mode := make([]byte, 6)
	binary.BigEndian.PutUint32(mode[0:4], copyRange)
	mode[4] = nfulnlCopyPacket
	timeout := binary.BigEndian.AppendUint32(nil, flushTimeout)
	qthresh := binary.BigEndian.AppendUint32(nil, queueThreshold)
	for _, a := range [][]byte{attr(nfulaCfgMode, mode), attr(nfulaCfgTimeout, timeout), attr(nfulaCfgQthresh, qthresh)} {
		if err := s.config(s.grp, a); err != nil {
			return nil, fmt.Errorf("denylog: configure NFLOG group %d: %w", s.grp, err)
		}
	}
	ok = true
	return s, nil
}

// attr encodes one netlink attribute, padded.
func attr(typ uint16, v []byte) []byte {
	n := nlaHdrLen + len(v)
	b := make([]byte, align4(n))
	binary.NativeEndian.PutUint16(b[0:2], uint16(n))
	binary.NativeEndian.PutUint16(b[2:4], typ)
	copy(b[nlaHdrLen:], v)
	return b
}

// config sends one NFULNL_MSG_CONFIG for group with an ack requested, and
// waits for the ack.
func (s *nflogSource) config(group uint16, attrs ...[]byte) error {
	seq := atomic.AddUint32(&s.seq, 1)
	body := []byte{unix.AF_UNSPEC, 0, byte(group >> 8), byte(group)} // nfgenmsg, res_id big-endian
	for _, a := range attrs {
		body = append(body, a...)
	}
	msg := make([]byte, nlmsgHdrLen, nlmsgHdrLen+len(body))
	binary.NativeEndian.PutUint32(msg[0:4], uint32(nlmsgHdrLen+len(body)))
	binary.NativeEndian.PutUint16(msg[4:6], nfnlSubsysLog<<8|nfulnlMsgConfig)
	binary.NativeEndian.PutUint16(msg[6:8], nlmFRequest|nlmFAck)
	binary.NativeEndian.PutUint32(msg[8:12], seq)
	msg = append(msg, body...)
	if err := unix.Sendto(s.fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	buf := make([]byte, 8192)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		n, _, err := unix.Recvfrom(s.fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		if code, found := ackFor(buf[:n], seq); found {
			if code == 0 {
				return nil
			}
			return unix.Errno(-code)
		}
	}
	return errors.New("no answer from the kernel")
}

// ackFor finds the NLMSG_ERROR answering seq: its error code, 0 for success.
func ackFor(buf []byte, seq uint32) (int32, bool) {
	for len(buf) >= nlmsgHdrLen {
		n := int(binary.NativeEndian.Uint32(buf[0:4]))
		if n < nlmsgHdrLen || n > len(buf) {
			return 0, false
		}
		if binary.NativeEndian.Uint16(buf[4:6]) == nlmsgError && binary.NativeEndian.Uint32(buf[8:12]) == seq &&
			n >= nlmsgHdrLen+4 {
			return int32(binary.NativeEndian.Uint32(buf[nlmsgHdrLen : nlmsgHdrLen+4])), true
		}
		if align4(n) > len(buf) {
			return 0, false
		}
		buf = buf[align4(n):]
	}
	return 0, false
}

func (s *nflogSource) read(buf []byte) (int, error) {
	n, _, err := unix.Recvfrom(s.fd, buf, 0)
	switch {
	case err == nil:
		return n, nil
	case errors.Is(err, unix.EAGAIN), errors.Is(err, unix.EINTR):
		return 0, errRetry
	case errors.Is(err, unix.ENOBUFS):
		return 0, errOverrun
	}
	return 0, err
}

func (s *nflogSource) group() uint16 { return s.grp }

// close releases the socket; the kernel unbinds the group with it.
func (s *nflogSource) close() error { return unix.Close(s.fd) }
