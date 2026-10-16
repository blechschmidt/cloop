//go:build !linux

package denylog

import "errors"

const (
	groupTries = 0
	// EnvBaseGroup overrides the first NFLOG group tried, on Linux.
	EnvBaseGroup = "CLOOP_DENIAL_LOG_GROUP"
)

func baseGroup() uint16 { return 0 }

// openSource has no NFLOG to bind outside Linux, where no sandbox firewall is
// installed either.
func openSource(uint16, int) (source, error) {
	return nil, errors.New("denylog: the packet log is read through NFLOG, which only Linux has")
}
