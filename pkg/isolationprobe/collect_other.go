//go:build !linux

package isolationprobe

import "errors"

// errNotLinux is what every read answers off Linux: the evidence the probe
// collects is Linux's, and a hub on another system has no kernel of that kind
// to describe.
var errNotLinux = errors.New("not a Linux kernel")

// hostSource reads nothing off Linux.
type hostSource struct{}

func (hostSource) uname() (string, string, string, error) { return "", "", "", errNotLinux }
func (hostSource) readFile(string) ([]byte, error)        { return nil, errNotLinux }
func (hostSource) syslog() ([]byte, error)                { return nil, errNotLinux }
