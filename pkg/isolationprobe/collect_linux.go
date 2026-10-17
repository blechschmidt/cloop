//go:build linux

package isolationprobe

import "golang.org/x/sys/unix"

// hostSource reads the running kernel.
type hostSource struct{}

func (hostSource) uname() (release, version, machine string, err error) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "", "", "", err
	}
	return unix.ByteSliceToString(u.Release[:]), unix.ByteSliceToString(u.Version[:]),
		unix.ByteSliceToString(u.Machine[:]), nil
}

func (hostSource) readFile(path string) ([]byte, error) { return readBounded(path) }

// syslog reads the kernel's log buffer. On Linux this needs CAP_SYSLOG under
// kernel.dmesg_restrict, which no sandbox the probe runs in has; gVisor's
// Sentry answers anyone with the boot log it synthesised.
func (hostSource) syslog() ([]byte, error) {
	buf := make([]byte, 16<<10)
	n, err := unix.Klogctl(unix.SYSLOG_ACTION_READ_ALL, buf)
	if err != nil {
		return nil, err
	}
	if n < 0 || n > len(buf) {
		n = 0
	}
	return buf[:n], nil
}
