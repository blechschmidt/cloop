package wizard

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

const ioctlGetTermios = syscall.TIOCGETA
const ioctlSetTermios = syscall.TIOCSETA

// IsTTY reports whether stdin is an interactive terminal.
func IsTTY() bool {
	var t syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(syscall.Stdin), ioctlGetTermios, uintptr(unsafe.Pointer(&t)))
	return errno == 0
}

func getTermios(fd int) (*syscall.Termios, error) {
	var t syscall.Termios
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), ioctlGetTermios, uintptr(unsafe.Pointer(&t))); errno != 0 {
		return nil, errno
	}
	return &t, nil
}

func setTermios(fd int, t *syscall.Termios) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), ioctlSetTermios, uintptr(unsafe.Pointer(t)))
	if errno != 0 {
		return errno
	}
	return nil
}

// readMasked reads a line from stdin with echo disabled.
func readMasked(scanner *bufio.Scanner) string {
	fd := int(os.Stdin.Fd())
	old, err := getTermios(fd)
	if err == nil {
		noEcho := *old
		noEcho.Lflag &^= syscall.ECHO
		_ = setTermios(fd, &noEcho)
		defer func() {
			_ = setTermios(fd, old)
			fmt.Println()
		}()
	}
	if scanner.Scan() {
		return strings.TrimSpace(scanner.Text())
	}
	return ""
}
