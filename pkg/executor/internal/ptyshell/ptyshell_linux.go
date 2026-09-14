//go:build linux

package ptyshell

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

const supported = true

// open allocates a pty pair the way Linux wants it: open the multiplexer, ask
// which slave it minted, unlock that slave, then open it by name.
//
// TIOCSPTLCK must come before opening the slave. A slave opened while still
// locked fails with EIO, and the failure looks like a missing /dev/pts mount
// rather than a missing ioctl, which is a long afternoon.
func open() (master, slave *os.File, err error) {
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("ptyshell: open /dev/ptmx: %w", err)
	}
	n, err := unix.IoctlGetInt(int(m.Fd()), unix.TIOCGPTN)
	if err != nil {
		_ = m.Close()
		return nil, nil, fmt.Errorf("ptyshell: get pty number: %w", err)
	}
	if err := unix.IoctlSetPointerInt(int(m.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		_ = m.Close()
		return nil, nil, fmt.Errorf("ptyshell: unlock pty: %w", err)
	}
	name := fmt.Sprintf("/dev/pts/%d", n)
	s, err := os.OpenFile(name, os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		_ = m.Close()
		return nil, nil, fmt.Errorf("ptyshell: open %s: %w", name, err)
	}
	return m, s, nil
}

func resize(master *os.File, rows, cols uint16) error {
	ws := &unix.Winsize{Row: rows, Col: cols}
	if err := unix.IoctlSetWinsize(int(master.Fd()), unix.TIOCSWINSZ, ws); err != nil {
		return fmt.Errorf("ptyshell: set window size: %w", err)
	}
	return nil
}

func start(cmd *exec.Cmd, rows, cols uint16) (*Session, error) {
	if cmd == nil {
		return nil, fmt.Errorf("ptyshell: nil command")
	}
	master, slave, err := open()
	if err != nil {
		return nil, err
	}
	if rows > 0 && cols > 0 {
		// Best effort, and before the command starts: a shell reads its window
		// size once at startup, so a size applied afterwards would not reach
		// the first prompt. A failure here is not worth losing the session
		// over — the command still runs, at the default 24x80.
		_ = resize(master, rows, cols)
	}

	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	// Setsid + Setctty makes the pty the child's *controlling* terminal, which
	// is what job control, Ctrl-C and the shell's own prompt all key off. Ctty
	// indexes the child's fds, and stdin is fd 0 there.
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setsid = true
	cmd.SysProcAttr.Setctty = true
	cmd.SysProcAttr.Ctty = 0

	if err := cmd.Start(); err != nil {
		_ = slave.Close()
		_ = master.Close()
		return nil, fmt.Errorf("ptyshell: start %s: %w", cmd.Path, err)
	}
	// The child holds its own descriptors now. Keeping this copy open would
	// mean reads on the master never see EOF, because a writer (this process)
	// would still exist after the command exits.
	_ = slave.Close()

	return &Session{Master: master, Cmd: cmd}, nil
}
