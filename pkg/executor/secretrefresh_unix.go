//go:build unix

package executor

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"golang.org/x/sys/unix"
)

// IdentityOf returns the identity of the directory at path, without following
// a symlink there.
func IdentityOf(path string) (FileIdentity, error) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return FileIdentity{}, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return FileIdentity{}, fmt.Errorf("%s is not a directory", path)
	}
	// The conversions are not redundant everywhere: Dev and Ino are narrower
	// than 64 bits on some platforms.
	return FileIdentity{Dev: uint64(st.Dev), Ino: uint64(st.Ino)}, nil
}

func replaceInDir(dir, name string, content []byte, mode fs.FileMode, opts ReplaceOptions) error {
	dirfd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("%w: open lease directory %s without following a link: %v", ErrInvalidSpec, dir, err)
	}
	defer unix.Close(dirfd)

	if opts.Dir != nil {
		var st unix.Stat_t
		if err := unix.Fstat(dirfd, &st); err != nil {
			return fmt.Errorf("executor: stat lease directory %s: %w", dir, err)
		}
		if uint64(st.Dev) != opts.Dir.Dev || uint64(st.Ino) != opts.Dir.Ino {
			return fmt.Errorf("%w: %s is no longer the lease directory that was created for this workload",
				ErrInvalidSpec, dir)
		}
	}

	var cur unix.Stat_t
	switch err := unix.Fstatat(dirfd, name, &cur, unix.AT_SYMLINK_NOFOLLOW); {
	case errors.Is(err, unix.ENOENT):
		return fmt.Errorf("%w: %s was not delivered, so it cannot be refreshed", ErrInvalidSpec, name)
	case err != nil:
		return fmt.Errorf("executor: stat %s in %s: %w", name, dir, err)
	case cur.Mode&unix.S_IFMT != unix.S_IFREG:
		return fmt.Errorf("%w: refusing to rewrite %s in %s: it is not a regular file", ErrInvalidSpec, name, dir)
	}

	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return fmt.Errorf("executor: name a replacement for %s: %w", name, err)
	}
	tmpName := ".cloop-refresh-" + hex.EncodeToString(suffix)
	fd, err := unix.Openat(dirfd, tmpName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("executor: create a replacement for %s: %w", name, err)
	}
	f := os.NewFile(uintptr(fd), tmpName)
	written := false
	fail := func(err error) error {
		if written {
			// Zero what was written before letting go of it: the file holds a
			// credential, and unlinking alone leaves the bytes behind on a
			// filesystem that is not a tmpfs.
			if _, zerr := f.WriteAt(make([]byte, len(content)), 0); zerr == nil {
				_ = f.Sync()
			}
		}
		_ = f.Close()
		_ = unix.Unlinkat(dirfd, tmpName, 0)
		return err
	}
	if err := f.Chmod(mode); err != nil {
		return fail(fmt.Errorf("executor: set mode on the replacement for %s: %w", name, err))
	}
	written = true
	if _, err := f.Write(content); err != nil {
		return fail(fmt.Errorf("executor: write the replacement for %s: %w", name, err))
	}
	if opts.Owner != nil {
		if err := f.Chown(opts.Owner.UID, opts.Owner.GID); err != nil {
			return fail(fmt.Errorf("executor: hand the replacement for %s to its owner: %w", name, err))
		}
		// chown clears setuid/setgid on some systems; the mode is asserted
		// again after it, as at first delivery.
		if err := f.Chmod(mode); err != nil {
			return fail(fmt.Errorf("executor: set mode on the replacement for %s: %w", name, err))
		}
	}
	if err := f.Sync(); err != nil {
		return fail(fmt.Errorf("executor: sync the replacement for %s: %w", name, err))
	}
	if err := f.Close(); err != nil {
		_ = unix.Unlinkat(dirfd, tmpName, 0)
		return fmt.Errorf("executor: close the replacement for %s: %w", name, err)
	}
	if err := unix.Renameat(dirfd, tmpName, dirfd, name); err != nil {
		_ = unix.Unlinkat(dirfd, tmpName, 0)
		return fmt.Errorf("executor: install the replacement for %s: %w", name, err)
	}
	return nil
}
