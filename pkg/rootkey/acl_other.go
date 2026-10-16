//go:build !linux

package rootkey

import "os"

// readACL reports no extended ACL. POSIX ACLs are read on Linux, where systemd
// hands a unit its credentials through one; elsewhere a key file's mode bits
// are the whole of the rule.
func readACL(*os.File) ([]aclEntry, error) { return nil, nil }
