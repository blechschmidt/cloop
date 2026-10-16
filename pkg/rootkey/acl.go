package rootkey

// POSIX access ACLs on a root-owned key file (Task 20431).
//
// systemd 255 and later hand a unit that runs as User= its credentials on a
// tmpfs that keeps ACLs: each file is owned by root, its group class grants
// nothing, and an ACL entry naming the unit's user grants read. stat reports
// it as 0440, but that 0440 is the ACL's mask, not a group's permission, so
// the mode-bit rule in checkAccess — readable through a group this process is
// in — refused every such credential, and `cloop ui` under the unit `cloop hub
// bootstrap` prints did not start. Earlier systemd chowned the file to the
// unit's user, which the owner rule accepts.
//
// A root-owned file with an extended ACL is therefore judged by its entries,
// never by its mode bits: every named user, the owning group and every named
// group whose entry grants anything after the mask must be this process's
// user or a group it is in, and one of them must grant it read. That admits
// exactly what systemd makes and nothing the mode-bit rule would have refused,
// and it refuses the one shape the mode bits hid: an ACL that also lets
// another user read the key.

import (
	"encoding/binary"
	"fmt"
)

// aclEntry is one entry of a POSIX access ACL, as the kernel keeps it in the
// system.posix_acl_access extended attribute.
type aclEntry struct {
	tag  uint16
	perm uint16
	id   uint32
}

// The tags and permission bits of include/uapi/linux/posix_acl.h and the
// version of include/uapi/linux/posix_acl_xattr.h.
const (
	aclUserObj  = 0x01
	aclUser     = 0x02
	aclGroupObj = 0x04
	aclGroup    = 0x08
	aclMask     = 0x10
	aclOther    = 0x20

	aclRead  = 0x04
	aclWrite = 0x02

	aclXattrVersion = 0x0002
)

// parseACL decodes a system.posix_acl_access value: a little-endian version
// word, then one 8-byte entry per tag.
func parseACL(b []byte) ([]aclEntry, error) {
	if len(b) < 4 || (len(b)-4)%8 != 0 {
		return nil, fmt.Errorf("an ACL attribute of %d bytes", len(b))
	}
	if v := binary.LittleEndian.Uint32(b); v != aclXattrVersion {
		return nil, fmt.Errorf("an ACL attribute of version %d", v)
	}
	entries := make([]aclEntry, 0, (len(b)-4)/8)
	for i := 4; i < len(b); i += 8 {
		entries = append(entries, aclEntry{
			tag:  binary.LittleEndian.Uint16(b[i:]),
			perm: binary.LittleEndian.Uint16(b[i+2:]),
			id:   binary.LittleEndian.Uint32(b[i+4:]),
		})
	}
	return entries, nil
}

// checkACL is the rule for a root-owned file whose extended ACL acl is: what
// it grants after the mask, it grants to this process's user or to groups this
// process is in, it grants nobody write, and it grants this process read.
func (rv resolver) checkACL(path string, gid int, acl []aclEntry) error {
	mask := uint16(0o7) // an ACL without a mask entry masks nothing
	for _, e := range acl {
		if e.tag == aclMask {
			mask = e.perm
		}
	}
	readable := false
	for _, e := range acl {
		switch e.tag {
		case aclUserObj, aclMask:
			continue // root, and the mask itself
		case aclOther:
			if e.perm != 0 {
				return fmt.Errorf("%w: %s can be read by every user on the host through its ACL; "+
					"chmod o= it", ErrRefused, path)
			}
			continue
		}
		eff := e.perm & mask
		if eff == 0 {
			continue
		}
		if eff&aclWrite != 0 {
			return fmt.Errorf("%w: %s's ACL lets users other than root write it; a key file is "+
				"written by its owner alone", ErrRefused, path)
		}
		switch e.tag {
		case aclUser:
			if int(e.id) != rv.euid {
				return fmt.Errorf("%w: %s's ACL lets uid %d read it, and this process is uid %d — another "+
					"user could read the key; remove that entry", ErrRefused, path, e.id, rv.euid)
			}
		case aclGroupObj:
			if !rv.inGroup(gid) {
				return fmt.Errorf("%w: %s's ACL lets its group (gid %d) read it, a group this process is "+
					"not in", ErrRefused, path, gid)
			}
		case aclGroup:
			if !rv.inGroup(int(e.id)) {
				return fmt.Errorf("%w: %s's ACL lets gid %d read it, a group this process is not in",
					ErrRefused, path, e.id)
			}
		default:
			return fmt.Errorf("%w: %s's ACL holds an entry of unknown tag %#x", ErrRefused, path, e.tag)
		}
		if eff&aclRead != 0 {
			readable = true
		}
	}
	if !readable {
		return fmt.Errorf("%w: %s is owned by root and its ACL grants this process (uid %d) no read",
			ErrRefused, path, rv.euid)
	}
	return nil
}
