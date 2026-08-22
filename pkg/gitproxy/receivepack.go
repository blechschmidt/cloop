package gitproxy

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

// zeroSHA is the all-zero object name git sends in place of a side that does
// not exist: as the old value of a ref being created, or the new value of one
// being deleted.
const zeroSHA = "0000000000000000000000000000000000000000"

// maxCommandSectionBytes caps the command list ahead of the pack.
//
// The commands are the part of a push this proxy has to hold in memory in order
// to decide about it, so this is the number that bounds what an unauthenticated
// body can make the hub allocate. A megabyte is four figures' worth of ref
// updates — far past any real push, far short of a problem.
const maxCommandSectionBytes = 1 << 20

// RefUpdate is one line of a push: move Ref from Old to New.
//
// The SHAs are the client's claim, not a verified fact. Old in particular is
// what the client believes the remote currently holds; the remote checks it,
// this proxy does not, and no decision here may depend on it being true. What
// the proxy does depend on is the *shape* — whether either side is the zero
// SHA — because that is what distinguishes a create from a delete from an
// update, and those are three different authorities.
type RefUpdate struct {
	Old string
	New string
	Ref string
}

// IsCreate reports whether the ref does not exist yet.
func (u RefUpdate) IsCreate() bool { return u.Old == zeroSHA && u.New != zeroSHA }

// IsDelete reports whether the push removes the ref.
func (u RefUpdate) IsDelete() bool { return u.New == zeroSHA }

// IsUpdate reports whether an existing ref moves to a new commit.
func (u RefUpdate) IsUpdate() bool { return u.Old != zeroSHA && u.New != zeroSHA }

// Action names the authority this update needs, for policy and for audit rows.
func (u RefUpdate) Action() string {
	switch {
	case u.IsDelete():
		return "delete"
	case u.IsCreate():
		return "create"
	default:
		return "update"
	}
}

// String renders the update for a log line. Object names are not secret.
func (u RefUpdate) String() string {
	return fmt.Sprintf("%s %s (%s..%s)", u.Action(), u.Ref, short(u.Old), short(u.New))
}

func short(sha string) string {
	if len(sha) > 8 {
		return sha[:8]
	}
	return sha
}

// ReceivePack is the head of a push: everything before the pack file.
type ReceivePack struct {
	// Commands are the ref updates, in wire order.
	Commands []RefUpdate
	// Capabilities are the tokens the client advertised after the NUL on the
	// first command line — "report-status", "side-band-64k", "agent=git/2.43"
	// and so on.
	Capabilities []string
	// Shallow lists the object names from any shallow lines. They are carried
	// so a caller can see them; nothing here decides on them.
	Shallow []string
}

// HasCapability reports whether the client advertised a bare capability token.
func (r *ReceivePack) HasCapability(name string) bool {
	for _, c := range r.Capabilities {
		if c == name {
			return true
		}
		// Valued capabilities arrive as key=value; match the key.
		if i := strings.IndexByte(c, '='); i >= 0 && c[:i] == name {
			return true
		}
	}
	return false
}

// WantsReportStatus reports whether the client will read a status report.
//
// This decides how a refusal is delivered. A client that asked for a report can
// be told which ref was refused and why, in git's own vocabulary, and will exit
// non-zero having printed it. A client that did not ask has no channel for that
// and must be refused at the HTTP layer instead — a silent 200 to a client that
// cannot read a report is a push that reports success and moved nothing.
func (r *ReceivePack) WantsReportStatus() bool {
	return r.HasCapability("report-status") || r.HasCapability("report-status-v2")
}

// WantsSideband reports whether the status report must be side-band framed.
func (r *ReceivePack) WantsSideband() bool {
	return r.HasCapability("side-band-64k")
}

// errPushCert rejects a signed push rather than guessing at it. See
// ParseReceivePack.
var errPushCert = errors.New("signed pushes (push-cert) are not supported by the git interception proxy")

// ParseReceivePack reads the command section of a git-receive-pack request.
//
// It returns the parsed head and a reader that replays the entire body — the
// consumed command bytes followed by the untouched pack — so a caller that
// decides to allow the push forwards exactly what the client sent. See
// pktReader for why replay rather than re-encode.
//
// A push carrying a push certificate is refused. With push-cert the command
// list lives inside a signed block and the remote applies *that* copy, so
// enforcing a branch allowlist against the unsigned lines would be enforcing it
// against bytes nothing acts on. Refusing is the only honest answer available
// without full certificate parsing, and a proxy that silently passed one
// through would be a branch allowlist with a documented bypass.
func ParseReceivePack(body io.Reader) (*ReceivePack, io.Reader, error) {
	pr := newPktReader(body, maxCommandSectionBytes)
	out := &ReceivePack{}

	first := true
	for {
		typ, payload, err := pr.next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				// A body that ends without a flush is truncated, not empty.
				return nil, nil, fmt.Errorf("%w: command section ended without a flush", errBadPktLine)
			}
			return nil, nil, err
		}
		if typ == pktFlush {
			break
		}
		if typ != pktData {
			return nil, nil, fmt.Errorf("%w: unexpected delimiter in the command section", errBadPktLine)
		}

		line := strings.TrimSuffix(string(payload), "\n")

		if first {
			first = false
			// Capabilities ride on the first line after a NUL.
			if i := strings.IndexByte(line, 0); i >= 0 {
				out.Capabilities = strings.Fields(line[i+1:])
				line = line[:i]
			}
			if strings.HasPrefix(line, "push-cert") {
				return nil, nil, errPushCert
			}
		} else if strings.IndexByte(line, 0) >= 0 {
			// Only the first line may carry a NUL. A second one would let a
			// client hide a command from a parser that splits on it.
			return nil, nil, fmt.Errorf("%w: NUL byte outside the first command line", errBadPktLine)
		}

		if rest, ok := strings.CutPrefix(line, "shallow "); ok {
			sha := strings.TrimSpace(rest)
			if !validObjectName(sha) {
				return nil, nil, fmt.Errorf("%w: shallow line has a malformed object name", errBadPktLine)
			}
			out.Shallow = append(out.Shallow, sha)
			continue
		}

		cmd, err := parseCommand(line)
		if err != nil {
			return nil, nil, err
		}
		out.Commands = append(out.Commands, cmd)
	}

	if len(out.Commands) == 0 {
		// Git sends this to probe; there is nothing to authorise and nothing to
		// forward a decision about. Callers treat it as a no-op push.
		return out, pr.tail(nil), nil
	}
	return out, pr.tail(nil), nil
}

// parseCommand splits one "<old> <new> <ref>" line.
func parseCommand(line string) (RefUpdate, error) {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 {
		return RefUpdate{}, fmt.Errorf("%w: command line %q is not <old> <new> <ref>", errBadPktLine, elide(line))
	}
	u := RefUpdate{Old: parts[0], New: parts[1], Ref: parts[2]}
	if !validObjectName(u.Old) || !validObjectName(u.New) {
		return RefUpdate{}, fmt.Errorf("%w: command line has a malformed object name", errBadPktLine)
	}
	if u.Old == zeroSHA && u.New == zeroSHA {
		// Deleting a ref that does not exist. Harmless upstream, but it is not
		// a shape any of the three authorities describes, so it is not one this
		// proxy will pass along.
		return RefUpdate{}, fmt.Errorf("%w: command line updates a ref from zero to zero", errBadPktLine)
	}
	if err := ValidateRefName(u.Ref); err != nil {
		return RefUpdate{}, fmt.Errorf("%w: %v", errBadPktLine, err)
	}
	return u, nil
}

// validObjectName reports whether s is a lowercase 40-hex object name.
//
// SHA-256 repositories use 64 hex digits; those are accepted too, because
// rejecting them would make this proxy silently unusable on such a repository
// rather than visibly so.
func validObjectName(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func elide(s string) string {
	const max = 120
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
