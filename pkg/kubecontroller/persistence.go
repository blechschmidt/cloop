package kubecontroller

// persistence.go: spec.persistence, as written and as the controller reads it
// (Task 20484) — defaults, the rules the CRD states repeated in Go, and the
// byte arithmetic a quantity needs.

import (
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strings"
)

// Where a runner's volume is mounted, and what each mount keeps there.
const (
	storageVolume = "storage"
	storageDir    = "/var/lib/cloop-runner/storage"
	// privateVolume is the memory-backed emptyDir for what must never reach
	// the volume: payload homes, leased files, the runner's own HOME.
	privateVolume = "private"
	privateDir    = "/var/run/cloop/private"
	// privateSizeLimit bounds it: it is counted against the Pod's memory.
	// The caches that grow in a home go to scratchCacheDir instead.
	privateSizeLimit = "512Mi"
	// scratchCacheDir is where caches that would grow in a home go: the
	// disk-backed state emptyDir, beside the agent's work root.
	scratchCacheDir = stateDir + "/caches"
)

// mountDirs maps a mount to its directory beneath the volume's root.
var mountDirs = map[string]string{
	MountWorkspace: "workspace",
	MountGitCache:  "git",
	MountToolCache: "tools",
}

// maxStorageQuantity bounds what a size or a floor may ask for: an exbibyte.
const maxStorageQuantity = int64(1) << 60

// storageQuantity is a size in bytes as the CRD's pattern admits it: no sign
// but +, no fractional-byte suffix, no negative exponent.
var storageQuantity = regexp.MustCompile(`^\+?(([0-9]+(\.[0-9]*)?)|(\.[0-9]+))(([KMGTPE]i)|[kMGTPE]|([eE]\+?[0-9]+))?$`)

// normalized applies the defaults the CRD declares.
func (p *Persistence) normalized(maxRunners int) *Persistence {
	if p == nil {
		return nil
	}
	out := *p
	out.StorageClassName = strings.TrimSpace(out.StorageClassName)
	out.Size = Quantity(strings.TrimSpace(string(out.Size)))
	if len(out.AccessModes) == 0 {
		out.AccessModes = []string{AccessReadWriteOnce}
	} else {
		out.AccessModes = append([]string(nil), out.AccessModes...)
	}
	if len(out.Mounts) == 0 {
		out.Mounts = []string{MountWorkspace, MountGitCache, MountToolCache}
	} else {
		out.Mounts = append([]string(nil), out.Mounts...)
	}
	if strings.TrimSpace(out.ReclaimPolicy) == "" {
		out.ReclaimPolicy = ReclaimDelete
	}
	if out.MaxClaims == 0 {
		out.MaxClaims = maxRunners
	}
	if strings.TrimSpace(string(out.MinFree)) == "" {
		out.MinFree = DefaultPersistenceMinFree
	}
	return &out
}

// hasMount reports whether the volume keeps m.
func (p *Persistence) hasMount(m string) bool {
	if p == nil {
		return false
	}
	for _, x := range p.Mounts {
		if x == m {
			return true
		}
	}
	return false
}

// mountList is the volume's subdirectories, sorted, as the init container
// takes them.
func (p *Persistence) mountList() []string {
	var out []string
	for _, m := range p.Mounts {
		if d, ok := mountDirs[m]; ok {
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out
}

// minFreeBytes is the floor in bytes; Validate refused one that does not parse.
func (p *Persistence) minFreeBytes() int64 {
	n, err := quantityBytes(string(p.MinFree))
	if err != nil {
		n, _ = quantityBytes(DefaultPersistenceMinFree)
	}
	return n
}

// validate adds the persistence rules to v. maxRunners is the spec's.
func (p *Persistence) validate(v *validator, maxRunners int) {
	const f = "spec.persistence"
	if p == nil {
		return
	}
	if p.Enabled && strings.TrimSpace(string(p.Size)) == "" {
		v.add(f+".size", "is required when persistence is enabled")
	}
	var size, floor int64
	if s := strings.TrimSpace(string(p.Size)); s != "" {
		n, err := quantityBytes(s)
		switch {
		case !storageQuantity.MatchString(s):
			v.add(f+".size", fmt.Sprintf("%q is not a size such as 20Gi", s))
		case err != nil:
			v.add(f+".size", fmt.Sprintf("%q is not a quantity such as 20Gi: %v", s, err))
		case n <= 0:
			v.add(f+".size", "must be more than zero")
		default:
			size = n
		}
	}
	if s := strings.TrimSpace(string(p.MinFree)); s != "" {
		n, err := quantityBytes(s)
		switch {
		case !storageQuantity.MatchString(s):
			v.add(f+".minFree", fmt.Sprintf("%q is not a size such as 1Gi", s))
		case err != nil:
			v.add(f+".minFree", fmt.Sprintf("%q is not a quantity such as 1Gi: %v", s, err))
		default:
			floor = n
		}
	}
	if size > 0 && floor > 0 && floor >= size {
		v.add(f+".minFree", fmt.Sprintf("(%s) must be less than size (%s): a runner starts with at least that much free",
			p.MinFree, p.Size))
	}
	if p.StorageClassName != "" && (len(p.StorageClassName) > maxDNSSubdomain || !dnsSubdomain.MatchString(p.StorageClassName)) {
		v.add(f+".storageClassName", fmt.Sprintf("%q is not a lowercase RFC 1123 name", p.StorageClassName))
	}
	if len(p.AccessModes) > 3 {
		v.add(f+".accessModes", "has more than 3 entries")
	}
	seenMode := map[string]bool{}
	for i, m := range p.AccessModes {
		switch m {
		case AccessReadWriteOnce, AccessReadWriteOncePod, AccessReadWriteMany:
		default:
			v.add(fmt.Sprintf("%s.accessModes[%d]", f, i), fmt.Sprintf("%q is not ReadWriteOnce, ReadWriteOncePod or "+
				"ReadWriteMany: a runner writes its volume", m))
		}
		if seenMode[m] {
			v.add(fmt.Sprintf("%s.accessModes[%d]", f, i), fmt.Sprintf("%q is listed twice", m))
		}
		seenMode[m] = true
	}
	if seenMode[AccessReadWriteOncePod] && len(p.AccessModes) > 1 {
		v.add(f+".accessModes", "ReadWriteOncePod cannot be combined with another access mode")
	}
	if len(p.Mounts) > len(mountDirs) {
		v.add(f+".mounts", fmt.Sprintf("has more than %d entries", len(mountDirs)))
	}
	seenMount := map[string]bool{}
	for i, m := range p.Mounts {
		if _, ok := mountDirs[m]; !ok {
			v.add(fmt.Sprintf("%s.mounts[%d]", f, i), fmt.Sprintf("%q is not workspace, gitCache or toolCache", m))
		}
		if seenMount[m] {
			v.add(fmt.Sprintf("%s.mounts[%d]", f, i), fmt.Sprintf("%q is listed twice", m))
		}
		seenMount[m] = true
	}
	switch p.ReclaimPolicy {
	case "", ReclaimDelete, ReclaimRetain:
	default:
		v.add(f+".reclaimPolicy", "must be Retain or Delete")
	}
	if p.MaxClaims < 0 || p.MaxClaims > maxClaimsCeiling {
		v.add(f+".maxClaims", fmt.Sprintf("must be between 1 and %d", maxClaimsCeiling))
	} else if p.MaxClaims > 0 && maxRunners >= 1 && p.MaxClaims < maxRunners {
		v.add(f+".maxClaims", fmt.Sprintf("(%d) must not be fewer than maxRunners (%d): every runner needs a volume "+
			"of its own", p.MaxClaims, maxRunners))
	}
}

// maxClaimsCeiling bounds maxClaims, as the CRD does.
const maxClaimsCeiling = 10000

// quantityBytes reads a Kubernetes quantity as a whole number of bytes,
// rounding a fraction up: 20Gi, 500M, 1.5Gi, 1e9, 1024.
func quantityBytes(q string) (int64, error) {
	q = strings.TrimSpace(q)
	if q == "" || len(q) > 64 || !quantity.MatchString(q) || strings.HasPrefix(q, "-") {
		return 0, fmt.Errorf("not a non-negative quantity")
	}
	q = strings.TrimPrefix(q, "+")
	mult := big.NewInt(1)
	num := q
	for _, suf := range []struct {
		s   string
		exp int64 // power of 1024 for binary, of 1000 for decimal
		bin bool
	}{{"Ki", 1, true}, {"Mi", 2, true}, {"Gi", 3, true}, {"Ti", 4, true}, {"Pi", 5, true}, {"Ei", 6, true},
		{"k", 1, false}, {"M", 2, false}, {"G", 3, false}, {"T", 4, false}, {"P", 5, false}, {"E", 6, false},
		{"m", -1, false}, {"n", -3, false}, {"u", -2, false}} {
		if !strings.HasSuffix(q, suf.s) {
			continue
		}
		rest := strings.TrimSuffix(q, suf.s)
		if rest == "" || strings.ContainsAny(rest[len(rest)-1:], "eE") {
			continue
		}
		num = rest
		base := int64(1000)
		if suf.bin {
			base = 1024
		}
		if suf.exp > 0 {
			mult = new(big.Int).Exp(big.NewInt(base), big.NewInt(suf.exp), nil)
		} else {
			// Milli-, micro- and nano-bytes: a fraction, rounded up below.
			r, ok := new(big.Rat).SetString(num)
			if !ok {
				return 0, fmt.Errorf("not a number")
			}
			den := new(big.Int).Exp(big.NewInt(1000), big.NewInt(-suf.exp), nil)
			r.Quo(r, new(big.Rat).SetInt(den))
			return ratBytes(r)
		}
		break
	}
	r, ok := new(big.Rat).SetString(num)
	if !ok {
		return 0, fmt.Errorf("not a number")
	}
	r.Mul(r, new(big.Rat).SetInt(mult))
	return ratBytes(r)
}

// ratBytes rounds a non-negative rational up to a whole number of bytes,
// refusing one past maxStorageQuantity.
func ratBytes(r *big.Rat) (int64, error) {
	if r.Sign() < 0 {
		return 0, fmt.Errorf("negative")
	}
	n := new(big.Int).Quo(r.Num(), r.Denom())
	if new(big.Rat).SetInt(n).Cmp(r) < 0 {
		n.Add(n, big.NewInt(1))
	}
	if !n.IsInt64() || n.Int64() > maxStorageQuantity {
		return 0, fmt.Errorf("larger than an exbibyte")
	}
	return n.Int64(), nil
}
