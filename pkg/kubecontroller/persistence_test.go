package kubecontroller

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executorpool"
)

func TestQuantityBytes(t *testing.T) {
	for q, want := range map[string]int64{
		"20Gi": 20 << 30, "1Gi": 1 << 30, "500M": 500_000_000, "1.5Gi": 3 << 29, "1e9": 1_000_000_000,
		"1024": 1024, "+3Ki": 3072, "0.5": 1, "1k": 1000, "2Ti": 2 << 40,
	} {
		got, err := quantityBytes(q)
		if err != nil || got != want {
			t.Errorf("quantityBytes(%q) = %d, %v; want %d", q, got, err, want)
		}
	}
	for _, q := range []string{"", "-1Gi", "abc", "1Gix", "9999Ei", "1e40"} {
		if _, err := quantityBytes(q); err == nil {
			t.Errorf("quantityBytes(%q) accepted it", q)
		}
	}
}

func TestPersistenceValidation(t *testing.T) {
	valid := ExecutorPoolSpec{HubURL: "https://hub.example", PoolCredentialSecretRef: SecretKeyRef{Name: "c"},
		MaxRunners: 3, Persistence: &Persistence{Enabled: true, Size: "20Gi"}}
	if problems := valid.Normalize().Validate(); len(problems) != 0 {
		t.Fatalf("a valid spec: %v", problems)
	}
	n := valid.Normalize().Persistence
	if n.ReclaimPolicy != ReclaimDelete || n.MaxClaims != 3 || n.MinFree != DefaultPersistenceMinFree ||
		!slices.Equal(n.AccessModes, []string{AccessReadWriteOnce}) || len(n.Mounts) != 3 {
		t.Fatalf("defaults %+v", n)
	}
	for field, mutate := range map[string]func(*Persistence){
		"size":             func(p *Persistence) { p.Size = "" },
		"size ":            func(p *Persistence) { p.Size = "10m" },
		"minFree":          func(p *Persistence) { p.MinFree = "30Gi" },
		"accessModes[0]":   func(p *Persistence) { p.AccessModes = []string{"ReadOnlyMany"} },
		"accessModes":      func(p *Persistence) { p.AccessModes = []string{"ReadWriteOncePod", "ReadWriteOnce"} },
		"mounts[0]":        func(p *Persistence) { p.Mounts = []string{"home"} },
		"reclaimPolicy":    func(p *Persistence) { p.ReclaimPolicy = "Recycle" },
		"maxClaims":        func(p *Persistence) { p.MaxClaims = 2 },
		"storageClassName": func(p *Persistence) { p.StorageClassName = "Fast_SSD" },
	} {
		s := valid
		p := *valid.Persistence
		mutate(&p)
		s.Persistence = &p
		problems := strings.Join(s.Normalize().Validate(), "\n")
		if !strings.Contains(problems, "spec.persistence."+strings.TrimSpace(field)) {
			t.Errorf("%s: problems %q", field, problems)
		}
	}
	// Off is fine without a size.
	off := valid
	off.Persistence = &Persistence{Enabled: false}
	if problems := off.Normalize().Validate(); len(problems) != 0 {
		t.Fatalf("persistence off: %v", problems)
	}
}

func TestTheCRDStatesThePersistenceRules(t *testing.T) {
	d := loadCRD(t)
	spec := d.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties["spec"]
	p := spec.Properties["persistence"]
	rules := func(s crdSchema) string {
		var b strings.Builder
		for _, v := range s.Validations {
			b.WriteString(v["rule"] + "\n")
		}
		return b.String()
	}
	for _, want := range []struct{ where, rule string }{
		{"spec", "self.persistence.maxClaims >= self.maxRunners"},
		{"persistence", "!self.enabled || has(self.size)"},
		{"persistence", "ReadWriteOncePod"},
	} {
		s := spec
		if want.where == "persistence" {
			s = p
		}
		if !strings.Contains(rules(s), want.rule) {
			t.Errorf("the CRD's %s has no rule %q", want.where, want.rule)
		}
	}
	if d := p.Properties["reclaimPolicy"].Default; d != ReclaimDelete {
		t.Errorf("reclaimPolicy defaults to %v", d)
	}
	if d := p.Properties["minFree"].Default; d != DefaultPersistenceMinFree {
		t.Errorf("minFree defaults to %v", d)
	}
	if got := p.Properties["mounts"].Items.Enum; !slices.Equal(got, []string{MountWorkspace, MountGitCache, MountToolCache}) {
		t.Errorf("mounts enum %v", got)
	}
	if storageQuantity.String() != p.Properties["size"].Pattern || storageQuantity.String() != p.Properties["minFree"].Pattern {
		t.Errorf("the CRD's size pattern %q is not the one Validate uses, %q", p.Properties["size"].Pattern,
			storageQuantity.String())
	}
}

func TestPlanDemandWithHeldVolumes(t *testing.T) {
	const web, api = "prj-web", "prj-api"
	for _, c := range []struct {
		name     string
		in       demandInput
		start    []string
		excess   int
		stranded map[string]int
	}{
		{"no storage: the controller's formula",
			demandInput{minRunners: 1, maxRunners: 10, busy: 2, waiting: []string{""}, demand: 3},
			[]string{"", "", ""}, 0, map[string]int{}},
		{"a project's run goes to a runner on its volume",
			demandInput{maxRunners: 10, queued: []executorpool.ProjectDemand{{Tenant: web, Queued: 1}}, demand: 1},
			[]string{web}, 0, map[string]int{}},
		{"a runner holding web serves web, not api",
			demandInput{maxRunners: 10, waiting: []string{web},
				queued: []executorpool.ProjectDemand{{Tenant: api, Queued: 1}}, demand: 1},
			[]string{api}, 1, map[string]int{web: 1}},
		{"a clean runner absorbs the oldest run",
			demandInput{maxRunners: 10, waiting: []string{""},
				queued: []executorpool.ProjectDemand{{Tenant: web, Queued: 1}, {Tenant: api, Queued: 1}}, demand: 2},
			[]string{api}, 0, map[string]int{}},
		{"the idle target is runners holding nothing",
			demandInput{minRunners: 1, maxRunners: 10, waiting: []string{web}},
			[]string{""}, 1, map[string]int{web: 1}},
		{"no room past maxRunners",
			demandInput{maxRunners: 2, busy: 1, waiting: []string{web},
				queued: []executorpool.ProjectDemand{{Tenant: api, Queued: 2}}, demand: 2},
			[]string{}, 1, map[string]int{web: 1}},
		{"runs the hub could not name need clean runners",
			demandInput{maxRunners: 10, waiting: []string{web},
				queued: []executorpool.ProjectDemand{{Tenant: web, Queued: 1}}, demand: 2},
			[]string{""}, 0, map[string]int{}},
	} {
		got := planDemand(c.in)
		if !slices.Equal(got.start, c.start) && !(len(got.start) == 0 && len(c.start) == 0) {
			t.Errorf("%s: start %q, want %q", c.name, got.start, c.start)
		}
		if got.excess != c.excess {
			t.Errorf("%s: excess %d, want %d", c.name, got.excess, c.excess)
		}
		if len(got.stranded) != len(c.stranded) {
			t.Errorf("%s: stranded %v, want %v", c.name, got.stranded, c.stranded)
		}
		for k, v := range c.stranded {
			if got.stranded[k] != v {
				t.Errorf("%s: stranded %v, want %v", c.name, got.stranded, c.stranded)
			}
		}
	}
}

func vol(ordinal int, holds, hubPool string, claimed bool, released time.Time) *volumeView {
	cl := &PersistentVolumeClaim{Metadata: ObjectMeta{Name: "p-storage-" + string(rune('0'+ordinal))},
		Status: ClaimState{Phase: ClaimBound}}
	v := &volumeView{claim: cl, ordinal: ordinal, holds: holds, hubPool: hubPool, releasedAt: released}
	if claimed {
		v.claimedBy = "runner"
	}
	return v
}

func TestPickVolumes(t *testing.T) {
	const web, api, pool = "prj-0000000000000000000000000000000a", "prj-0000000000000000000000000000000b", "pool-x"
	now := time.Now()
	old, recent := now.Add(-time.Hour), now.Add(-time.Minute)
	vols := []*volumeView{
		vol(0, web, pool, false, recent),
		vol(1, api, pool, false, old),
		vol(2, holdsUnknown, pool, false, recent),
		vol(3, web, "another-hub-pool", false, old),
	}
	plans, _ := pickVolumes([]string{web}, vols, 4, pool, nil, now)
	if len(plans) != 1 || plans[0].vol != vols[0] || plans[0].wipe || plans[0].holds != web {
		t.Fatalf("web's run: %+v", plans)
	}
	// A clean runner takes a volume holding nothing worth keeping first —
	// "unknown", or another hub pool's tenant — never api's while there is.
	plans, _ = pickVolumes([]string{"", ""}, vols, 4, pool, nil, now)
	if len(plans) != 2 || !plans[0].wipe || !plans[1].wipe || plans[0].vol == vols[1] || plans[1].vol == vols[1] {
		t.Fatalf("clean runners: %+v", plans)
	}
	// With nothing worthless free, a fresh volume before a project's.
	plans, _ = pickVolumes([]string{""}, vols[:2], 4, pool, nil, now)
	if len(plans) != 1 || plans[0].vol != nil || plans[0].ordinal != 2 || !plans[0].wipe {
		t.Fatalf("a fresh volume: %+v", plans)
	}
	// No room for a fresh one: the least recently used project's, preferring
	// one nobody waits for.
	plans, _ = pickVolumes([]string{""}, vols[:2], 2, pool, map[string]bool{api: true}, now)
	if len(plans) != 1 || plans[0].vol != vols[0] || !plans[0].wipe {
		t.Fatalf("wiping a project's volume: %+v", plans)
	}
	// A claimed volume is never handed out; one whose claim never bound
	// blocks new volumes, which its storage class would fail the same way.
	busy := []*volumeView{vol(0, web, pool, true, old)}
	busy[0].problemAt, busy[0].problemReason = now, "Pending"
	busy[0].claim.Status.Phase = ClaimPending
	if plans, blocked := pickVolumes([]string{web, ""}, busy, 3, pool, nil, now); len(plans) != 0 || blocked == "" {
		t.Fatalf("with the only volume claimed and never bound: %+v %q", plans, blocked)
	}
	// A bound one that failed — a zone, a broken filesystem — does not.
	busy[0].claim.Status.Phase = ClaimBound
	if plans, _ := pickVolumes([]string{""}, busy, 3, pool, nil, now); len(plans) != 1 || plans[0].vol != nil {
		t.Fatalf("with a bound volume that failed: %+v", plans)
	}
	// A volume runners failed on goes last, and one given up on never.
	failed := vol(1, holdsUnknown, pool, false, old)
	failed.failures = 1
	fine := vol(2, holdsUnknown, pool, false, recent)
	if plans, _ := pickVolumes([]string{""}, []*volumeView{failed, fine}, 3, pool, nil, now); len(plans) != 1 ||
		plans[0].vol != fine {
		t.Fatalf("a volume that failed before was preferred: %+v", plans)
	}
	failed.failures = maxVolumeFailures
	if plans, _ := pickVolumes([]string{""}, []*volumeView{failed}, 2, pool, nil, now); len(plans) != 1 ||
		plans[0].vol != nil {
		t.Fatalf("a volume given up on was handed out: %+v", plans)
	}
}

func TestClaimNamesAreStableOrdinals(t *testing.T) {
	pool := &ExecutorPool{Metadata: ObjectMeta{Name: "build"}}
	for n := range []int{0, 1, 12} {
		name := claimName(pool, n)
		got, ok := ordinalOf(pool, name)
		if !ok || got != n {
			t.Errorf("ordinalOf(%q) = %d, %v", name, got, ok)
		}
	}
	for _, bad := range []string{"build-storage-", "build-storage-01", "build-storage-x", "other-storage-0", "build-storage--1"} {
		if _, ok := ordinalOf(pool, bad); ok {
			t.Errorf("%q passed as an ordinal of build", bad)
		}
	}
	long := &ExecutorPool{Metadata: ObjectMeta{Name: strings.Repeat("a", 253)}}
	if name := claimName(long, 9999); len(name) > 253 {
		t.Errorf("a claim name of %d characters", len(name))
	}
}

// fakeFS measures a volume as full until enough is removed from it.
type fakeFS struct {
	root     string
	capacity int64
}

func (f fakeFS) measure(string) (int64, int64, error) {
	var used int64
	_ = filepath.Walk(f.root, func(_ string, fi os.FileInfo, err error) error {
		if err == nil && fi.Mode().IsRegular() {
			used += fi.Size()
		}
		return nil
	})
	return f.capacity, f.capacity - used, nil
}

func TestPrepareStorage(t *testing.T) {
	write := func(t *testing.T, path string, n int) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, make([]byte, n), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("a wipe empties everything, lost+found too", func(t *testing.T) {
		root := t.TempDir()
		write(t, filepath.Join(root, "workspace", "web", "secret.txt"), 10)
		write(t, filepath.Join(root, "stray"), 10)
		write(t, filepath.Join(root, lostFound, "hidden-by-the-last-run"), 10)
		if err := os.Symlink("/etc", filepath.Join(root, "link")); err != nil {
			t.Fatal(err)
		}
		rep, err := PrepareStorage(PrepareOptions{Root: root, Dirs: []string{"workspace", "git"}, Wipe: true,
			Measure: fakeFS{root, 1 << 20}.measure})
		if err != nil || !rep.Wiped || rep.WipeReason != "asked" {
			t.Fatalf("%+v, %v", rep, err)
		}
		entries, _ := os.ReadDir(root)
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		if !slices.Equal(names, []string{"git", lostFound, "workspace"}) {
			t.Fatalf("after the wipe %v", names)
		}
		if inner, _ := os.ReadDir(filepath.Join(root, lostFound)); len(inner) != 0 {
			t.Fatalf("lost+found kept %v through the wipe", inner)
		}
		if _, err := os.Stat("/etc/hostname"); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the link's target was touched: %v", err)
		}
	})
	t.Run("without a wipe the workspace stays and dropped mounts go", func(t *testing.T) {
		root := t.TempDir()
		write(t, filepath.Join(root, "workspace", "web", "main.go"), 10)
		write(t, filepath.Join(root, "tools", "npm", "x"), 10)
		rep, err := PrepareStorage(PrepareOptions{Root: root, Dirs: []string{"workspace"},
			Measure: fakeFS{root, 1 << 20}.measure})
		if err != nil || rep.Wiped {
			t.Fatalf("%+v, %v", rep, err)
		}
		if _, err := os.Stat(filepath.Join(root, "workspace", "web", "main.go")); err != nil {
			t.Fatal("the workspace did not survive")
		}
		if _, err := os.Stat(filepath.Join(root, "tools")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("a mount no longer named survived")
		}
	})
	t.Run("under the floor the caches go first, then everything", func(t *testing.T) {
		root := t.TempDir()
		write(t, filepath.Join(root, "workspace", "web", "big"), 600)
		write(t, filepath.Join(root, "tools", "cache"), 300)
		write(t, filepath.Join(root, "git", "objects"), 50)
		rep, err := PrepareStorage(PrepareOptions{Root: root, Dirs: []string{"workspace", "git", "tools"}, MinFree: 500,
			Measure: fakeFS{root, 1000}.measure})
		if err != nil || !slices.Equal(rep.Cleared, []string{"tools", "git"}) || !rep.Wiped || rep.WipeReason != "full" ||
			rep.FreeBytes != 1000 {
			t.Fatalf("%+v, %v", rep, err)
		}
		root2 := t.TempDir()
		write(t, filepath.Join(root2, "workspace", "web", "small"), 100)
		write(t, filepath.Join(root2, "tools", "cache"), 450)
		rep, err = PrepareStorage(PrepareOptions{Root: root2, Dirs: []string{"workspace", "tools"}, MinFree: 500,
			Measure: fakeFS{root2, 1000}.measure})
		if err != nil || rep.Wiped || !slices.Equal(rep.Cleared, []string{"tools"}) {
			t.Fatalf("clearing the cache was enough: %+v, %v", rep, err)
		}
		if _, err := os.Stat(filepath.Join(root2, "workspace", "web", "small")); err != nil {
			t.Fatal("the workspace went though clearing the cache was enough")
		}
	})
	t.Run("a volume under the floor even empty is full", func(t *testing.T) {
		root := t.TempDir()
		rep, err := PrepareStorage(PrepareOptions{Root: root, Dirs: []string{"workspace"}, MinFree: 2000,
			Measure: fakeFS{root, 1000}.measure})
		if err == nil || !rep.Full || rep.Error == "" {
			t.Fatalf("%+v, %v", rep, err)
		}
	})
	t.Run("a tree the last run broke is put right", func(t *testing.T) {
		root := t.TempDir()
		ws := filepath.Join(root, "workspace")
		write(t, filepath.Join(ws, "web", "main.go"), 10)
		write(t, filepath.Join(ws, "api", "main.go"), 10)
		write(t, filepath.Join(ws, "file-not-tree"), 1)
		if err := os.Symlink("/etc", filepath.Join(ws, "linked")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/etc", filepath.Join(ws, "web", ".cloop")); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(ws, "api"), 0); err != nil {
			t.Fatal(err)
		}
		if _, err := PrepareStorage(PrepareOptions{Root: root, Dirs: []string{"workspace"},
			Measure: fakeFS{root, 1 << 20}.measure}); err != nil {
			t.Fatal(err)
		}
		entries, _ := os.ReadDir(ws)
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		if !slices.Equal(names, []string{"api", "web"}) {
			t.Fatalf("the workspace after repair: %v", names)
		}
		if _, err := os.Lstat(filepath.Join(ws, "web", ".cloop")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("a .cloop link survived")
		}
		if _, err := os.ReadDir(filepath.Join(ws, "api")); err != nil {
			t.Fatalf("an unreadable tree stayed unreadable: %v", err)
		}
	})
	t.Run("refuses what is not a volume root", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "f")
		write(t, file, 1)
		for _, o := range []PrepareOptions{{Root: "relative"}, {Root: file}, {Root: t.TempDir(), Dirs: []string{"../x"}}} {
			if _, err := PrepareStorage(o); err == nil {
				t.Errorf("%+v was accepted", o)
			}
		}
	})
}

// TestRetireOrderCountsOnlyIdleStrandedRunners: only idle runners can be
// retired, so the stranded share of a scale-down is the stranded runners that
// are idle — as many of each project's as are stranded, oldest first — ahead
// of the runners holding nothing, which the idle target may need, and of the
// holders a waiting run needs.
func TestRetireOrderCountsOnlyIdleStrandedRunners(t *testing.T) {
	const web, api = "prj-0000000000000000000000000000000a", "prj-0000000000000000000000000000000b"
	base := time.Now()
	runner := func(name, holds string, age int) *runnerView {
		return &runnerView{pod: &Pod{Metadata: ObjectMeta{Name: name}},
			hub: &executorpool.RunnerState{Holds: holds, EnrolledAt: base.Add(-time.Duration(age) * time.Minute)}}
	}
	idle := []*runnerView{runner("clean-new", "", 1), runner("web-new", web, 2), runner("api", api, 3),
		runner("clean-old", "", 4), runner("web-old", web, 5)}
	// One of web's runners is stranded: the oldest idle one goes first, then
	// the runners holding nothing, then the holders waiting runs need, each
	// group oldest first.
	ordered, strandedIdle := retireOrder(idle, map[string]int{web: 1})
	var names []string
	for _, v := range ordered {
		names = append(names, v.pod.Metadata.Name)
	}
	want := []string{"web-old", "clean-old", "clean-new", "api", "web-new"}
	if !slices.Equal(names, want) || strandedIdle != 1 {
		t.Fatalf("retire order %v (%d stranded idle), want %v (1)", names, strandedIdle, want)
	}
	if _, n := retireOrder(idle[:1], map[string]int{web: 2}); n != 0 {
		t.Fatalf("%d stranded idle runners among runners holding nothing", n)
	}
}
