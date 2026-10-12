package container

// stagerecord.go: where a container's credential files are staged survives
// the hub process that staged them (Task 20419).
//
// A container's staged credential files lived in that process's memory alone:
// the directory under /dev/shm, the file of each lease and grant in it, the
// sandbox user who owns them. A hub member that adopted the container after its
// owner died rebuilt the handle from its row and had none of it, so the
// directory was never wiped when the container ended, a revocation could take
// the files back only by killing the container (revoke.go), and a GitHub App
// token delivered as a file could not be refreshed — GitHub access died an hour
// into the run.
//
// So the layout is written into the handle's row (HandleRecord.Meta), and an
// adopter rebuilds the stage from it. Paths and names only: the credentials
// themselves stay in the files, and a row is no more a credential than the
// lease bindings beside it.
//
// A row is read back from a database, so nothing in it is trusted further
// than the filesystem bears it out: a directory is accepted only under a
// staging base this driver uses, named as this driver names them, and with
// the identity it had when it was staged — a directory renamed away and
// replaced since, which the sandbox user who owns it in a sticky /dev/shm can
// do, is not the one this stage wiped, refreshes or revokes. A file is
// accepted only inside an accepted directory. What cannot be accounted for
// marks the stage incomplete, and a revocation of a lease whose files it held
// then escalates to removing the container, as it did for a stage that was not
// recorded at all.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// metaSecretStage is the HandleRecord.Meta key carrying a container's staging
// layout, JSON-encoded. Absent for a workload with no file-backed grant.
const metaSecretStage = "secret_stage"

// stageRecord is the persisted shape of a secretStage.
type stageRecord struct {
	UID   int               `json:"uid,omitempty"`
	GID   int               `json:"gid,omitempty"`
	Chown bool              `json:"chown,omitempty"`
	Dirs  []stageDirRecord  `json:"dirs"`
	Files []stageFileRecord `json:"files,omitempty"`
}

type stageDirRecord struct {
	Host   string `json:"host"`
	Target string `json:"target"`
	Dev    uint64 `json:"dev"`
	Ino    uint64 `json:"ino"`
}

type stageFileRecord struct {
	Host    string `json:"host"`
	Sandbox string `json:"sandbox"`
	Lease   string `json:"lease,omitempty"`
	Grant   string `json:"grant,omitempty"`
}

// metaValue renders the stage for its handle's row, "" when there is nothing
// staged.
func (s *secretStage) metaValue() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.dirs) == 0 {
		return ""
	}
	rec := stageRecord{UID: s.uid, GID: s.gid, Chown: s.chown}
	targets := make(map[string]string, len(s.mounts))
	for _, m := range s.mounts {
		targets[m.HostPath] = m.TargetPath
	}
	for _, dir := range s.dirs {
		id := s.dirIDs[dir]
		rec.Dirs = append(rec.Dirs, stageDirRecord{Host: dir, Target: targets[dir], Dev: id.Dev, Ino: id.Ino})
	}
	for _, f := range s.files {
		rec.Files = append(rec.Files, stageFileRecord{Host: f.host, Sandbox: f.sandbox, Lease: f.leaseID, Grant: f.grantID})
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return ""
	}
	return string(b)
}

// withStageMeta records the stage in a handle's meta.
func withStageMeta(meta map[string]string, s *secretStage) map[string]string {
	v := s.metaValue()
	if v == "" {
		return meta
	}
	if meta == nil {
		meta = map[string]string{}
	}
	meta[metaSecretStage] = v
	return meta
}

// stagingBases are the parent directories a staging directory may be in.
func stagingBases() []string {
	bases := append([]string(nil), secretTmpfsCandidates...)
	bases = append(bases, os.TempDir(), secretStageBase())
	for i, b := range bases {
		bases[i] = filepath.Clean(b)
	}
	return bases
}

// restoreSecretStage rebuilds an adopted container's stage from its handle's
// meta. It returns nil when the row recorded none. A stage some of whose
// directories could not be accounted for is returned incomplete, with what
// was wrong; a directory that is simply gone is not a problem — what was in it
// is gone too.
func restoreSecretStage(meta map[string]string) (*secretStage, []string) {
	raw := strings.TrimSpace(meta[metaSecretStage])
	if raw == "" {
		return nil, nil
	}
	var rec stageRecord
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		return &secretStage{incomplete: true, dirIDs: map[string]executor.FileIdentity{}},
			[]string{fmt.Sprintf("its staging record is unreadable: %v", err)}
	}
	stage := &secretStage{uid: rec.UID, gid: rec.GID, chown: rec.Chown, dirIDs: map[string]executor.FileIdentity{}}
	var problems []string
	accepted := map[string]bool{}
	bases := stagingBases()
	for _, d := range rec.Dirs {
		host := filepath.Clean(d.Host)
		target := filepath.Clean(d.Target)
		switch {
		case !filepath.IsAbs(host) || host != d.Host || !strings.HasPrefix(filepath.Base(host), secretDirPrefix):
			stage.incomplete = true
			problems = append(problems, fmt.Sprintf("%q is not a staging directory this driver names", d.Host))
			continue
		case !containsPath(bases, filepath.Dir(host)):
			stage.incomplete = true
			problems = append(problems, fmt.Sprintf("%s is outside every staging base (%s)", host, strings.Join(bases, ", ")))
			continue
		case !filepath.IsAbs(target) || target != d.Target:
			stage.incomplete = true
			problems = append(problems, fmt.Sprintf("%s names no usable path in the container (%q)", host, d.Target))
			continue
		}
		id, err := executor.IdentityOf(host)
		if err != nil {
			if os.IsNotExist(err) {
				continue // gone, and what was staged in it with it
			}
			stage.incomplete = true
			problems = append(problems, fmt.Sprintf("%s cannot be examined: %v", host, err))
			continue
		}
		if id != (executor.FileIdentity{Dev: d.Dev, Ino: d.Ino}) {
			stage.incomplete = true
			problems = append(problems, fmt.Sprintf("%s is not the directory staged for this container: it was "+
				"replaced since", host))
			continue
		}
		accepted[host] = true
		stage.dirs = append(stage.dirs, host)
		stage.dirIDs[host] = id
		stage.mounts = append(stage.mounts, mount{HostPath: host, TargetPath: target, ReadOnly: true})
	}
	for _, f := range rec.Files {
		host := filepath.Clean(f.Host)
		if host != f.Host || !accepted[filepath.Dir(host)] {
			continue // in a directory that is gone, or that was not accepted above
		}
		sandbox := filepath.Clean(f.Sandbox)
		if !filepath.IsAbs(sandbox) {
			stage.incomplete = true
			problems = append(problems, fmt.Sprintf("%s names no usable path in the container (%q)", host, f.Sandbox))
			continue
		}
		stage.files = append(stage.files, stagedFile{host: host, sandbox: sandbox, leaseID: f.Lease, grantID: f.Grant})
	}
	return stage, problems
}

// containsPath reports whether paths holds p.
func containsPath(paths []string, p string) bool {
	for _, c := range paths {
		if c == p {
			return true
		}
	}
	return false
}
