// Package sync implements git-based team plan sharing and merging.
// It pushes .cloop/state.json and .cloop/plan-history/ to a configured git
// remote branch and pulls/merges remote state.
package sync

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

const defaultRemote = "origin"
const defaultBranch = "cloop-state"

// Config holds git sync configuration.
type Config struct {
	Remote string
	Branch string
}

// DefaultConfig returns Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Remote: defaultRemote,
		Branch: defaultBranch,
	}
}

// Push commits .cloop/state.json and .cloop/plan-history/ to the configured
// git remote branch. The commit message includes a UTC timestamp.
// The push uses a git worktree so it does not disturb the main working tree.
func Push(workDir, remote, branch string) error {
	if remote == "" {
		remote = defaultRemote
	}
	if branch == "" {
		branch = defaultBranch
	}

	// Ensure the .cloop directory exists.
	cloopDir := filepath.Join(workDir, ".cloop")
	if _, err := os.Stat(cloopDir); os.IsNotExist(err) {
		return fmt.Errorf(".cloop directory not found — run 'cloop init' first")
	}

	// Create a temporary directory for the worktree.
	tmpDir, err := os.MkdirTemp("", "cloop-sync-*")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Try to fetch the branch (may fail if branch doesn't exist yet — that's OK).
	_ = runGit(workDir, "fetch", remote, branch)

	// Check if the remote branch exists.
	remoteRef := remote + "/" + branch
	branchExists := runGit(workDir, "rev-parse", "--verify", remoteRef) == nil

	// Add a worktree on the target branch.
	var addErr error
	if branchExists {
		addErr = runGit(workDir, "worktree", "add", tmpDir, remoteRef)
	} else {
		// Create an orphan branch.
		addErr = runGit(workDir, "worktree", "add", "--orphan", "-b", branch, tmpDir)
	}
	if addErr != nil {
		return fmt.Errorf("creating worktree: %w", addErr)
	}
	defer func() {
		_ = runGit(workDir, "worktree", "remove", "--force", tmpDir)
	}()

	// Copy .cloop/state.json
	if err := copyFile(
		filepath.Join(workDir, ".cloop", "state.json"),
		filepath.Join(tmpDir, ".cloop", "state.json"),
	); err != nil {
		return fmt.Errorf("copying state.json: %w", err)
	}

	// Copy .cloop/plan-history/ (best effort — directory may not exist)
	histSrc := filepath.Join(workDir, ".cloop", "plan-history")
	histDst := filepath.Join(tmpDir, ".cloop", "plan-history")
	_ = copyDir(histSrc, histDst)

	// Stage and commit.
	if err := runGit(tmpDir, "add", ".cloop"); err != nil {
		return fmt.Errorf("git add: %w", err)
	}

	// Check if there is anything to commit (exit 0 = clean, no diff).
	diffErr := runGit(tmpDir, "diff", "--cached", "--quiet")
	if diffErr == nil {
		// Nothing staged — no-op push.
		return nil
	}

	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	msg := "cloop: sync state " + timestamp

	if err := runGit(tmpDir, "commit", "-m", msg); err != nil {
		return fmt.Errorf("git commit: %w", err)
	}

	// Push HEAD to the remote branch.
	if err := runGit(tmpDir, "push", remote, "HEAD:"+branch); err != nil {
		return fmt.Errorf("git push: %w", err)
	}

	return nil
}

// Pull fetches the remote branch and performs a three-way merge of the remote
// plan with the local plan:
//   - Local in_progress tasks are preserved unchanged.
//   - Remote done/failed status is accepted for tasks that exist locally.
//   - Pending tasks that exist only on the remote are unioned in.
//
// Returns the merged plan (the caller must persist it).
// Returns nil, nil if the remote branch has no state.
func Pull(workDir, remote, branch string) (*pm.Plan, error) {
	if remote == "" {
		remote = defaultRemote
	}
	if branch == "" {
		branch = defaultBranch
	}

	// Fetch the remote branch.
	if err := runGit(workDir, "fetch", remote, branch); err != nil {
		return nil, fmt.Errorf("git fetch %s %s: %w", remote, branch, err)
	}

	// Read state.json from the fetched ref.
	remoteRef := remote + "/" + branch
	remoteJSON, err := gitShow(workDir, remoteRef+":"+".cloop/state.json")
	if err != nil {
		// Branch exists but no state.json yet — nothing to merge.
		return nil, nil //nolint:nilerr
	}

	// Parse the remote state.
	var remoteState state.ProjectState
	if err := json.Unmarshal([]byte(remoteJSON), &remoteState); err != nil {
		return nil, fmt.Errorf("parsing remote state.json: %w", err)
	}

	if remoteState.Plan == nil || len(remoteState.Plan.Tasks) == 0 {
		return nil, nil
	}

	// Copy remote plan-history snapshots (best effort).
	_ = pullPlanHistory(workDir, remote, branch, remoteRef)

	// Load the local plan.
	localState, err := state.Load(workDir)
	if err != nil {
		// No local state — just use remote plan entirely.
		return remoteState.Plan, nil
	}

	if localState.Plan == nil || len(localState.Plan.Tasks) == 0 {
		return remoteState.Plan, nil
	}

	// Three-way merge.
	merged := mergePlans(localState.Plan, remoteState.Plan)
	return merged, nil
}

// mergePlans performs the three-way merge:
//   - Keep local in_progress tasks as-is.
//   - Accept remote done/failed status for shared tasks (unless local is in_progress).
//   - Union pending tasks that exist only on the remote.
func mergePlans(local, remote *pm.Plan) *pm.Plan {
	result := &pm.Plan{
		Goal:    local.Goal,
		Version: local.Version,
		Tasks:   make([]*pm.Task, 0, len(local.Tasks)),
	}
	if result.Goal == "" {
		result.Goal = remote.Goal
	}

	// Index remote tasks by ID and by normalised title for matching.
	remoteByID := make(map[int]*pm.Task, len(remote.Tasks))
	remoteByTitle := make(map[string]*pm.Task, len(remote.Tasks))
	for _, t := range remote.Tasks {
		remoteByID[t.ID] = t
		remoteByTitle[normalizeTitle(t.Title)] = t
	}

	// Index local task IDs to detect new remote tasks.
	localIDs := make(map[int]bool, len(local.Tasks))

	// Process local tasks: prefer local in_progress; accept remote terminal status.
	for _, lt := range local.Tasks {
		localIDs[lt.ID] = true
		merged := *lt // copy

		rt, remoteHasTask := remoteByID[lt.ID]
		if !remoteHasTask {
			rt = remoteByTitle[normalizeTitle(lt.Title)]
			remoteHasTask = rt != nil
		}

		if remoteHasTask {
			switch {
			case lt.Status == pm.TaskInProgress:
				// Local is being worked on — preserve local status.
			case rt.Status == pm.TaskDone || rt.Status == pm.TaskFailed || rt.Status == pm.TaskSkipped:
				// Remote reached a terminal status — accept it.
				merged.Status = rt.Status
			}
		}

		result.Tasks = append(result.Tasks, &merged)
	}

	// Union: add pending remote tasks that are not present locally.
	maxLocalID := 0
	for _, t := range local.Tasks {
		if t.ID > maxLocalID {
			maxLocalID = t.ID
		}
	}

	nextID := maxLocalID + 1
	for _, rt := range remote.Tasks {
		if localIDs[rt.ID] {
			continue
		}
		if remoteByTitle[normalizeTitle(rt.Title)] != nil {
			// Check if this title already covered by a local task.
			alreadyLocal := false
			for _, lt := range local.Tasks {
				if normalizeTitle(lt.Title) == normalizeTitle(rt.Title) {
					alreadyLocal = true
					break
				}
			}
			if alreadyLocal {
				continue
			}
		}
		// Only import pending tasks from remote — don't import already-done work.
		if rt.Status != pm.TaskPending {
			continue
		}
		newTask := *rt
		newTask.ID = nextID
		nextID++
		result.Tasks = append(result.Tasks, &newTask)
	}

	return result
}

// normalizeTitle returns a lowercase, whitespace-collapsed title for fuzzy matching.
func normalizeTitle(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}

// copyFile copies src to dst, creating the parent directory as needed.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}

// copyDir recursively copies all files from src to dst.
func copyDir(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			if err := copyDir(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); err != nil {
				return err
			}
		} else {
			if err := copyFile(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

// pullPlanHistory copies snapshot files from the remote branch into the local
// .cloop/plan-history/ directory (skipping files that already exist).
func pullPlanHistory(workDir, remote, branch, remoteRef string) error {
	// List files in remote plan-history.
	out, err := gitShowOutput(workDir, "ls-tree", "--name-only", remoteRef, ".cloop/plan-history/")
	if err != nil {
		return err
	}

	localHistDir := filepath.Join(workDir, ".cloop", "plan-history")
	if err := os.MkdirAll(localHistDir, 0o755); err != nil {
		return err
	}

	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		// line is the full path like ".cloop/plan-history/20250101-120000-v1.json"
		baseName := filepath.Base(line)
		localPath := filepath.Join(localHistDir, baseName)
		if _, err := os.Stat(localPath); err == nil {
			continue // already have it
		}
		content, err := gitShow(workDir, remoteRef+":"+line)
		if err != nil {
			continue
		}
		_ = os.WriteFile(localPath, []byte(content), 0o644)
	}
	_ = remote
	_ = branch
	return nil
}

// runGit executes a git command in the given directory.
func runGit(dir string, args ...string) error {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git %s: %w\n%s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// gitShow returns the content of a file at a git ref.
func gitShow(dir, ref string) (string, error) {
	cmd := exec.Command("git", "show", ref)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git show %s: %w", ref, err)
	}
	return string(out), nil
}

// gitShowOutput runs git with the given args and returns stdout.
func gitShowOutput(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}
