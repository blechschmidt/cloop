package planio

// Every pm.Task field either travels through a plan file or is excused by name
// (Task 20361). TaskFile lists what it carries by hand, like the statedb
// columns that silently dropped fourteen fields; this keeps the next field
// from being left out of the interchange format without anyone deciding to.

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/taskfill"
	"github.com/blechschmidt/cloop/pkg/pm"
)

// notInterchanged are the pm.Task fields a plan file deliberately leaves out.
var notInterchanged = map[string]string{
	"StartedAt":        "when the exporting project's run worked on the task",
	"CompletedAt":      "when the exporting project's run worked on the task",
	"VerifyRetries":    "a counter of the exporting project's runs",
	"ActualMinutes":    "measured by the exporting project's run",
	"ArtifactPath":     "a file in the exporting project",
	"FailureDiagnosis": "the exporting project's account of a failed run",
	"FailCount":        "a counter of the exporting project's runs",
	"HealAttempts":     "a counter of the exporting project's runs",
	"Annotations":      "the exporting project's decision log",
	"NextRunAt":        "computed from Recurrence when the plan is scheduled",
	"Approved":         "an approval is the exporting team's decision; importing it would skip the importing team's gate",
	"Pinned":           "a queue position on the exporting dashboard",
	"GitHubIssue":      "an issue number in the exporting project's repository; ExternalURL and Links carry full addresses",
	"WriteBackBranch":  "where the exporting hub's executor left the work",
	"WriteBackCommit":  "where the exporting hub's executor left the work",
	"ExecutorID":       "where the exporting hub ran the task",
	"ExecutorKind":     "where the exporting hub ran the task",
	"Isolation":        "where the exporting hub ran the task",
	"RunID":            "an execution of the exporting hub",
	"Background":       "a record of the exporting project's run",
	"Abort":            "a record of the exporting project's run",
	"Review":           "the exporting project's review gate's verdict",
	"Quarantine": "the exporting hub's failover evidence about its own executors, which only that hub's " +
		"explicit reset clears; a plan file must not be able to hold a task back on the importing hub, or release one",
	"ChainInput": "derived at dispatch from the chained predecessor's output",
}

// TestEveryTaskFieldIsInterchangedOrExcused round-trips a task with every
// field set through each format, in replace mode, where IDs are kept.
func TestEveryTaskFieldIsInterchangedOrExcused(t *testing.T) {
	want := taskfill.Task(1)
	// A plan file records deadlines to the second.
	*want.Deadline = want.Deadline.Truncate(time.Second)
	for _, format := range []string{"yaml", "json", "toml"} {
		t.Run(format, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "plan."+format)
			if err := Export(&pm.Plan{Goal: "g", Tasks: []*pm.Task{want}}, format, path); err != nil {
				t.Fatalf("Export: %v", err)
			}
			res, err := Import(path, "", nil, MergeReplace)
			if err != nil {
				t.Fatalf("Import: %v", err)
			}
			got := res.Plan.Tasks[0]

			lost := map[string]bool{}
			for _, name := range taskfill.Diff(want, got) {
				lost[name] = true
				if _, excused := notInterchanged[name]; !excused {
					t.Errorf("%s did not survive a %s plan file: carry it in TaskFile, or add it to "+
						"notInterchanged saying why a plan file should not", name, format)
				}
			}
			for name := range notInterchanged {
				if !lost[name] {
					t.Errorf("notInterchanged excuses %s, which a %s plan file does carry", name, format)
				}
			}
		})
	}
}

// TestMergeImportDropsReferencesIntoTheSourcePlan: a merged task is renumbered,
// so the task IDs its branches name and the sprint it was in belong to the
// plan it came from, as its dependencies already did.
func TestMergeImportDropsReferencesIntoTheSourcePlan(t *testing.T) {
	src := taskfill.Task(1)
	path := filepath.Join(t.TempDir(), "plan.json")
	if err := Export(&pm.Plan{Goal: "g", Tasks: []*pm.Task{src}}, "json", path); err != nil {
		t.Fatalf("Export: %v", err)
	}
	existing := &pm.Plan{Goal: "g", Tasks: []*pm.Task{{ID: 7, Title: "already here"}}}
	res, err := Import(path, "", existing, MergeMerge)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if res.Added != 1 {
		t.Fatalf("added %d tasks, want 1", res.Added)
	}
	got := res.Plan.Tasks[1]
	if got.ID == src.ID || len(got.DependsOn) != 0 || len(got.OnSuccess) != 0 ||
		len(got.OnFailure) != 0 || got.SprintID != 0 {
		t.Errorf("merged task kept references into its source plan: %+v", got)
	}
	// Everything that is not a reference still travels.
	if got.Assignee != src.Assignee || got.StoryPoints != src.StoryPoints ||
		got.RetryBudget != src.RetryBudget || !reflect.DeepEqual(got.Links[0].URL, src.Links[0].URL) {
		t.Errorf("merged task lost fields that are not references: %+v", got)
	}
}

func TestNotInterchangedNamesRealFields(t *testing.T) {
	ty := reflect.TypeOf(pm.Task{})
	for name, why := range notInterchanged {
		if _, ok := ty.FieldByName(name); !ok {
			t.Errorf("notInterchanged names %q, which pm.Task does not have", name)
		}
		if strings.TrimSpace(why) == "" {
			t.Errorf("notInterchanged[%q] gives no reason", name)
		}
	}
}
