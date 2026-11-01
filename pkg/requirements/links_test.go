package requirements

// Links from tasks to the requirements they implement, and the contract the
// agent is given (Task 20460).

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestParseRefAcceptsWhatPeopleWrite(t *testing.T) {
	for in, want := range map[string]int{"3": 3, "R-3": 3, "r-12": 12, "#7": 7, " R-4 ": 4} {
		if got, err := ParseRef(in); err != nil || got != want {
			t.Errorf("ParseRef(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "R-", "R-0", "-3", "R-x", "3.5", "R3"} {
		if _, err := ParseRef(in); !errors.Is(err, ErrInvalid) {
			t.Errorf("ParseRef(%q) = %v, want an ErrInvalid", in, err)
		}
	}
	got, err := ParseRefs([]string{"R-3,R-5", "7", " , "})
	if err != nil || fmt.Sprint(got) != "[3 5 7]" {
		t.Errorf("ParseRefs = %v, %v", got, err)
	}
}

func TestRefsDecodeNumbersAndNames(t *testing.T) {
	var body struct {
		Requirements *Refs `json:"requirements"`
	}
	if err := json.Unmarshal([]byte(`{"requirements":[3,"R-5","#7"]}`), &body); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(*body.Requirements) != "[3 5 7]" {
		t.Errorf("decoded %v", *body.Requirements)
	}
	body.Requirements = nil
	if err := json.Unmarshal([]byte(`{"requirements":[]}`), &body); err != nil || body.Requirements == nil || len(*body.Requirements) != 0 {
		t.Errorf("[] decodes to %v, %v; want an empty list, which clears", body.Requirements, err)
	}
	body.Requirements = nil
	if err := json.Unmarshal([]byte(`{}`), &body); err != nil || body.Requirements != nil {
		t.Errorf("an absent list decodes to %v, %v; want nil, which leaves the links", body.Requirements, err)
	}
	for _, bad := range []string{`"R-3"`, `[0]`, `[-2]`, `[1.5]`, `["R-x"]`, `[true]`, `{"id":3}`} {
		var r Refs
		if err := json.Unmarshal([]byte(bad), &r); !errors.Is(err, ErrInvalid) {
			t.Errorf("Refs from %s = %v, %v; want an ErrInvalid", bad, r, err)
		}
	}
}

func project() []Requirement {
	return []Requirement{
		{ID: 1, Title: "Approved", Status: StatusApproved},
		{ID: 2, Title: "Draft", Status: StatusDraft},
		{ID: 3, Title: "Deprecated", Status: StatusDeprecated},
		{ID: 4, Title: "No status: approved"},
	}
}

func TestCheckLinksKeepsToTheProjectsOwnRequirements(t *testing.T) {
	got, err := CheckLinks([]int{4, 1, 2, 1}, project(), nil)
	if err != nil || fmt.Sprint(got) != "[1 2 4]" {
		t.Fatalf("CheckLinks = %v, %v; want [1 2 4], sorted without repeats, drafts allowed", got, err)
	}
	if got, err := CheckLinks(nil, project(), []int{1}); got != nil || err != nil {
		t.Errorf("no ids = %v, %v; want nothing to store", got, err)
	}

	// An id the project has no requirement for — another project's, say —
	// names nothing here.
	_, err = CheckLinks([]int{1, 9}, project(), nil)
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "R-9 is not a requirement of this project") {
		t.Errorf("an unknown id = %v", err)
	}
	_, err = CheckLinks([]int{8, 9}, project(), nil)
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "R-8, R-9 are not requirements of this project") {
		t.Errorf("two unknown ids = %v", err)
	}
	// Even one the task already names: a link to nothing is not kept.
	if _, err := CheckLinks([]int{9}, project(), []int{9}); !errors.Is(err, ErrInvalid) {
		t.Errorf("a stale link to a requirement that is gone = %v, want refused", err)
	}

	// A new link to a deprecated requirement is refused; one the task has
	// already stays.
	_, err = CheckLinks([]int{3}, project(), nil)
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "R-3 is deprecated") {
		t.Errorf("a new link to a deprecated requirement = %v", err)
	}
	if got, err := CheckLinks([]int{3, 1}, project(), []int{3}); err != nil || fmt.Sprint(got) != "[1 3]" {
		t.Errorf("keeping a link to a requirement deprecated since = %v, %v", got, err)
	}

	many := make([]int, MaxTaskLinks+1)
	var reqs []Requirement
	for i := range many {
		many[i] = i + 1
		reqs = append(reqs, Requirement{ID: i + 1, Title: "r"})
	}
	if _, err := CheckLinks(many, reqs, nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("%d links = %v, want refused", len(many), err)
	}
}

func TestResolveKeepsTheTasksOrder(t *testing.T) {
	linked, missing := Resolve([]int{4, 9, 1, 4}, project())
	if len(linked) != 2 || linked[0].ID != 4 || linked[1].ID != 1 || fmt.Sprint(missing) != "[9]" {
		t.Errorf("Resolve = %+v, %v", linked, missing)
	}
}

// TestContractSectionIsTheAcceptanceContract: the agent is told each linked
// requirement's title, details and test commands, that the task is done only
// when those tests pass, and that they must not be weakened.
func TestContractSectionIsTheAcceptanceContract(t *testing.T) {
	linked := []Requirement{
		{ID: 3, Title: "Config errors exit non-zero", Priority: PriorityMust,
			Description: "A malformed .cloop/config.yaml makes every command exit 1 and name the line.",
			Tests: []Test{
				{Command: "go test ./pkg/config -run TestInvalid"},
				{Name: "cli", Command: "./scripts/check-exit.sh\nexit $?", TimeoutSeconds: 90},
			}},
		{ID: 5, Title: "Every route declares a permission", Status: StatusDraft,
			Description: "No handler is registered without one."},
		{ID: 6, Title: "Old rule", Status: StatusDeprecated, Tests: []Test{{Command: "true"}}},
	}
	s := ContractSection(linked, []int{9})
	for _, want := range []string{
		"## ACCEPTANCE CONTRACT",
		"The task is done only when every test listed here passes",
		"must not be weakened",
		"do not edit,\nskip, disable, delete or loosen a requirement's tests",
		"TASK_FAILED rather than TASK_DONE",
		"### R-3: Config errors exit non-zero [must]",
		"A malformed .cloop/config.yaml makes every command exit 1 and name the line.",
		"1. `go test ./pkg/config -run TestInvalid` (timeout 10m0s)",
		"2. cli — (timeout 1m30s)\n```sh\n./scripts/check-exit.sh\nexit $?\n```",
		"### R-5: Every route declares a permission [draft]",
		"No handler is registered without one.",
		"It has no automated test: its details are the contract.",
		"R-6 (Old rule) is linked to this task but deprecated",
		"R-9 is linked to this task, but its text is not available to this run.",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("the contract lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "### R-6") {
		t.Errorf("a deprecated requirement is part of the contract:\n%s", s)
	}
	if !strings.HasSuffix(s, "\n\n") {
		t.Errorf("the section does not end with a blank line, so the next one would run into it: %q", s[len(s)-20:])
	}
	if got := ContractSection(nil, nil); got != "" {
		t.Errorf("a task that implements nothing gets %q", got)
	}
	// Only links whose text is not here: the agent is told, and not held to
	// tests it cannot see.
	if got := ContractSection(nil, []int{4, 7}); !strings.Contains(got, "R-4, R-7 are linked to this task, but their text is not available") ||
		strings.Contains(got, "done only when") {
		t.Errorf("unavailable links only:\n%s", got)
	}
}

// A command holding a fence of its own is set in a longer one, so it cannot
// end the block early and pass the rest of the prompt off as its own.
func TestContractSectionFencesACommandThatHoldsBackticks(t *testing.T) {
	s := ContractSection([]Requirement{{ID: 1, Title: "t", Tests: []Test{{Command: "echo ```\necho `date`"}}}}, nil)
	if !strings.Contains(s, "````sh\necho ```\necho `date`\n````\n") {
		t.Errorf("fence:\n%s", s)
	}
	s = ContractSection([]Requirement{{ID: 1, Title: "t", Tests: []Test{{Command: "echo `date`"}}}}, nil)
	if !strings.Contains(s, "```sh\necho `date`\n```\n") {
		t.Errorf("a one-line command with a backtick is not fenced:\n%s", s)
	}
}

// TestContractSectionIsBounded: requirements past MaxContractBytes are named
// with their titles and where to read them, and the largest requirement
// Normalize admits still fits whole.
func TestContractSectionIsBounded(t *testing.T) {
	big := func(id int) Requirement {
		r := Requirement{ID: id, Title: fmt.Sprintf("Big %d", id), Description: strings.Repeat("d", MaxDescriptionRunes)}
		for i := 0; i < MaxTests; i++ {
			r.Tests = append(r.Tests, Test{Command: strings.Repeat("c", 3000)})
		}
		if err := r.Normalize(); err != nil {
			t.Fatalf("the test's requirement is not one Normalize admits: %v", err)
		}
		return r
	}
	var linked []Requirement
	for id := 1; id <= 5; id++ {
		linked = append(linked, big(id))
	}
	s := ContractSection(linked, nil)
	if len(s) > MaxContractBytes+4096 {
		t.Errorf("the contract is %d bytes, over its %d budget", len(s), MaxContractBytes)
	}
	if !strings.Contains(s, "### R-1: Big 1") {
		t.Errorf("the first requirement did not fit whole")
	}
	if !strings.Contains(s, "did not\nfit in this prompt") || !strings.Contains(s, "- R-5: Big 5\n") ||
		!strings.Contains(s, "cloop requirements show <id>") {
		t.Errorf("the requirements past the budget are not named:\n%s", s[len(s)-600:])
	}
}

func TestForSeedCarriesWhatARunReadsAndNotWhoWroteIt(t *testing.T) {
	r := Requirement{ID: 3, Title: "t", Description: "d", Priority: PriorityMust, Tags: []string{"x"},
		Tests: []Test{{Command: "true"}}, CreatedBy: "alice@example.com", UpdatedBy: "bob@example.com"}
	got := r.ForSeed()
	if got.CreatedBy != "" || got.UpdatedBy != "" || got.Status != StatusApproved || got.Title != "t" ||
		got.Description != "d" || len(got.Tests) != 1 || got.Priority != PriorityMust {
		t.Errorf("ForSeed = %+v", got)
	}
}
