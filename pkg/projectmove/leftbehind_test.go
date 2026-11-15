package projectmove

import (
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor/movegit"
)

// TestLeftBehindByFindsTheMoveThatTookTheProjectOffTheHub: the copy in the
// hub's directory is the one the latest finished move from the hub's tree
// captured, unless a later move built or kept the working copy there.
func TestLeftBehindByFindsTheMoveThatTookTheProjectOffTheHub(t *testing.T) {
	repo := movegit.Manifest{Repository: true, Snapshot: &movegit.Snapshot{}}
	move := func(id string, phase Phase, from, delivery string, git movegit.Manifest) Move {
		return Move{ID: id, Phase: phase, Detail: Detail{Capture: &CaptureRecord{From: from, Delivery: delivery, Git: git}}}
	}
	cases := []struct {
		name  string
		moves []Move // newest first
		want  string
	}{
		{"none", nil, ""},
		{"hub to a device", []Move{move("a", PhaseDone, "hub", DeliverDevice, repo)}, "a"},
		{"then from that device to another",
			[]Move{move("b", PhaseDone, "device d1", DeliverDevice, repo), move("a", PhaseDone, "hub", DeliverDevice, repo)}, "a"},
		{"a failed move after it changes nothing",
			[]Move{move("b", PhaseFailed, "device d1", DeliverHubTree, repo), move("a", PhaseDone, "hub", DeliverDevice, repo)}, "a"},
		{"back on the hub since",
			[]Move{move("b", PhaseDone, "device d1", DeliverHubTree, repo), move("a", PhaseDone, "hub", DeliverDevice, repo)}, ""},
		{"onto a container on the hub's tree since",
			[]Move{move("b", PhaseDone, "hub", DeliverSameTree, repo), move("a", PhaseDone, "hub", DeliverDevice, repo)}, ""},
		{"a hub tree with no repository left nothing to restore into",
			[]Move{move("a", PhaseDone, "hub", DeliverDevice, movegit.Manifest{})}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, ok := LeftBehindBy(c.moves)
			if got := map[bool]string{true: m.ID, false: ""}[ok]; got != c.want {
				t.Errorf("LeftBehindBy = %q, want %q", got, c.want)
			}
		})
	}
}
