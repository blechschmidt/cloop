package wizard

import (
	"reflect"
	"testing"
)

func TestMoveFirst(t *testing.T) {
	for _, c := range []struct {
		first string
		list  []string
		want  []string
	}{
		{"b", []string{"a", "b", "c"}, []string{"b", "a", "c"}},
		{"a", []string{"a", "b"}, []string{"a", "b"}},
		{"z", []string{"a", "b"}, []string{"z", "a", "b"}},
		{"z", nil, []string{"z"}},
	} {
		if got := moveFirst(c.first, c.list); !reflect.DeepEqual(got, c.want) {
			t.Errorf("moveFirst(%q, %v) = %v, want %v", c.first, c.list, got, c.want)
		}
	}
}
