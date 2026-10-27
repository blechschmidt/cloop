package broken

import "testing"

func TestTotal(t *testing.T) {
	if Total([]int{1, 2}) != "3" {
		t.Fatal("wrong total")
	}
}
