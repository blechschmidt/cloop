// Package missing imports a package that does not exist, so go test cannot
// set it up. A fixture; see ../failing.
package missing

import (
	"testing"

	"github.com/blechschmidt/cloop/scripts/ci-annotate/testdata/red/nowhere"
)

func TestImports(t *testing.T) { nowhere.Call() }
