package remote

import (
	"strings"
	"testing"
)

// TestMintedIDsNeverBeginWithADash: an enrollment token's, an agent's or a
// handle's ID is typed as a command-line argument, and one that begins with
// '-' reads as a flag. Base64url starts one draw in 64 with it; CI's
// `cloop executor revoke <agent>` test drew one (run 38989510992: "unknown
// shorthand flag: 'B' in -B63De5I_6wwcG6R"). Plain randomString passes
// 5,000 draws with a chance of 1 in 10^34.
func TestMintedIDsNeverBeginWithADash(t *testing.T) {
	want := b64.EncodedLen(idBytes)
	for i := 0; i < 5000; i++ {
		id, err := randomID(idBytes)
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(id, "-") || len(id) != want {
			t.Fatalf("minted %q; want %d base64url characters, not beginning with '-'", id, want)
		}
	}
}
