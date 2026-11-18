package layoutsweep

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// chromeCandidates are the install locations this project's machines actually
// use, in preference order; FindChrome then looks on PATH, which is where a CI
// runner has it.
var chromeCandidates = []string{
	"/opt/cft/chrome-linux64/chrome",
	"/root/.cache/puppeteer/chrome/linux-*/chrome-linux64/chrome",
	"/root/.cache/ms-playwright/chromium-*/chrome-linux64/chrome",
	"/root/.cache/ms-playwright/chromium-*/chrome-linux/chrome",
}

// FindChrome returns the Chrome or Chromium the browser tests drive, or "" when
// there is none: those tests skip then, which is how every browser test here
// is gated.
func FindChrome() string {
	for _, pat := range chromeCandidates {
		if !strings.Contains(pat, "*") {
			if st, err := os.Stat(pat); err == nil && !st.IsDir() {
				return pat
			}
			continue
		}
		matches, _ := filepath.Glob(pat)
		for _, m := range matches {
			if st, err := os.Stat(m); err == nil && !st.IsDir() {
				return m
			}
		}
	}
	for _, name := range []string{"google-chrome", "chromium", "chromium-browser"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}
