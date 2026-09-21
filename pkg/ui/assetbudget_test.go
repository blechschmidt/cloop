package ui

// First-paint asset budget (Task 20289).
//
// The dashboard's eagerly-loaded set is everything a first-time visitor must
// pull down before the page can paint: index.html plus every stylesheet and
// script it references. That set has a habit of growing one <script> at a time,
// and each addition is individually defensible — which is how chart.js came to
// be fetched, parsed and compiled by every visitor on the way to first paint
// when its only consumers were five canvases on a tab most sessions never open.
//
// This gate makes that growth visible at the commit that causes it rather than
// months later in a profile, the way tests/docs gates the published nav and
// tests/arch gates orphaned packages.
//
// Note what is deliberately *not* here: a hand-maintained list of the eager
// assets. The set is derived from the served HTML itself, so moving a script
// out of the document (or back into it) changes the measured number
// automatically. A list would have to be remembered, and a stale one fails far
// from the file that broke it.

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// eagerWireBudgetBytes caps the gzip-encoded octets of the first-paint set.
//
// Wire bytes rather than decoded bytes because that is what a user on a slow
// link actually waits for, and because it is what the deployment serves: nginx
// in front of the hub passes these assets through as the hub emits them, so the
// number measured here is the number that crosses the network.
//
// Measured at 240,895 B (946,640 B decoded) immediately after Task 20289
// deferred chart.js, down from 308,554 B (1,145,442 B decoded); the ceiling was
// that figure plus ~8%
// headroom. The headroom is deliberately modest — enough to absorb ordinary
// panel growth and any jitter in compress/gzip's output across toolchain
// revisions, not enough to hide another 70 KiB library slipping into the head.
//
// Raising this is a legitimate thing to do, but it should be a decision with a
// reason in the commit message, not a reflex to make a red test green.
//
// Raised to 270,000 B by Task 20308, which added the single sign-on Settings
// panel: 5,550 B wire (14.5 KiB of JavaScript and 7.4 KiB of markup). The
// reason it is a raise rather than a deferral is worth recording, because the
// next person will face the same choice with less room than this one had:
//
//   - The 260,000 B ceiling was already spent. HEAD measured 259,025 B — 975 B
//     of headroom — so the budget had stopped being a brake on large additions
//     and become a tripwire for the next addition of any size.
//   - The prose above distinguishes "ordinary panel growth" from "another
//     70 KiB library". A Settings section with a role-mapping editor is the
//     former; for scale, the whole stylesheet is 23 KiB wire.
//   - Deferral — the remedy the failure message recommends first, and the right
//     one for an admin-only panel most sessions never open — is not cheap here.
//     The bundle is one IIFE and none of the shared helpers (api, apiMethod,
//     esc, toast, canGlobal) are on window, so a fragment fetched separately
//     runs at global scope where it can reach none of them. Doing it properly
//     means either widening the global surface or threading a helpers object
//     through a loader shim, which is a frontend refactor with its own
//     regression risk and does not belong in a task about configuring OIDC.
//   - The display-glasses front end does not pay for this: glasses.html does
//     not reference app.js, so bundle growth never reaches it.
//
// The new figure is the measurement plus ~2%, not ~8%, on purpose. That is
// ample for gzip jitter across toolchain revisions and deliberately too little
// for another panel — so the next addition here has to build the deferral path
// rather than move this number again.
//
// Raised to 270,500 B by Task 20320, and the paragraph above is the reason this
// one needs an explicit answer rather than a measurement.
//
// What it bought: 620 B wire. HEAD measured 269,641 B, leaving 359 B, so this
// did not fit. The bytes are errText() and normalizeAPIError() in 00-core.js,
// plus routing the Claude Code panel through api() instead of fetch().
//
// Why it is not the addition that comment was aimed at. That sentence is about
// panels — admin-only UI most sessions never open, which is deferrable in
// principle and was deferred in practice by naming a second hashed asset and
// fetching it on demand. These two functions are inside parseAPIResponse, which
// is the function every api() call already goes through before any panel exists.
// There is no later moment to load them at: the first response they have to
// normalise can arrive before the first tab is opened. Deferring them is not
// expensive here, it is not possible.
//
// And they are not a feature. The hub answers in two error dialects, and
// middleware — authorization, quota, rate limiting — produces the nested one, so
// every refusal a user most needs to read was reaching the DOM as the literal
// "[object Object]". Flattening it once here is what makes ~100 existing render
// sites correct without touching them; the alternative measured *larger*,
// because a wrapper at every call site costs more than one at the boundary.
//
// Trimming was done first and is in the figure: the prose on both functions is
// deliberately terse and points at claude_login_frontend_test.go for the
// rationale, which is why 620 B buys two functions and a panel conversion.
//
// The new slack is 239 B — tighter than what was inherited, on purpose. The
// next addition still has to build the deferral path.
//
// Raised to 271,850 B by Task 20326, which stopped the Claude Code caps panel
// re-fetching from render(): 1,120 B wire. HEAD measured 270,478 B, 22 B of
// headroom, so nothing of any size fitted.
//
// This raise is a different shape from the three above, and the difference is
// the justification. Those bought panels — new surface, deferrable in
// principle. This buys a *reduction*: a throttle, a project-key check and a
// focus guard, which together take the dashboard from ~54 requests/minute at
// /api/claudecode-limits down to one. The trade is bytes once against requests
// for as long as the tab is open, and it was measured in a browser both ways
// (18 requests in 20 s before, 1 in 60 s after).
//
// Deferral does not apply. The other raises could at least argue about loader
// shims; this code is called from render() by way of updateCCLimitsVisibility,
// so it has to be resident before the first project view paints. There is no
// later moment to fetch it at.
//
// The new slack is 230 B, held at the same order as the 239 B above — this
// raise does not reopen the room the previous one closed, and the deferral
// refactor named there is still the next frontend task.
//
// Raised to 272,750 B by Task 20329, which added host_interface passthrough:
// 675 B wire, all of it markup in the Secrets panel's two dialogs.
//
// Most of that is not the new kind. Three of the four fieldsets it adds are
// `local_repo`, `host_device` and the writable checkbox on the *grant* dialog,
// which were simply missing: SEC_GRANT_KINDS listed neither kind, so an
// operator could file an access *request* for a device and could not issue the
// grant that answers it. Minting a device inventory from the dashboard and then
// having to reach for the CLI to hand it out was the gap; this closes it.
//
// Deferral was considered and rejected on consistency grounds rather than on
// cost. The Secrets panel's markup is already resident in index.html in its
// entirety, so lifting out only the four newest fieldsets would leave the
// dialog split across two fetch paths for no measurable gain — 675 B is 0.25%
// of the set, and the panel's own two dialogs are ~40x that. The deferral that
// pays here is the whole panel, which is the refactor the 20326 note already
// names as next; this raise does not make that job larger.
//
// Trimming came first and is in the diff: the hint copy on all four new
// fieldsets was cut to the two facts an operator must not miss. It recovered
// 65 B, which is the honest measure of how little prose weighs after gzip and
// why the remaining bytes are structural.
//
// The new slack is 225 B, held at the same order as the two above.
const eagerWireBudgetBytes = 272_750

// eagerAsset is one member of the first-paint set.
type eagerAsset struct {
	name    string
	wire    int // octets as served: gzip when the asset compresses, else identity
	decoded int // octets after gunzip — what the parser and compiler chew through
}

// collectEagerAssets returns the served page plus every asset it references
// from a src= or href= attribute, which is exactly the set a browser fetches
// without being asked. An asset named only from a data attribute or a <meta>
// (as the deferred chart library now is) is not in it, because nothing fetches
// it until code decides to.
func collectEagerAssets(t *testing.T) []eagerAsset {
	t.Helper()
	set := loadAssets()

	served := func(a *staticAsset) (wire, decoded int) {
		if a.gz != nil {
			return len(a.gz), len(a.raw)
		}
		return len(a.raw), len(a.raw)
	}

	w, d := served(set.page)
	out := []eagerAsset{{name: "/ (index.html)", wire: w, decoded: d}}

	seen := map[string]bool{}
	for _, m := range assetRefRe.FindAllStringSubmatch(set.page.contents, -1) {
		url := m[1]
		if seen[url] {
			continue // referenced twice; the browser fetches it once
		}
		seen[url] = true
		a := set.byPath[url]
		if a == nil {
			t.Fatalf("the served page references %s, which resolves to no asset — "+
				"a browser would 404 on it", url)
		}
		w, d := served(a)
		out = append(out, eagerAsset{name: url, wire: w, decoded: d})
	}
	return out
}

// TestStaticAssets_FirstPaintBudget fails when the eagerly-loaded set outgrows
// its ceiling, and says which asset is responsible.
func TestStaticAssets_FirstPaintBudget(t *testing.T) {
	assets := collectEagerAssets(t)
	if len(assets) < 4 {
		t.Fatalf("only %d eager assets found (%v); the page is not assembled, so "+
			"this budget would pass vacuously", len(assets), assets)
	}

	totalWire, totalDecoded := 0, 0
	for _, a := range assets {
		totalWire += a.wire
		totalDecoded += a.decoded
	}

	sort.Slice(assets, func(i, j int) bool { return assets[i].wire > assets[j].wire })
	var table strings.Builder
	for _, a := range assets {
		fmt.Fprintf(&table, "\n  %-46s %8d B wire  %9d B decoded", a.name, a.wire, a.decoded)
	}

	// Always reported, so `go test -v -run FirstPaintBudget ./pkg/ui/` is the
	// one command that answers "what does a first paint cost today" — both for
	// tuning the ceiling below and for checking a change did what it claimed.
	t.Logf("first-paint set: %d B wire, %d B decoded (ceiling %d B wire):%s",
		totalWire, totalDecoded, eagerWireBudgetBytes, table.String())

	if totalWire > eagerWireBudgetBytes {
		t.Errorf("the first-paint asset set is %d B over its %d B budget "+
			"(%d B wire, %d B decoded).\n"+
			"Every visitor pays this before the dashboard can paint, including "+
			"the display-glasses front end and every session that never leaves "+
			"Projects or Tasks.\n"+
			"Largest first — the one at the top is where the growth is:%s\n\n"+
			"If the new bytes belong to a panel most sessions never open, load "+
			"them on demand instead: name the asset in a <meta> and fetch it "+
			"from the panel, as ensureChartLib does for chart.js (Task 20289). "+
			"If they genuinely belong on first paint, raise "+
			"eagerWireBudgetBytes and say why in the commit message.",
			totalWire-eagerWireBudgetBytes, eagerWireBudgetBytes,
			totalWire, totalDecoded, table.String())
	}

	// A budget that has drifted far below the ceiling is a budget that stopped
	// gating. This is not a failure — shrinking the front end is the goal — but
	// it should be noticed and the ceiling brought down with it.
	if slack := eagerWireBudgetBytes - totalWire; slack > eagerWireBudgetBytes/4 {
		t.Logf("the first-paint set is %d B, %d B under its %d B ceiling — "+
			"if that is a real reduction rather than a stripped-down test build, "+
			"lower eagerWireBudgetBytes so the gate keeps its grip:%s",
			totalWire, slack, eagerWireBudgetBytes, table.String())
	}
}

// TestStaticAssets_ChartLibraryIsNotEager is the specific regression Task 20289
// fixed, kept as its own named check.
//
// The byte budget above would eventually catch chart.js returning to the head,
// but only as "something grew by 69 KiB". This says what happened and why it
// matters, which is the difference between a developer reverting their change
// and a developer understanding it.
func TestStaticAssets_ChartLibraryIsNotEager(t *testing.T) {
	set := loadAssets()

	// The library must still be served, content-addressed and compressed —
	// deferring it must not mean dropping it.
	var chartURL string
	for url := range set.byPath {
		if strings.HasPrefix(url, "/assets/chart.") {
			chartURL = url
		}
	}
	if chartURL == "" {
		t.Fatal("no content-addressed chart.js asset is served; the Analytics " +
			"canvases have nothing to draw with")
	}
	if a := set.byPath[chartURL]; a.gz == nil {
		t.Errorf("%s is served uncompressed; the deferred fetch should still "+
			"cross the network gzipped", chartURL)
	}

	// …but nothing on the page may reference it from an attribute a browser
	// acts on before script runs.
	for _, a := range collectEagerAssets(t) {
		if strings.HasPrefix(a.name, "/assets/chart.") {
			t.Errorf("chart.js is back in the first-paint set (%d B wire, %d B "+
				"decoded). It is loaded from the document rather than on demand, "+
				"so every visitor now pays for it again — including the ones who "+
				"never open Analytics, which is most of them.\n"+
				"Load it through ensureChartLib() from the panel that draws, and "+
				"leave the URL in the <meta name=\"cloop-chart-src\"> the loader "+
				"reads.", a.wire, a.decoded)
		}
	}

	// The loader's two halves have to agree on the meta name, and neither side
	// fails loudly if they drift: the page would simply never draw a chart.
	if !strings.Contains(set.page.contents, `name="cloop-chart-src"`) {
		t.Error(`the served page has no <meta name="cloop-chart-src">; ` +
			"ensureChartLib has no URL to fetch and the Analytics tab will " +
			"show its retry banner forever")
	}
	if !strings.Contains(set.bundle, `meta[name="cloop-chart-src"]`) {
		t.Error("nothing in the bundle reads the cloop-chart-src meta tag — " +
			"the deferred loader is gone, so the charts have no way to load")
	}
}
