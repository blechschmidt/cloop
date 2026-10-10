package hubdoctor

// Cloud metadata services in allow lists (Task 20397).
//
// An allowlist entry that contains a cloud metadata service without naming it
// — 169.254.0.0/16 with 169.254.169.254 in it, fc00::/7 with AWS's
// fd00:ec2::254 — is refused wherever an allowlist is written. Two places can
// still hold one, and this check reports both:
//
//   - the configuration file, where nothing refuses a hand edit until the
//     next start: `cloop ui` will not start while one is in force, so that is
//     a Fail, and one in a section that is switched off is a Warn;
//   - rule sets and egress grants stored before the refusal existed. They
//     keep loading and keep the service closed — every filter compiled from
//     them drops it ahead of the allow, and the proxy will not dial it — so
//     each is a Warn, listed so an admin can say what was meant.

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/cloudmeta"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const (
	metadataCheck = "firewall.metadata"
	metadataTitle = "Metadata services in allow lists"
)

func checkMetadataExposure(dir string, cfg *config.Config, add addFn) {
	clean := true
	for _, x := range cfg.Executors.MetadataExposures() {
		clean = false
		if x.InForce {
			add(Finding{
				Check: metadataCheck, Title: metadataTitle, Severity: SeverityFail,
				Message: x.Error(),
				Remediation: "Name the address in " + x.Key + " if a sandbox should reach it, or allow a " +
					"range that leaves it out; `cloop ui` refuses to start until then",
				Details: map[string]any{"key": x.Key, "allow": x.Finding.Allow.String(),
					"services": serviceAddrs(x.Finding.Services)},
			})
			continue
		}
		add(Finding{
			Check: metadataCheck, Title: metadataTitle, Severity: SeverityWarn,
			Message: x.Error() + " — the section is switched off, so it opens nothing today",
			Remediation: "Correct " + x.Key + " before switching the section on: `cloop ui` refuses to " +
				"start while it is in force",
			Details: map[string]any{"key": x.Key, "allow": x.Finding.Allow.String(),
				"services": serviceAddrs(x.Finding.Services)},
		})
	}

	stored, known := storedMetadataNotes(dir)
	for _, s := range stored {
		clean = false
		add(Finding{
			Check: metadataCheck, Title: metadataTitle, Severity: SeverityWarn,
			Message:     s.where + ": " + s.note,
			Remediation: s.remedy,
			Details:     map[string]any{"subject": s.subject, "kind": s.kind},
		})
	}
	if !clean {
		return
	}
	msg := "no allowlist opens a cloud metadata service by containing it"
	if !known {
		msg += " in the configuration; the stored rule sets could not be read (see the storage findings)"
	}
	add(Finding{Check: metadataCheck, Title: metadataTitle, Severity: SeverityPass, Message: msg})
}

// storedMetadata is one stored rule set or grant whose allowlist contains a
// metadata service it does not name.
type storedMetadata struct {
	kind, subject, where, note, remedy string
}

const (
	firewallRemedy = "Open the rule set's card and save it again with the address in its allowlist, if a " +
		"sandbox should reach it, or in its denylist to keep it closed"
	grantRemedy = "Revoke the grant and grant it again with --cidrs naming the address, if a sandbox should " +
		"reach it, or with a range that leaves it out"
)

// storedMetadataNotes reads every stored rule set and active egress grant, and
// says which contain a metadata service without naming it. known is false when
// the control plane's database exists and could not be read.
func storedMetadataNotes(dir string) (out []storedMetadata, known bool) {
	dbPath := state.DBPath(dir)
	if _, err := os.Stat(dbPath); err != nil {
		return nil, true
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil, false
	}
	defer func() { _ = db.Close() }()

	known = true
	if recs, err := db.ListExecutorFirewalls(); err == nil {
		for _, r := range recs {
			for _, n := range r.Rules.MetadataNotes() {
				out = append(out, storedMetadata{kind: "device", subject: r.Subject,
					where: "device " + r.Subject + "'s firewall", note: n, remedy: firewallRemedy})
			}
		}
	} else {
		known = false
	}
	if vxs, err := db.ListVirtualExecutors(); err == nil {
		for _, v := range vxs {
			if v.Spec.Firewall == nil {
				continue
			}
			for _, n := range v.Spec.Firewall.MetadataNotes() {
				out = append(out, storedMetadata{kind: "virtual", subject: v.ID,
					where: fmt.Sprintf("virtual executor %s (%s)'s firewall", v.ID, v.Name), note: n,
					remedy: firewallRemedy})
			}
		}
	} else {
		known = false
	}
	if recs, err := db.ListProjectFirewalls(); err == nil {
		for _, r := range recs {
			for _, n := range r.Rules.MetadataNotes() {
				out = append(out, storedMetadata{kind: "project", subject: r.Subject,
					where: "project " + r.Subject + "'s firewall", note: n, remedy: firewallRemedy})
			}
		}
	} else {
		known = false
	}

	store, err := secretstore.NewEgressStore(db)
	if err != nil {
		return out, false
	}
	grants, err := store.ListGrants()
	if err != nil {
		return out, false
	}
	now := time.Now()
	for _, g := range grants {
		if !g.Active(now) {
			continue
		}
		var allow []netip.Prefix
		for _, c := range g.CIDRs {
			if p, err := netip.ParsePrefix(strings.TrimSpace(c)); err == nil {
				allow = append(allow, p)
			}
		}
		for _, f := range cloudmeta.Check(allow, nil) {
			out = append(out, storedMetadata{kind: "egress_grant", subject: g.ID,
				where:  "egress grant " + g.ID,
				note:   f.Sentence() + ". The egress proxy keeps it closed: only its own address in --cidrs opens it",
				remedy: grantRemedy})
		}
	}
	return out, known
}

func serviceAddrs(ss []cloudmeta.Service) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = s.Addr.String()
	}
	return out
}
