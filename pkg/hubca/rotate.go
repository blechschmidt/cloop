package hubca

// rotate.go replaces the hub's CA online (Task 20438): `cloop hub ca rotate`
// and Settings → Hub health both take these steps.
//
//	Stage            mint a second CA, sealed exactly as the first — under
//	                 the KEK registry, so under the KMS when secrets.kms is
//	                 set, and rewrapped by key rotation — and store it as
//	                 'ca:next'. Every hub member re-reads its trust within a
//	                 minute (sooner on the cluster bus), and from then on
//	                 every sandbox it dispatches trusts both CAs: git's
//	                 per-URL sslCAInfo bundle, the kube monitor kubeconfig's
//	                 certificate-authority-data, Node's NODE_EXTRA_CA_CERTS,
//	                 a Pod's lease Secret, a device's or virtual executor's
//	                 start frame. Leaves still come from the first CA.
//	Activate         make the second CA the one leaves come from. Refused
//	                 while a run dispatched before the stage is still running
//	                 — it trusts only the first, and would stop verifying the
//	                 monitors — unless forced, which names the runs it breaks;
//	                 and refused while a live member has not adopted the
//	                 stage or predates rotation. The cluster leader then
//	                 reissues every leaf, and every member serves it within a
//	                 minute.
//	RetirePrevious   delete the first CA, its sealed key with it, on a
//	                 secure-delete connection, once every leaf a member serves
//	                 comes from the second — the leaf of a monitor no live
//	                 member runs is reissued by the step itself. It leaves
//	                 every bundle.
//	Abort            destroy a staged CA that was never activated.
//	Emergency        all three at once, with a fresh CA, for a key believed
//	                 compromised now: the proxy sessions of every run that
//	                 trusts only the old CAs are ended, and the runs named.
//
// What a run trusts is what its dispatch recorded (executor.LabelHubCATrust,
// on the spec its executor session keeps). A dispatch with no record was made
// by a build from before rotation, and is assumed to trust only the CA that
// was active then — the old one.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// EndpointRotation is the hub_members endpoint a member advertises when its
// build takes part in a CA rotation: it refreshes its trust, records what each
// dispatch trusts and reports what it serves. A member without it would keep
// signing with the CA it opened at start, so an activation is refused while
// one is live.
const EndpointRotation = "hub_ca_rotation"

// BusTopic is the hub cluster bus topic a rotation step is announced on, so
// every member re-reads its CAs at once rather than at its next minute's tick.
const BusTopic = "hub_ca"

// MemberReportStale is how old a member's report may be before the member is
// taken to have stopped refreshing: it reports every minute.
const MemberReportStale = 3 * time.Minute

// MaxConstraintNames bounds the names one CA's constraints permit.
const MaxConstraintNames = 32

// Step names a rotation step, on RotationEvent and in the audit trail.
type Step string

const (
	StepStage          Step = "stage"
	StepActivate       Step = "activate"
	StepRetirePrevious Step = "retire_previous"
	StepAbandon        Step = "abandon"
	StepEmergency      Step = "emergency"
)

// RotationEvent describes a step this process took. Certificates and names
// only: no key appears in one.
type RotationEvent struct {
	Step       Step
	RotationID string
	FromSerial string
	ToSerial   string
	// Fingerprint and NotAfter describe the CA a stage minted.
	Fingerprint string
	NotAfter    time.Time
	Names       []string
	// Forced are the runs an activation was told to break.
	Forced []string
	// CutRuns are the runs whose proxy sessions an emergency ends.
	CutRuns   []string
	Emergency bool
	Detail    string
}

func (o Options) rotation(e RotationEvent) {
	if o.Rotation != nil {
		o.Rotation(e)
	}
}

// Errors a step refuses with. Each is wrapped with the particulars.
var (
	// ErrNoCA: tls: auto has never run here, so there is nothing to rotate.
	ErrNoCA = errors.New("hubca: there is no hub CA to rotate — no credential monitor has run under tls: auto here")
	// ErrWrongPhase: the rotation is not at the step asked for.
	ErrWrongPhase = errors.New("hubca: the rotation is not at that step")
	// ErrRunsWouldBreak: an activation found runs it would break.
	ErrRunsWouldBreak = errors.New("hubca: runs dispatched before the stage are still running")
	// ErrMembersBehind: a live member has not adopted the step before.
	ErrMembersBehind = errors.New("hubca: not every hub member has caught up")
	// ErrLeavesBehind: a leaf still comes from the previous CA.
	ErrLeavesBehind = errors.New("hubca: a monitor's certificate still comes from the previous CA")
)

// Run is a dispatch still running, as a rotation sees it.
type Run struct {
	ID         string    `json:"run_id,omitempty"`
	SessionID  string    `json:"session_id"`
	Project    string    `json:"project,omitempty"`
	TaskID     int       `json:"task_id,omitempty"`
	ExecutorID string    `json:"executor_id,omitempty"`
	StartedAt  time.Time `json:"started_at,omitzero"`
	// Trusts are the hub CA serials the dispatch was told to trust, and Uses
	// the paths it was told them on (UseGitProxy, UseKubeGuard, UseNode).
	// Recorded is false for a dispatch made by a build from before rotation.
	Trusts   []string `json:"trusts,omitempty"`
	Uses     []string `json:"uses,omitempty"`
	Recorded bool     `json:"recorded"`
}

// Paths a dispatch is given the hub's CA on (executor.LabelHubCAUses).
const (
	UseGitProxy  = "git_proxy"
	UseKubeGuard = "kube_guard"
	UseNode      = "node"
)

// Name is how a run is named to an operator: its run id, or its executor
// session's.
func (r Run) Name() string {
	if r.ID != "" {
		return r.ID
	}
	return r.SessionID
}

// Describe names the run, where it runs and since when.
func (r Run) Describe() string {
	var b strings.Builder
	b.WriteString("run " + r.Name())
	if r.Project != "" {
		b.WriteString(" of " + r.Project)
	}
	if r.TaskID > 0 {
		b.WriteString(" (task " + strconv.Itoa(r.TaskID) + ")")
	}
	if r.ExecutorID != "" {
		b.WriteString(" on executor " + r.ExecutorID)
	}
	if !r.StartedAt.IsZero() {
		b.WriteString(", dispatched " + r.StartedAt.UTC().Format(time.RFC3339))
	}
	if !r.Recorded {
		b.WriteString(", by a build that did not record what it trusts")
	} else if len(r.Uses) > 0 {
		b.WriteString(", trusting the hub CA for " + strings.Join(r.Uses, ", "))
	}
	return b.String()
}

// TrustsCA reports whether the run was told to trust the CA with serial.
func (r Run) TrustsCA(serial string) bool {
	for _, s := range r.Trusts {
		if s == strings.ToLower(serial) {
			return true
		}
	}
	return false
}

// Depends reports whether the run verifies a monitor against the hub's CA at
// all: it was given the CA on some path, or nobody recorded whether it was.
func (r Run) Depends() bool { return !r.Recorded || len(r.Uses) > 0 }

// Breaks reports whether the run would stop verifying a monitor that serves a
// leaf from the CA with serial.
func (r Run) Breaks(serial string) bool { return r.Depends() && !r.TrustsCA(serial) }

// RunsFrom reads the runs out of executor session rows, keeping those still
// running.
func RunsFrom(rows []statedb.ExecutorSessionRow) []Run {
	var out []Run
	for _, row := range rows {
		if row.State != statedb.ExecutorSessionRunning {
			continue
		}
		r := Run{SessionID: row.ID, Project: row.ProjectPath, TaskID: row.TaskID, ExecutorID: row.ExecutorID,
			StartedAt: row.StartedAt}
		var spec struct {
			Labels map[string]string `json:"labels"`
		}
		if strings.TrimSpace(row.SpecJSON) != "" {
			_ = json.Unmarshal([]byte(row.SpecJSON), &spec)
		}
		r.ID = spec.Labels[executor.LabelRunID]
		if v, ok := spec.Labels[executor.LabelHubCATrust]; ok {
			r.Recorded = true
			r.Trusts = ParseLabel(v)
			r.Uses = ParseLabel(spec.Labels[executor.LabelHubCAUses])
		}
		out = append(out, r)
	}
	return out
}

// RunningRuns reads the dispatches the control plane has on record as running.
func RunningRuns(db *statedb.DB) ([]Run, error) {
	rows, err := db.ListExecutorSessions("", true)
	if err != nil {
		return nil, err
	}
	return RunsFrom(rows), nil
}

// Member is a live hub member as a rotation sees it.
type Member struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname,omitempty"`
	PID      int    `json:"pid,omitempty"`
	Version  string `json:"version,omitempty"`
	// Rotates reports that the member's build takes part in a rotation
	// (EndpointRotation).
	Rotates bool `json:"rotates"`
	// Report is what the member last said it serves; nil when it has said
	// nothing — it runs no credential monitor under tls: auto.
	Report *statedb.HubCAMemberRow `json:"-"`
}

// Name names the member to an operator.
func (m Member) Name() string {
	s := m.ID
	if m.Hostname != "" {
		s += " (pid " + strconv.Itoa(m.PID) + " on " + m.Hostname + ")"
	}
	return s
}

// LiveMembers reads the hub members alive now, judged by alive, and what each
// last reported serving. A nil alive counts every member that has not left.
func LiveMembers(db *statedb.DB, alive func(statedb.HubMemberRow) bool) ([]Member, error) {
	rows, err := db.ListHubMembers()
	if err != nil {
		return nil, err
	}
	reports, err := db.ListHubCAMembers()
	if err != nil {
		return nil, err
	}
	byID := map[string]statedb.HubCAMemberRow{}
	for _, r := range reports {
		byID[r.InstanceID] = r
	}
	var out []Member
	for _, r := range rows {
		if !r.LeftAt.IsZero() || (alive != nil && !alive(r)) {
			continue
		}
		m := Member{ID: r.InstanceID, Hostname: r.Hostname, PID: r.PID, Version: r.Version}
		var eps map[string]string
		if json.Unmarshal([]byte(r.Meta), &eps) == nil && eps[EndpointRotation] != "" {
			m.Rotates = true
		}
		if rep, ok := byID[r.InstanceID]; ok {
			rep := rep
			m.Report = &rep
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// MemberStatus is a member and whether it has caught up with the rotation.
type MemberStatus struct {
	Member
	Trusts    []string                        `json:"trusts,omitempty"`
	Active    string                          `json:"active,omitempty"`
	Leaves    map[string]statedb.HubCALeafAck `json:"leaves,omitempty"`
	AdoptedAt time.Time                       `json:"adopted_at,omitzero"`
	SeenAt    time.Time                       `json:"seen_at,omitzero"`
	// Serves reports that the member runs a credential monitor under tls:
	// auto: it reported, recently.
	Serves bool `json:"serves"`
	// CaughtUp is false while the member trusts, signs with or serves
	// something the rotation's current step has moved past; Behind says what.
	CaughtUp bool   `json:"caught_up"`
	Behind   string `json:"behind,omitempty"`
}

// judgeMembers says, for each member, whether it has caught up with st.
func judgeMembers(st State, members []Member, now time.Time) []MemberStatus {
	out := make([]MemberStatus, 0, len(members))
	for _, m := range members {
		ms := MemberStatus{Member: m, CaughtUp: true}
		if rep := m.Report; rep != nil {
			ms.Trusts, ms.Active, ms.Leaves = rep.Trusts, rep.Active, rep.Leaves
			ms.AdoptedAt, ms.SeenAt = rep.AdoptedAt, rep.SeenAt
			ms.Serves = now.Sub(rep.SeenAt) <= MemberReportStale
		}
		switch {
		case !m.Rotates:
			ms.CaughtUp = false
			ms.Behind = "its build (" + orUnknown(m.Version) + ") predates CA rotation: it would keep signing with " +
				"the CA it opened at start — upgrade or stop it"
		case m.Report != nil && !ms.Serves && st.Phase() != PhaseSteady:
			ms.CaughtUp = false
			ms.Behind = "it has not reported for " + now.Sub(m.Report.SeenAt).Round(time.Second).String() +
				", so whether it adopted the step is unknown"
		case ms.Serves:
			ms.Behind = memberBehind(st, ms)
			ms.CaughtUp = ms.Behind == ""
		}
		out = append(out, ms)
	}
	return out
}

// memberBehind says what a reporting member has not yet adopted, "" when
// nothing.
func memberBehind(st State, ms MemberStatus) string {
	if st.Active == nil {
		return ""
	}
	if ms.Active != st.Active.Serial {
		return "it still signs with hub CA " + shortSerial(ms.Active)
	}
	have := map[string]bool{}
	for _, s := range ms.Trusts {
		have[s] = true
	}
	for _, c := range st.Trusted() {
		if !have[c.Serial] {
			return "it does not yet hand dispatches hub CA " + shortSerial(c.Serial)
		}
	}
	trusted := map[string]bool{}
	for _, c := range st.Trusted() {
		trusted[c.Serial] = true
	}
	for _, s := range ms.Trusts {
		if !trusted[s] {
			return "it still hands dispatches hub CA " + shortSerial(s) + ", which is no longer trusted"
		}
	}
	if st.Phase() == PhaseActivated || st.Phase() == PhaseSteady {
		for _, m := range Monitors() {
			if l, ok := ms.Leaves[string(m)]; ok && l.Issuer != "" && l.Issuer != st.Active.Serial {
				return "its " + m.Label() + " serves a leaf from hub CA " + shortSerial(l.Issuer)
			}
		}
	}
	return ""
}

func orUnknown(s string) string {
	if strings.TrimSpace(s) == "" {
		return "unknown"
	}
	return s
}

// servedByAMember reports whether a reporting member serves monitor m.
func servedByAMember(statuses []MemberStatus, m Monitor) bool {
	for _, ms := range statuses {
		if _, ok := ms.Leaves[string(m)]; ok && ms.Serves {
			return true
		}
	}
	return false
}

// LeafStatus is a monitor's stored leaf and the CA it chains to.
type LeafStatus struct {
	Monitor  Monitor   `json:"monitor"`
	Serial   string    `json:"serial"`
	Issuer   string    `json:"issuer"`
	Slot     Slot      `json:"slot,omitempty"`
	Names    []string  `json:"names"`
	NotAfter time.Time `json:"not_after"`
}

// storedLeaves reads each monitor's stored leaf and names the CA that signed
// it.
func storedLeaves(s *Store, st State) ([]LeafStatus, error) {
	var out []LeafStatus
	for _, m := range Monitors() {
		info, err := s.ReadLeaf(m)
		if errors.Is(err, ErrNotMinted) {
			continue
		}
		if err != nil {
			return nil, err
		}
		ls := LeafStatus{Monitor: m, Serial: serialHex(info.Cert.SerialNumber), Issuer: info.Issuer,
			Names: info.SANs, NotAfter: info.Cert.NotAfter}
		if ca := st.ByIssuer(info.Cert); ca != nil {
			ls.Issuer, ls.Slot = ca.Serial, ca.Slot
		}
		out = append(out, ls)
	}
	return out, nil
}

// StoredLeafNames is every name a stored leaf carries: what the monitors are
// reached at by every member, as far as the hub has issued for them.
func StoredLeafNames(s *Store) ([]string, error) {
	var names []string
	for _, m := range Monitors() {
		info, err := s.ReadLeaf(m)
		if errors.Is(err, ErrNotMinted) {
			continue
		}
		if err != nil {
			return nil, err
		}
		names = append(names, info.SANs...)
	}
	return NormalizeSANs(names)
}

// Env is what a step works against.
type Env struct {
	Store  *Store
	Sealer Sealer
	// Options carries the clock, who is acting (Actor) and where the step's
	// record goes (Rotation, Audit).
	Options Options
	// Runs lists the dispatches still running; nil reads the control plane's
	// executor sessions.
	Runs func() ([]Run, error)
	// Alive judges a hub member row; nil counts every member that has not
	// left. The CLI passes hubcluster.RowAlive, a member its own view.
	Alive func(statedb.HubMemberRow) bool
}

func (e Env) runs() ([]Run, error) {
	if e.Runs != nil {
		return e.Runs()
	}
	return RunningRuns(e.Store.db)
}

func (e Env) members() ([]Member, error) { return LiveMembers(e.Store.db, e.Alive) }

func (e Env) check(write bool) error {
	if e.Store == nil {
		return errors.New("hubca: no store")
	}
	if write && e.Sealer == nil {
		return errors.New("hubca: a rotation step needs the sealing keys")
	}
	return nil
}

func newRotationID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("hubca: draw a rotation id: %w", err)
	}
	return "rot_" + hex.EncodeToString(b), nil
}

// StageRequest asks for a stage.
type StageRequest struct {
	// Names are the names the new CA's constraints permit, beside the ones
	// every stored leaf already carries: what the monitors are reached at, and
	// any name an advertise URL is about to move to.
	Names []string
	// NoNameConstraints mints the new CA without constraints, as the first one
	// was: it can then vouch for any name.
	NoNameConstraints bool
	// Emergency marks the stage as Emergency's first step.
	Emergency bool
}

// StageResult is a stage taken.
type StageResult struct {
	Rotation statedb.HubCARotationRow `json:"rotation"`
	CA       *CAInfo                  `json:"ca"`
}

// Stage mints and stores the CA that will replace the active one. Refused
// while another rotation is under way.
func Stage(env Env, req StageRequest) (StageResult, error) {
	if err := env.check(true); err != nil {
		return StageResult{}, err
	}
	st, err := ReadState(env.Store)
	if err != nil {
		return StageResult{}, err
	}
	switch st.Phase() {
	case PhaseNone:
		return StageResult{}, ErrNoCA
	case PhaseStaged:
		return StageResult{}, fmt.Errorf("%w: hub CA %s is already staged%s — activate it, or abort it with --abort",
			ErrWrongPhase, shortSerial(st.Next.Serial), rotationNote(st))
	case PhaseActivated:
		return StageResult{}, fmt.Errorf("%w: the previous hub CA %s is still trusted%s — finish with "+
			"--retire-previous before staging another", ErrWrongPhase, shortSerial(st.Previous.Serial), rotationNote(st))
	}
	var names []string
	if !req.NoNameConstraints {
		stored, err := StoredLeafNames(env.Store)
		if err != nil {
			return StageResult{}, err
		}
		if names, err = NormalizeSANs(append(append([]string(nil), req.Names...), stored...)); err != nil {
			return StageResult{}, err
		}
		if len(names) == 0 {
			return StageResult{}, errors.New("hubca: the new CA's name constraints would permit nothing: no " +
				"monitor's certificate has been issued yet and no name was given — name the hosts the monitors " +
				"are reached at with --name, or mint it without constraints with --no-name-constraints")
		}
		if len(names) > MaxConstraintNames {
			return StageResult{}, fmt.Errorf("hubca: %d names for the new CA's constraints; at most %d",
				len(names), MaxConstraintNames)
		}
	}
	now := env.Options.now()
	cert, certPEM, key, err := mintCA(now, names)
	if err != nil {
		return StageResult{}, err
	}
	serial := serialHex(cert.SerialNumber)
	envl, err := sealKey(env.Sealer, statedb.HubCANext, "ca", serial, key)
	if err != nil {
		return StageResult{}, err
	}
	id, err := newRotationID()
	if err != nil {
		return StageResult{}, err
	}
	rot := statedb.HubCARotationRow{ID: id, State: statedb.HubCARotationStaged, FromSerial: st.Active.Serial,
		ToSerial: serial, Names: names, Emergency: req.Emergency, StagedAt: now, StagedBy: env.Options.Actor}
	ok, err := env.Store.db.StageHubCA(statedb.HubTLSRow{
		ID: statedb.HubCANext, Kind: "ca", Serial: serial, CertPEM: string(certPEM),
		KeyID: envl.KeyID, WrappedDEK: envl.WrappedDEK, KeySealed: envl.Ciphertext,
		NotBefore: cert.NotBefore, NotAfter: cert.NotAfter, IssuedAt: now, IssuedBy: env.Options.Actor,
	}, rot)
	if err != nil {
		return StageResult{}, err
	}
	if !ok {
		return StageResult{}, fmt.Errorf("%w: another rotation was staged at the same moment", ErrWrongPhase)
	}
	info := &CAInfo{Slot: SlotNext, Serial: serial, Fingerprint: certFingerprint(cert), NotBefore: cert.NotBefore,
		NotAfter: cert.NotAfter, Names: ConstraintNames(cert), IssuedAt: now, IssuedBy: env.Options.Actor,
		Cert: cert, PEM: certPEM}
	env.Options.rotation(RotationEvent{Step: StepStage, RotationID: id, FromSerial: st.Active.Serial,
		ToSerial: serial, Fingerprint: info.Fingerprint, NotAfter: cert.NotAfter, Names: names,
		Emergency: req.Emergency})
	return StageResult{Rotation: rot, CA: info}, nil
}

func rotationNote(st State) string {
	if st.Rotation == nil {
		return ""
	}
	return " (rotation " + st.Rotation.ID + ", staged " + st.Rotation.StagedAt.UTC().Format(time.RFC3339) + ")"
}

// RunsError carries the runs an activation would break.
type RunsError struct{ Runs []Run }

func (e *RunsError) Error() string {
	names := make([]string, 0, len(e.Runs))
	for _, r := range e.Runs {
		names = append(names, r.Describe())
	}
	return fmt.Sprintf("%v: %d run(s) trust only the CA being replaced and would stop verifying the monitors: %s — "+
		"wait for them to finish, or activate with --force, which breaks them", ErrRunsWouldBreak, len(e.Runs),
		strings.Join(names, "; "))
}

func (e *RunsError) Unwrap() error { return ErrRunsWouldBreak }

// MembersError carries the members a step waits for.
type MembersError struct {
	Members []MemberStatus
	// Old reports that some predate rotation: no flag overrides that.
	Old bool
}

func (e *MembersError) Error() string {
	parts := make([]string, 0, len(e.Members))
	for _, m := range e.Members {
		parts = append(parts, m.Name()+": "+m.Behind)
	}
	return fmt.Sprintf("%v: %s", ErrMembersBehind, strings.Join(parts, "; "))
}

func (e *MembersError) Unwrap() error { return ErrMembersBehind }

func membersBehind(statuses []MemberStatus) *MembersError {
	var behind []MemberStatus
	old := false
	for _, m := range statuses {
		if !m.CaughtUp {
			behind = append(behind, m)
			old = old || !m.Rotates
		}
	}
	if len(behind) == 0 {
		return nil
	}
	return &MembersError{Members: behind, Old: old}
}

// ActivateRequest asks for an activation.
type ActivateRequest struct {
	// Force activates although runs dispatched before the stage are still
	// running: they stop verifying the monitors, and are named.
	Force bool
	// emergency marks the activation as Emergency's.
	emergency bool
}

// ActivateResult is an activation taken.
type ActivateResult struct {
	Rotation statedb.HubCARotationRow `json:"rotation"`
	// Broken are the runs a forced activation broke.
	Broken []Run `json:"broken,omitempty"`
}

// Activate makes the staged CA the one leaves are issued from.
func Activate(env Env, req ActivateRequest) (ActivateResult, error) {
	if err := env.check(false); err != nil {
		return ActivateResult{}, err
	}
	st, err := ReadState(env.Store)
	if err != nil {
		return ActivateResult{}, err
	}
	if st.Phase() != PhaseStaged {
		return ActivateResult{}, fmt.Errorf("%w: nothing is staged (the hub CA is %s)", ErrWrongPhase, st.Phase())
	}
	if st.Rotation == nil || st.Rotation.ToSerial != st.Next.Serial {
		return ActivateResult{}, fmt.Errorf("%w: the staged hub CA %s has no rotation on record", ErrWrongPhase,
			shortSerial(st.Next.Serial))
	}
	now := env.Options.now()
	members, err := env.members()
	if err != nil {
		return ActivateResult{}, err
	}
	if me := membersBehind(judgeMembers(st, members, now)); me != nil {
		return ActivateResult{}, me
	}
	runs, err := env.runs()
	if err != nil {
		return ActivateResult{}, err
	}
	var broken []Run
	for _, r := range runs {
		if r.Breaks(st.Next.Serial) {
			broken = append(broken, r)
		}
	}
	if len(broken) > 0 && !req.Force {
		return ActivateResult{}, &RunsError{Runs: broken}
	}
	forced := make([]string, 0, len(broken))
	for _, r := range broken {
		forced = append(forced, r.Name())
	}
	if err := env.Store.db.ActivateHubCA(st.Active.Serial, st.Next.Serial, st.Rotation.ID, now,
		env.Options.Actor, forced); err != nil {
		return ActivateResult{}, err
	}
	rot := *st.Rotation
	rot.State, rot.ActivatedAt, rot.ActivatedBy, rot.Forced = statedb.HubCARotationActive, now, env.Options.Actor, forced
	env.Options.rotation(RotationEvent{Step: StepActivate, RotationID: rot.ID, FromSerial: st.Active.Serial,
		ToSerial: st.Next.Serial, Forced: forced, Emergency: req.emergency || rot.Emergency})
	return ActivateResult{Rotation: rot, Broken: broken}, nil
}

// RetireResult is a retirement taken.
type RetireResult struct {
	Rotation statedb.HubCARotationRow `json:"rotation"`
	Retired  string                   `json:"retired"`
}

// RetirePrevious destroys the previous CA once nothing serves its leaves.
func RetirePrevious(env Env) (RetireResult, error) { return retirePrevious(env, nil, false) }

func retirePrevious(env Env, cut []string, emergency bool) (RetireResult, error) {
	if err := env.check(false); err != nil {
		return RetireResult{}, err
	}
	st, err := ReadState(env.Store)
	if err != nil {
		return RetireResult{}, err
	}
	if st.Phase() != PhaseActivated {
		return RetireResult{}, fmt.Errorf("%w: there is no previous hub CA to retire (the hub CA is %s)",
			ErrWrongPhase, st.Phase())
	}
	if st.Rotation == nil || st.Rotation.FromSerial != st.Previous.Serial {
		return RetireResult{}, fmt.Errorf("%w: the previous hub CA %s has no activated rotation on record",
			ErrWrongPhase, shortSerial(st.Previous.Serial))
	}
	if !emergency {
		leaves, err := storedLeaves(env.Store, st)
		if err != nil {
			return RetireResult{}, err
		}
		members, err := env.members()
		if err != nil {
			return RetireResult{}, err
		}
		statuses := judgeMembers(st, members, env.Options.now())
		stale := false
		for _, l := range leaves {
			if l.Issuer == st.Active.Serial {
				continue
			}
			if servedByAMember(statuses, l.Monitor) || env.Sealer == nil {
				return RetireResult{}, fmt.Errorf("%w: the %s's stored certificate %s was issued by hub CA %s — the "+
					"cluster leader reissues it within a minute of the activation; check --status",
					ErrLeavesBehind, l.Monitor.Label(), shortSerial(l.Serial), shortSerial(l.Issuer))
			}
			// No live member serves this monitor — it was turned off, or the
			// hub is down — so no leader will reissue its leaf: this step
			// does, and a member that starts it later serves the new one.
			stale = true
		}
		if stale {
			if _, err := ReissueLeaves(env.Store, env.Sealer, env.Options); err != nil {
				return RetireResult{}, err
			}
		}
		if me := membersBehind(statuses); me != nil {
			return RetireResult{}, me
		}
	}
	now := env.Options.now()
	if err := env.Store.db.RetireHubCAPrevious(st.Previous.Serial, st.Rotation.ID, now, env.Options.Actor, cut); err != nil {
		return RetireResult{}, err
	}
	rot := *st.Rotation
	rot.State, rot.EndedAt, rot.EndedBy, rot.CutRuns = statedb.HubCARotationRetired, now, env.Options.Actor, cut
	env.Options.rotation(RotationEvent{Step: StepRetirePrevious, RotationID: rot.ID, FromSerial: st.Previous.Serial,
		ToSerial: st.Active.Serial, CutRuns: cut, Emergency: emergency || rot.Emergency})
	return RetireResult{Rotation: rot, Retired: st.Previous.Serial}, nil
}

// Abort destroys the staged CA, which was never activated: every dispatch
// that trusted it trusts the active CA too, so nothing breaks.
func Abort(env Env, detail string) (statedb.HubCARotationRow, error) {
	if err := env.check(false); err != nil {
		return statedb.HubCARotationRow{}, err
	}
	st, err := ReadState(env.Store)
	if err != nil {
		return statedb.HubCARotationRow{}, err
	}
	if st.Phase() != PhaseStaged {
		return statedb.HubCARotationRow{}, fmt.Errorf("%w: nothing is staged to abort (the hub CA is %s)",
			ErrWrongPhase, st.Phase())
	}
	return abandon(env, st, detail, false)
}

func abandon(env Env, st State, detail string, emergency bool) (statedb.HubCARotationRow, error) {
	now := env.Options.now()
	rotID := ""
	var rot statedb.HubCARotationRow
	if st.Rotation != nil && st.Rotation.State == statedb.HubCARotationStaged && st.Rotation.ToSerial == st.Next.Serial {
		rotID, rot = st.Rotation.ID, *st.Rotation
	}
	if err := env.Store.db.AbandonHubCANext(st.Next.Serial, rotID, now, env.Options.Actor, detail); err != nil {
		return statedb.HubCARotationRow{}, err
	}
	rot.State, rot.EndedAt, rot.EndedBy, rot.Detail = statedb.HubCARotationAbandoned, now, env.Options.Actor, detail
	env.Options.rotation(RotationEvent{Step: StepAbandon, RotationID: rotID, FromSerial: st.Active.Serial,
		ToSerial: st.Next.Serial, Detail: detail, Emergency: emergency})
	return rot, nil
}

// EmergencyResult is an emergency rotation taken.
type EmergencyResult struct {
	Rotation statedb.HubCARotationRow `json:"rotation"`
	// Replaced are the CAs it took out of every bundle.
	Replaced []string `json:"replaced"`
	CA       *CAInfo  `json:"ca"`
	// Cut are the runs whose proxy sessions the hub members end.
	Cut []Run `json:"cut,omitempty"`
	// Leaves are the monitors' certificates it reissued from the new CA.
	Leaves []Issued `json:"leaves,omitempty"`
}

// Emergency replaces every CA at once with a fresh one, for a key believed
// compromised now: a staged CA is abandoned too, since its key sits in the
// same database. Every run that trusts only the CAs it replaces is named, and
// recorded on the rotation, so each hub member ends the run's proxy sessions —
// whoever holds the old key could otherwise answer for the monitors and take
// the session tokens those runs present. It refuses while a member predates
// rotation, which would go on signing with the replaced CA.
func Emergency(env Env, req StageRequest) (EmergencyResult, error) {
	if err := env.check(true); err != nil {
		return EmergencyResult{}, err
	}
	st, err := ReadState(env.Store)
	if err != nil {
		return EmergencyResult{}, err
	}
	if st.Phase() == PhaseNone {
		return EmergencyResult{}, ErrNoCA
	}
	members, err := env.members()
	if err != nil {
		return EmergencyResult{}, err
	}
	var old []MemberStatus
	for _, m := range judgeMembers(st, members, env.Options.now()) {
		if !m.Rotates {
			old = append(old, m)
		}
	}
	if len(old) > 0 {
		return EmergencyResult{}, &MembersError{Members: old, Old: true}
	}
	var replaced []string
	for _, c := range st.Trusted() {
		replaced = append(replaced, c.Serial)
	}
	const why = "an emergency rotation replaced it"
	if st.Phase() == PhaseStaged {
		if _, err := abandon(env, st, why, true); err != nil {
			return EmergencyResult{}, err
		}
	}
	if st.Phase() == PhaseActivated {
		if _, err := retirePrevious(env, nil, true); err != nil {
			return EmergencyResult{}, err
		}
	}
	req.Emergency = true
	staged, err := Stage(env, req)
	if err != nil {
		return EmergencyResult{}, err
	}
	runs, err := env.runs()
	if err != nil {
		return EmergencyResult{}, err
	}
	var cut []Run
	var cutNames []string
	for _, r := range runs {
		if r.Breaks(staged.CA.Serial) {
			cut = append(cut, r)
			cutNames = append(cutNames, r.Name())
		}
	}
	if _, err := activateUnchecked(env, staged, cutNames); err != nil {
		return EmergencyResult{}, err
	}
	issued, err := ReissueLeaves(env.Store, env.Sealer, env.Options)
	if err != nil {
		return EmergencyResult{}, err
	}
	ret, err := retirePrevious(env, cutNames, true)
	if err != nil {
		return EmergencyResult{}, err
	}
	env.Options.rotation(RotationEvent{Step: StepEmergency, RotationID: ret.Rotation.ID,
		FromSerial: strings.Join(replaced, ","), ToSerial: staged.CA.Serial, Names: staged.CA.Names,
		CutRuns: cutNames, Emergency: true})
	return EmergencyResult{Rotation: ret.Rotation, Replaced: replaced, CA: staged.CA, Cut: cut, Leaves: issued}, nil
}

// activateUnchecked activates the CA a stage just minted, without waiting for
// members or runs: an emergency's, whose runs are cut rather than waited for.
func activateUnchecked(env Env, staged StageResult, forced []string) (statedb.HubCARotationRow, error) {
	now := env.Options.now()
	rot := staged.Rotation
	if err := env.Store.db.ActivateHubCA(rot.FromSerial, rot.ToSerial, rot.ID, now, env.Options.Actor, forced); err != nil {
		return statedb.HubCARotationRow{}, err
	}
	rot.State, rot.ActivatedAt, rot.ActivatedBy, rot.Forced = statedb.HubCARotationActive, now, env.Options.Actor, forced
	env.Options.rotation(RotationEvent{Step: StepActivate, RotationID: rot.ID, FromSerial: rot.FromSerial,
		ToSerial: rot.ToSerial, Forced: forced, Emergency: true})
	return rot, nil
}

// ReissueLeaves replaces every stored leaf the active CA did not sign with one
// it did, for the names the stored leaf carries as far as the CA permits them:
// what the cluster leader does after an activation, done at once by an
// emergency. It reports the leaves it issued.
func ReissueLeaves(s *Store, sealer Sealer, o Options) ([]Issued, error) {
	row, err := s.db.GetHubTLS(statedb.HubCAActive)
	if err != nil {
		return nil, fmt.Errorf("hubca: read the active hub CA: %w", err)
	}
	ca, err := openAuthorityRow(sealer, row, o.now())
	if err != nil {
		return nil, err
	}
	var out []Issued
	audit := o.Audit
	o.Audit = func(i Issued) {
		out = append(out, i)
		if audit != nil {
			audit(i)
		}
	}
	for _, m := range Monitors() {
		info, err := s.ReadLeaf(m)
		if errors.Is(err, ErrNotMinted) {
			continue
		}
		if err != nil {
			return out, err
		}
		if info.Cert.CheckSignatureFrom(ca.cert) == nil {
			continue
		}
		names, _ := Permitted(ca.cert, info.SANs)
		if len(names) == 0 {
			return out, fmt.Errorf("hubca: the new hub CA permits none of the names the %s's certificate "+
				"carries (%s)", m.Label(), strings.Join(info.SANs, ", "))
		}
		if _, _, err := issueLeaf(s, sealer, ca, m, names, serialHex(info.Cert.SerialNumber), ReasonActivation, o); err != nil {
			return out, err
		}
	}
	return out, nil
}

// Status is where a rotation stands, for `--status`, Settings → Hub health and
// the doctor.
type Status struct {
	Phase    Phase                     `json:"phase"`
	Active   *CAInfo                   `json:"active,omitempty"`
	Next     *CAInfo                   `json:"next,omitempty"`
	Previous *CAInfo                   `json:"previous,omitempty"`
	Rotation *statedb.HubCARotationRow `json:"rotation,omitempty"`
	Members  []MemberStatus            `json:"members"`
	Leaves   []LeafStatus              `json:"leaves"`
	// Blocking are the runs the next step would break: while staged, those
	// that do not trust the staged CA; once activated, those that trust only
	// the previous one.
	Blocking []Run `json:"blocking,omitempty"`
	// Running counts the runs on record as running.
	Running int `json:"running"`
	// NextStep says what an operator can do now.
	NextStep string `json:"next_step"`
	// Ready reports that the next step would not be refused.
	Ready bool `json:"ready"`
}

// ReadStatus reads where a rotation stands.
func ReadStatus(env Env) (Status, error) {
	if err := env.check(false); err != nil {
		return Status{}, err
	}
	st, err := ReadState(env.Store)
	if err != nil {
		return Status{}, err
	}
	out := Status{Phase: st.Phase(), Active: st.Active, Next: st.Next, Previous: st.Previous, Rotation: st.Rotation}
	if st.Phase() == PhaseNone {
		out.NextStep = "There is no hub CA: no credential monitor has run under tls: auto here."
		return out, nil
	}
	now := env.Options.now()
	members, err := env.members()
	if err != nil {
		return Status{}, err
	}
	out.Members = judgeMembers(st, members, now)
	if out.Leaves, err = storedLeaves(env.Store, st); err != nil {
		return Status{}, err
	}
	runs, err := env.runs()
	if err != nil {
		return Status{}, err
	}
	out.Running = len(runs)
	switch st.Phase() {
	case PhaseStaged:
		for _, r := range runs {
			if r.Breaks(st.Next.Serial) {
				out.Blocking = append(out.Blocking, r)
			}
		}
	case PhaseActivated:
		for _, r := range runs {
			if r.Breaks(st.Active.Serial) {
				out.Blocking = append(out.Blocking, r)
			}
		}
	}
	behind := membersBehind(out.Members)
	switch st.Phase() {
	case PhaseSteady:
		out.Ready = true
		out.NextStep = "Nothing is under way. To replace the hub CA, stage a new one: `cloop hub ca rotate --stage`."
	case PhaseStaged:
		switch {
		case behind != nil:
			out.NextStep = "Waiting for every hub member to hand dispatches the staged CA: " + behind.Error()
		case len(out.Blocking) > 0:
			out.NextStep = fmt.Sprintf("Waiting for %d run(s) dispatched before the stage to finish; then "+
				"`cloop hub ca rotate --activate` (--force breaks them).", len(out.Blocking))
		default:
			out.Ready = true
			out.NextStep = "Every run trusts the staged CA: activate it with `cloop hub ca rotate --activate`."
		}
	case PhaseActivated:
		leavesBehind := false
		for _, l := range out.Leaves {
			if l.Issuer != st.Active.Serial {
				leavesBehind = true
			}
		}
		switch {
		case leavesBehind:
			out.NextStep = "Waiting for the cluster leader to reissue the monitors' certificates from the new CA."
		case behind != nil:
			out.NextStep = "Waiting for every hub member to serve the new certificates: " + behind.Error()
		default:
			out.Ready = true
			out.NextStep = "Every member serves certificates from the new CA: retire the previous one with " +
				"`cloop hub ca rotate --retire-previous`."
		}
	}
	return out, nil
}

// Payload is the audit row's payload for the step, with via naming what took
// it (the CLI, the dashboard). Its keys are the ones pkg/auditaction lists for
// the step's action.
func (e RotationEvent) Payload(via string) map[string]any {
	p := map[string]any{"rotation": e.RotationID, "emergency": e.Emergency, "via": via}
	switch e.Step {
	case StepStage:
		p["from"], p["to"], p["fingerprint"] = e.FromSerial, e.ToSerial, e.Fingerprint
		p["not_after"], p["names"] = e.NotAfter.UTC().Format(time.RFC3339), nonNil(e.Names)
	case StepActivate:
		p["from"], p["to"], p["forced"] = e.FromSerial, e.ToSerial, nonNil(e.Forced)
	case StepRetirePrevious:
		p["retired"], p["active"], p["cut_runs"] = e.FromSerial, e.ToSerial, nonNil(e.CutRuns)
	case StepAbandon:
		p["abandoned"], p["active"], p["detail"] = e.ToSerial, e.FromSerial, e.Detail
	case StepEmergency:
		delete(p, "emergency")
		p["replaced"], p["active"] = strings.Split(e.FromSerial, ","), e.ToSerial
		p["names"], p["cut_runs"] = nonNil(e.Names), nonNil(e.CutRuns)
	}
	return p
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
