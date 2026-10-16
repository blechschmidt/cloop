package egressbroker

// relabel.go: a live proxy session follows its executor's labels (Task 20432).
//
// A session stands on one grant, and a grant issued to label:region=eu stood
// on the labels the session's executor carried when it was redeemed. When the
// hub's record of those labels changes, the session is judged by the new ones:
// RecheckSession — which a hub's keepalive asks every tick — then refuses a
// grant the executor no longer qualifies for, and the hub closes the session,
// its tunnels with it. The record is rewritten too, so a process restoring the
// session judges it the same way.

import (
	"fmt"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// SessionLabelStore is an optional SessionStore extension that rewrites the
// labels a durable session's record holds (Task 20432). A store without it
// keeps the labels the session was redeemed with, and a process restoring the
// session relabels it again when it finds the record and the hub disagree.
type SessionLabelStore interface {
	RelabelSession(id string, labels map[string]string) error
}

// SessionRequester returns who the live session id is judged as, and whether
// this broker serves it.
func (b *Broker) SessionRequester(id string) (r secretbroker.Requester, live bool) {
	sess := b.Session(id)
	if sess == nil || sess.Closed() {
		return r, false
	}
	return sess.issuedTo(), true
}

// RelabelSession judges the live session id as its executor carrying labels
// from now on, and reports whether that changed anything. It closes nothing:
// the caller asks RecheckSession next, and ends a session whose grant the new
// labels no longer match.
func (b *Broker) RelabelSession(id string, labels map[string]string) (bool, error) {
	sess := b.Session(id)
	if sess == nil || sess.Closed() {
		return false, fmt.Errorf("%w: session %s is not live", ErrSessionExpired, id)
	}
	sess.reqMu.Lock()
	if secretbroker.SameLabels(sess.requester.Labels, labels) {
		sess.reqMu.Unlock()
		return false, nil
	}
	sess.requester = sess.requester.Relabeled(labels)
	sess.reqMu.Unlock()

	if store, ok := b.sessionStore.(SessionLabelStore); ok && sess.Durable() {
		if err := store.RelabelSession(id, copyLabels(labels)); err != nil {
			return true, fmt.Errorf("egressbroker: record the labels of session %s: %w", id, err)
		}
	}
	return true, nil
}
