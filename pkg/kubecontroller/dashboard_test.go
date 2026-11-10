package kubecontroller

// Tests for what the controller tells the hub and does for it since Task
// 20486: it names its build and protocol, holds still while its pool is
// cordoned, and reports how many volumes its runners have and how full.

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executorpool"
)

func TestTheControllerNamesItsBuildAndProtocol(t *testing.T) {
	r := newRig(t)
	r.pool("build", r.spec())
	r.start()
	r.eventually("the feed asked for", func() bool {
		uas, _ := r.hub.namedAs()
		return len(uas) > 0
	})
	uas, protocols := r.hub.namedAs()
	for _, ua := range uas {
		if !strings.HasPrefix(ua, executorpool.ControllerUserAgentPrefix+"/") || executorpool.ParseControllerUserAgent(ua) == "" {
			t.Errorf("a request named the controller %q, which names no build the hub can read", ua)
		}
	}
	if len(protocols) != 1 || protocols[0] != strconv.Itoa(executorpool.ControllerProtocol) {
		t.Errorf("the controller said it speaks %v, want only %d", protocols, executorpool.ControllerProtocol)
	}
}

// A cordoned pool is told no demand and no room: the busy runner finishes,
// the idle ones go after the delay — the idle target too — and nothing new
// starts, not even when runs queue.
func TestACordonedPoolKeepsBusyRunnersAndStartsNone(t *testing.T) {
	r := newRig(t)
	spec := r.spec()
	spec.MinRunners = 2
	spec.ScaleDownDelay = "1s"
	r.pool("warm", spec)
	r.start()
	r.eventually("two warm runners", func() bool { return len(r.runnerSecrets()) == 2 })
	pods := r.pods()
	for _, p := range pods {
		r.hub.enroll(r.enrollmentOf(p), time.Now().Add(-time.Hour))
	}
	r.hub.setDemand(1)
	busy := r.enrollmentOf(pods[0])
	r.hub.assign(busy)
	r.eventually("a third runner, so two stay idle", func() bool { return len(r.runnerSecrets()) == 3 })
	for _, p := range r.pods() {
		if id := r.enrollmentOf(p); id != busy {
			r.hub.enroll(id, time.Now().Add(-time.Hour))
		}
	}

	r.hub.set(func(h *fakeHub) { h.cordoned = true; h.demand = 5 })
	r.eventually("the idle runners retired", func() bool { return len(r.hub.retiredIDs()) == 2 })
	for _, id := range r.hub.retiredIDs() {
		if id == busy {
			t.Fatal("the busy runner was retired because its pool was cordoned")
		}
	}
	minted := r.hub.mintedCount()
	r.never("a runner started while cordoned", time.Second, func() bool { return r.hub.mintedCount() > minted })
	if got := r.status("warm").DesiredRunners; got != 1 {
		t.Errorf("desired %d while cordoned with one busy runner, want 1", got)
	}

	r.hub.set(func(h *fakeHub) { h.cordoned = false })
	r.eventually("runners started again once uncordoned", func() bool { return r.hub.mintedCount() > minted })
}

// The hub is told how many volumes the pool's runners have, whenever that
// changes, with each report of its health.
func TestTheHubIsToldTheVolumeCounts(t *testing.T) {
	r := newRig(t)
	r.hub.setDemand(2)
	r.pool("build", r.persistentSpec())
	r.start()
	r.startedRunners(2)
	r.eventually("a report that counts two volumes", func() bool {
		for _, rep := range r.hub.storageReports() {
			st, ok := rep["storage"].(map[string]any)
			if ok && st["claims"] == float64(2) && rep["healthy"] == true {
				return true
			}
		}
		return false
	})
}

// A pool without volumes reports none. A test of its own: a second rig in one
// test would set the package's timings under the first rig's running controller.
func TestAPoolWithoutVolumesReportsNoVolumeCounts(t *testing.T) {
	r := newRig(t)
	r.hub.setDemand(1)
	r.pool("plain", r.spec())
	r.start()
	r.eventually("a report", func() bool { return len(r.hub.storageReports()) > 0 })
	for _, rep := range r.hub.storageReports() {
		if _, ok := rep["storage"]; ok {
			t.Fatalf("a pool without volumes reported some: %v", rep)
		}
	}
}
