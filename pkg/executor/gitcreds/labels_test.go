package gitcreds_test

// A workspace fetch reaches a grant issued to a label selector (Task 20432).
//
// The guide used to say label: subjects did not work on this path, and they
// did not: the source leased by executor ID alone. It now leases as the
// executor the hub records — a device by its credential's labels, a virtual
// executor by its device's — through the records it is given.

import (
	"context"
	"errors"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitcreds"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// fleetRecords is the hub's record of a small fleet: a device labelled
// region=eu with a virtual executor on it, and one labelled region=us.
type fleetRecords struct{}

func (fleetRecords) RecordedExecutor(id string) (secretbroker.RecordedExecutor, error) {
	switch id {
	case "device-eu", "virt-eu":
		return secretbroker.RecordedExecutor{ID: id, Labels: map[string]string{"region": "eu"}}, nil
	case "device-us":
		return secretbroker.RecordedExecutor{ID: id, Labels: map[string]string{"region": "us"}}, nil
	}
	return secretbroker.RecordedExecutor{ID: id}, nil
}

func TestWorkspaceFetchLeasesALabelGrant(t *testing.T) {
	const token = "ghp_labelworkspace0123456789abcdefghi"
	b := brokerWithPAT(t, token, "label:region=eu")

	for _, tc := range []struct {
		name, device, requesting string
		want                     bool
	}{
		{"a device carrying the labels", "device-eu", "", true},
		{"a virtual executor on it", "device-eu", "virt-eu", true},
		{"a device labelled otherwise", "device-us", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src, err := gitcreds.New(b, tc.device, "ui")
			if err != nil {
				t.Fatal(err)
			}
			src.Records = fleetRecords{}
			ctx := context.Background()
			if tc.requesting != "" {
				ctx = executor.WithRequestingExecutor(ctx, tc.requesting)
			}
			access, release, err := src.ForWorkspace(ctx, "/srv/app", privateWorkspace())
			defer release()
			if tc.want {
				if err != nil || access.Credential.Password != token {
					t.Fatalf("ForWorkspace = %v; want the label grant's token", err)
				}
				return
			}
			var grantErr *executor.WorkspaceGrantError
			if !errors.As(err, &grantErr) {
				t.Fatalf("err = %v, want the fetch refused for want of a grant", err)
			}
		})
	}

	// Without the hub's records the source knows the executor by ID alone,
	// which no label grant matches.
	src, err := gitcreds.New(b, "device-eu", "ui")
	if err != nil {
		t.Fatal(err)
	}
	_, release, err := src.ForWorkspace(context.Background(), "/srv/app", privateWorkspace())
	defer release()
	if err == nil {
		t.Error("a source with no records leased a label grant")
	}
}
