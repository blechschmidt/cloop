package kubernetes

import (
	"context"
	"errors"
	"testing"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// clusterRecords is the hub's record of the Kubernetes executor: the labels
// its configuration gives it.
type clusterRecords map[string]map[string]string

func (c clusterRecords) RecordedExecutor(id string) (secretbroker.RecordedExecutor, error) {
	return secretbroker.RecordedExecutor{ID: id, Labels: c[id], Source: "configuration"}, nil
}

// TestBrokerSource_ALabelGrantReachesTheConfiguredExecutor (Task 20432): the
// driver's own cluster credential, granted to a label selector, is leased to
// the executor its configuration labels so, and to no other.
func TestBrokerSource_ALabelGrantReachesTheConfiguredExecutor(t *testing.T) {
	broker, _, executorGrant := newTestBroker(t, "nobody", testKubeconfigYAML(t))
	ctx := context.Background()
	sub, err := secretbroker.ParseSubject("label:cluster=prod")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Grant(ctx, secretbroker.GrantRequest{
		SecretRef: executorGrant.SecretID, Subject: sub,
		Constraints: secretbroker.Constraints{Namespaces: []string{"cloop-jobs"}}, Actor: "test",
	}); err != nil {
		t.Fatal(err)
	}
	records := clusterRecords{"k8s-prod": {"cluster": "prod"}, "k8s-dev": {"cluster": "dev"}}

	src, err := NewBrokerSource(broker, "k8s-prod", "", "")
	if err != nil {
		t.Fatal(err)
	}
	src.Records = records
	creds, err := src.Acquire(ctx, "/srv/app")
	if err != nil {
		t.Fatalf("Acquire on the labelled executor: %v", err)
	}
	src.Release(creds.LeaseID)

	other, err := NewBrokerSource(broker, "k8s-dev", "", "")
	if err != nil {
		t.Fatal(err)
	}
	other.Records = records
	if _, err := other.Acquire(ctx, "/srv/app"); !errors.Is(err, ErrNoKubeconfigGrant) {
		t.Errorf("Acquire on an executor labelled otherwise = %v, want ErrNoKubeconfigGrant", err)
	}
}
