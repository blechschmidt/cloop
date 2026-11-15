package kubernetes

// Two projects on one Kubernetes executor (Task 20500): each run is a Pod of
// its own whose writable volumes are emptyDirs that die with it, and whose
// Secrets are its own; nothing on a node, no claim and no object another
// project's Pod mounts is ever given to it.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
)

func TestTwoProjectsPodsShareNoVolume(t *testing.T) {
	type built struct {
		project string
		raw     string
		names   map[string]bool
	}
	var pods []built
	for i, project := range []string{"/srv/web", "/srv/api"} {
		req := baseRequest()
		req.HandleID = []string{"k-web000001", "k-api000002"}[i]
		req.Labels = map[string]string{"project": project, "task_id": "1"}
		req.Env = []string{"GITHUB_TOKEN=x"}
		req.LeaseSecretName = leaseSecretName(req.HandleID)
		req.Workspace = executor.Workspace{Kind: executor.WorkspaceGit, Repo: "https://example.com/" +
			strings.TrimPrefix(project, "/srv/") + ".git", Ref: "main"}
		p, err := buildPod(req)
		if err != nil {
			t.Fatalf("buildPod(%s): %v", project, err)
		}
		raw, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		names := map[string]bool{}
		for _, v := range p.Spec.Volumes {
			switch {
			case v.EmptyDir != nil:
			case v.Secret != nil:
				names["secret:"+v.Secret.SecretName] = true
			case v.ConfigMap != nil:
				names["configmap:"+v.ConfigMap.Name] = true
			default:
				t.Errorf("%s's Pod mounts volume %q, which is none of emptyDir, Secret or ConfigMap", project, v.Name)
			}
		}
		for _, banned := range []string{`"hostPath"`, `"persistentVolumeClaim"`, `"nfs"`, `"csi"`} {
			if strings.Contains(string(raw), banned) {
				t.Errorf("%s's Pod carries %s", project, banned)
			}
		}
		pods = append(pods, built{project, string(raw), names})
	}
	for name := range pods[0].names {
		if pods[1].names[name] && !strings.HasPrefix(name, "configmap:") {
			t.Errorf("both projects' Pods mount %s", name)
		}
	}
	if strings.Contains(pods[0].raw, "/srv/api") || strings.Contains(pods[1].raw, "/srv/web") {
		t.Error("one project's Pod names the other project")
	}
}
