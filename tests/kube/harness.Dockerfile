# The workload image for tests/kube (Task 20385): what the Kubernetes executor
# runs a task in. cloop under test, git, kubectl, and the deterministic
# stand-in for the claude CLI (scripts/e2e/gitproxy/claude), which runs the
# probe carried in the task. kube_test.go assembles the context — the static
# cloop and kubectl binaries and the stand-in — and loads the image into kind.
ARG BASE=alpine:3.20
FROM ${BASE}
RUN apk add --no-cache git ca-certificates
COPY cloop kubectl claude /usr/local/bin/
RUN chmod 0755 /usr/local/bin/cloop /usr/local/bin/kubectl /usr/local/bin/claude
# The Pod's root filesystem is read-only; /tmp is the emptyDir the driver mounts.
ENV HOME=/tmp
USER 65532:65532
