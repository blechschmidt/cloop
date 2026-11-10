# The one image tests/kubecontroller (Task 20487) runs everywhere in the
# cluster: the executor controller the chart installs (its Deployment passes
# only arguments, so cloop is the entrypoint), every runner Pod the controller
# starts (the controller names `cloop` as their command), and the Pods the test
# reads the runners' volumes with.
#
# cloop under test, git for the probes, and the deterministic stand-in for the
# claude CLI (scripts/e2e/gitproxy/claude), which runs the probe a task
# carries, so a run needs no Claude login. pool_test.go assembles the context
# and loads the image onto the nodes.
ARG BASE=alpine:3.20
FROM ${BASE}
RUN apk add --no-cache git ca-certificates
# The test copies both in mode 0755, which COPY keeps: no layer of their own
# for a chmod, which would hold the binary a second time.
COPY cloop claude /usr/local/bin/
# Runner Pods run as 65532 with a read-only root; the controller mounts what
# they write. The chart's controller Pods run as the same user.
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/cloop"]
