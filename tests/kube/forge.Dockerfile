# The test forge for tests/kube (Task 20385): pkg/secretbroker/secretbrokertest's
# git smart-HTTP forge, served over TLS by ./forge, with the git and
# git-http-backend it drives. kube_test.go builds it from a context holding the
# static forge binary and loads it into kind; it is never pushed.
ARG BASE=alpine:3.20
FROM ${BASE}
RUN apk add --no-cache git git-daemon
COPY forge /usr/local/bin/forge
RUN chmod 0755 /usr/local/bin/forge
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/forge"]
