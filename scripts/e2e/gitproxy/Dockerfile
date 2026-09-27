# The sandbox image for the git proxy probe: the published harness image with
# the cloop under test and the deterministic stand-in for the claude CLI.
#
#   cp "$(command -v cloop)" scripts/e2e/gitproxy/cloop    # the build to test
#   docker build -t cloop-harness:gitproxy-probe scripts/e2e/gitproxy
#
# Build it on the device: a virtual executor names a local image.
ARG BASE=ghcr.io/blechschmidt/cloop-harness:latest
FROM ${BASE}
USER root
# The base image's claude is a symlink; replace the link, not what it points to.
RUN rm -f /usr/local/bin/claude
COPY cloop /usr/local/bin/cloop
COPY claude /usr/local/bin/claude
RUN chmod 0755 /usr/local/bin/cloop /usr/local/bin/claude
USER 65532:65532
