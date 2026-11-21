#!/usr/bin/env bash
#
# Put images the local Docker daemon holds on every node of a kind cluster,
# whichever image store the daemon uses.
#
#   scripts/kind-load-image.sh CLUSTER IMAGE...
#
# `kind load docker-image` saves an image with a plain `docker save` and has
# each node import the archive with `ctr images import --all-platforms`. Under
# Docker's containerd image store, which a fresh Docker 29 uses by default and
# GitHub's Ubuntu 26 runners therefore do, an image pulled by a multi-platform
# index keeps the whole index but only the daemon's own platform's content. The
# archive then names blobs it does not hold, and every node refuses it:
#
#   ctr: content digest sha256:…: not found
#
# That turned CI's Deployment artifacts job red on every push from 2026-11-17
# (Task 20510). An archive of the daemon's own platform alone (`docker save
# --platform`, Docker 28 or later) holds every blob it names, from either
# store, and `kind load image-archive` imports it with the same command.
#
# The Go end-to-end tests that load images into kind (tests/kube,
# tests/kubecontroller) do the same; tests/ciscripts fails a plain
# `kind load docker-image` anywhere CI runs one.

set -euo pipefail

if [ $# -lt 2 ]; then
	echo "usage: kind-load-image.sh CLUSTER IMAGE..." >&2
	exit 2
fi
cluster=$1
shift

# The platform the daemon runs on, as Go names it ("linux/amd64"): what it
# pulled and built for, and what the cluster's nodes, its containers, run.
platform=$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}')

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

for image in "$@"; do
	docker save --platform "$platform" -o "$tmp/image.tar" "$image"
	kind load image-archive "$tmp/image.tar" --name "$cluster"
	rm -f "$tmp/image.tar"
	echo "kind-load-image: $image ($platform) is on every node of $cluster"
done
