{{/*
Render-time refusals, included first by deployment.yaml so they hold whatever
else is switched off. Each fails the render with the field to change: a value
the controller would refuse at runtime shows here instead of as a Pod that
crash-loops, a pool that stays Invalid, or a runner that can never reach its
hub.
*/}}
{{- define "cloop-executor-controller.validate" -}}
{{- $dns1123 := "^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$" }}
{{- $duration := "^([0-9]+(\\.[0-9]+)?(ns|us|ms|s|m|h))+$" }}

{{/* --- images ------------------------------------------------------- */}}
{{- with .Values.image.digest }}
{{- if not (regexMatch (include "cloop-executor-controller.digestPattern" $) (toString .)) }}
{{- fail (printf "image.digest %q is not a content digest: it is sha256: and 64 lowercase hex digits (or sha512: and 128), as `docker buildx imagetools inspect` or `crane digest` print it." (toString .)) }}
{{- end }}
{{- end }}
{{- if .Values.requireDigest }}
{{- if not (include "cloop-executor-controller.imagePinned" .) }}
{{- fail (printf "requireDigest is true but the controller's image is %s, a tag. Set image.digest to the digest that tag names (sha256:…), so the Pods run that artifact whatever the registry later points the tag at." (include "cloop-executor-controller.image" .)) }}
{{- end }}
{{- if .Values.pool.create }}
{{- with .Values.pool.template.image }}
{{- $img := toString . }}
{{/*
  As the controller decides it under --require-image-digest: a digest, or one
  of cloop's own repositories by tag, which the controller resolves at the
  registry and verifies like the empty default. ownRepositories is
  imagepolicy.OwnRepositories; helm_test.go holds the two equal.
*/}}
{{- $name := regexReplaceAll ":[^:/@]+$" (regexReplaceAll "@.*$" $img "") "" }}
{{- $own := has $name (include "cloop-executor-controller.ownRepositories" $ | fromJsonArray) }}
{{- if not (or $own (regexMatch (printf "@%s" (trimPrefix "^" (include "cloop-executor-controller.digestPattern" $))) $img)) }}
{{- fail (printf "requireDigest is true but pool.template.image %q is not pinned by digest. Name it as repository@sha256:…, or leave it empty for cloop's harness image, which the controller resolves to a digest and verifies." $img) }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}

{{/* --- replicas and leader election ----------------------------------- */}}
{{- $replicas := int .Values.replicaCount }}
{{- if lt $replicas 0 }}
{{- fail "replicaCount cannot be negative." }}
{{- end }}
{{- if and (gt $replicas 1) (not .Values.leaderElection.enabled) }}
{{- fail (printf "replicaCount is %d but leaderElection.enabled is false: every replica would lead, and each would start runners for the same demand. Enable leader election, or run one replica." $replicas) }}
{{- end }}
{{- if .Values.leaderElection.enabled }}
{{- if not (regexMatch $dns1123 (toString .Values.leaderElection.leaseName)) }}
{{- fail (printf "leaderElection.leaseName %q is not a lowercase RFC 1123 name." (toString .Values.leaderElection.leaseName)) }}
{{- end }}
{{- end }}

{{/* --- controller flags ------------------------------------------------ */}}
{{- $prov := toString .Values.controller.imageProvenance }}
{{- if not (has $prov (list "warn" "required")) }}
{{- fail (printf "controller.imageProvenance must be warn or required (got %q)." $prov) }}
{{- end }}
{{- $port := int .Values.controller.healthPort }}
{{- if or (lt $port 1) (gt $port 65535) }}
{{- fail (printf "controller.healthPort %d is not a TCP port." $port) }}
{{- end }}
{{- $resync := toString .Values.controller.resync }}
{{- if not (regexMatch $duration $resync) }}
{{- fail (printf "controller.resync %q is not a duration such as 5m (at least 30s)." $resync) }}
{{- end }}
{{- if lt (include "cloop-executor-controller.seconds" $resync | float64) 30.0 }}
{{- fail (printf "controller.resync %q is under 30s, the least the controller accepts: it would exit at start." $resync) }}
{{- end }}
{{- if lt (int .Values.controller.workers) 1 }}
{{- fail "controller.workers must be at least 1." }}
{{- end }}

{{/* --- service accounts ----------------------------------------------- */}}
{{- $controllerSA := include "cloop-executor-controller.serviceAccountName" . }}
{{- $runnerSA := include "cloop-executor-controller.runnerServiceAccountName" . }}
{{- if and (not .Values.serviceAccount.create) (not .Values.serviceAccount.name) }}
{{- fail "serviceAccount.create is false and serviceAccount.name is empty, so the controller would run as the namespace's \"default\" ServiceAccount and its RoleBinding would name it — handing every Pod here that names no account the controller's authority, Secrets included.\nSet serviceAccount.name to an account made for the controller." }}
{{- end }}
{{- if eq $controllerSA "default" }}
{{- fail "the controller's ServiceAccount is the namespace's \"default\", which every Pod here that names no account runs as: binding the controller's Role to it would hand them all its authority, Secrets included. Name an account made for the controller." }}
{{- end }}
{{- if not (regexMatch $dns1123 $controllerSA) }}
{{- fail (printf "the controller's ServiceAccount name %q is not a lowercase RFC 1123 name." $controllerSA) }}
{{- end }}
{{- if not $runnerSA }}
{{- fail "runnerServiceAccount.create is false and runnerServiceAccount.name is empty: runners would run as the namespace's \"default\" ServiceAccount, which other workloads share. Create the runner account, or name one made for runners." }}
{{- end }}
{{- if not (regexMatch $dns1123 $runnerSA) }}
{{- fail (printf "the runner ServiceAccount name %q is not a lowercase RFC 1123 name." $runnerSA) }}
{{- end }}
{{- if eq $runnerSA $controllerSA }}
{{- fail (printf "the runner ServiceAccount and the controller's are both %q. Runners run model-authored code and must never hold the account that can read this namespace's Secrets; the controller refuses such a pool too." $runnerSA) }}
{{- end }}
{{- if eq $runnerSA "default" }}
{{- fail "the runner ServiceAccount is the namespace's \"default\", which other workloads share. Create the runner account, or name one made for runners." }}
{{- end }}

{{/* --- the pool's credential -------------------------------------------- */}}
{{- $cred := .Values.pool.credential }}
{{- if and $cred.existingSecret $cred.value }}
{{- fail "pool.credential.existingSecret and pool.credential.value are mutually exclusive: one names your Secret, the other has the chart write one. Pick one." }}
{{- end }}
{{- with $cred.value }}
{{- if not (regexMatch "^cloop_pool1_[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$" (trim (toString .))) }}
{{- fail "pool.credential.value is not a pool controller credential (cloop_pool1_<id>.<secret>), which the hub prints once when it mints one." }}
{{- end }}
{{- end }}
{{- if $cred.existingSecret }}
{{- if not (regexMatch $dns1123 (toString $cred.existingSecret)) }}
{{- fail (printf "pool.credential.existingSecret %q is not a lowercase RFC 1123 name." (toString $cred.existingSecret)) }}
{{- end }}
{{- if not (regexMatch "^[-._a-zA-Z0-9]+$" (toString (default "credential" $cred.key))) }}
{{- fail (printf "pool.credential.key %q is not a Secret key." (toString $cred.key)) }}
{{- end }}
{{- end }}

{{/* --- the pool ------------------------------------------------------- */}}
{{- if .Values.pool.create }}
{{- $p := .Values.pool }}
{{- if not (regexMatch $dns1123 (include "cloop-executor-controller.poolName" .)) }}
{{- fail (printf "pool.name %q is not a lowercase RFC 1123 name." (include "cloop-executor-controller.poolName" .)) }}
{{- end }}
{{- if not $p.hubURL }}
{{- fail "pool.create is true but pool.hubURL is empty: the controller would not know which hub to ask for runners. Set it to the hub's https base URL." }}
{{- end }}
{{- if not (regexMatch "^https://[^/?#@[:space:]]+(/[^?#[:space:]]*)?$" (toString $p.hubURL)) }}
{{- fail (printf "pool.hubURL %q must be an https URL with no user, query or fragment: the pool credential and every runner token travel on it." (toString $p.hubURL)) }}
{{- end }}
{{- with $p.hubCABundle }}
{{- if not (contains "-----BEGIN CERTIFICATE-----" (toString .)) }}
{{- fail "pool.hubCABundle holds no PEM certificate (no BEGIN CERTIFICATE line). It is the CA the hub's certificate chains to, as PEM." }}
{{- end }}
{{- end }}
{{- if not (or $cred.existingSecret $cred.value) }}
{{- fail "pool.create is true but the pool has no credential: set pool.credential.existingSecret to a Secret holding it, or pool.credential.value to have the chart write one. Mint it on the hub for the pool first." }}
{{- end }}
{{- $max := int $p.maxRunners }}
{{- $min := int (default 0 $p.minRunners) }}
{{- if or (lt $max 1) (gt $max 1000) }}
{{- fail (printf "pool.maxRunners %d must be between 1 and 1000." $max) }}
{{- end }}
{{- if or (lt $min 0) (gt $min $max) }}
{{- fail (printf "pool.minRunners %d must be between 0 and pool.maxRunners (%d)." $min $max) }}
{{- end }}
{{- $credSecret := include "cloop-executor-controller.credentialSecretName" . }}
{{- range $i, $e := (default list $p.template.env) }}
{{- if eq (toString (dig "secretKeyRef" "name" "" $e)) $credSecret }}
{{- fail (printf "pool.template.env[%d] (%s) reads the Secret %q, which holds the pool's controller credential: a runner is never given it." $i (toString $e.name) $credSecret) }}
{{- end }}
{{- end }}
{{- if not (regexMatch $duration (include "cloop-executor-controller.scaleDownDelay" .)) }}
{{- fail (printf "pool.scaleDownDelay %q is not a duration such as 5m or 90s." (include "cloop-executor-controller.scaleDownDelay" .)) }}
{{- end }}
{{- $persist := default dict $p.persistence }}
{{- if $persist.enabled }}
{{- if not $persist.size }}
{{- fail "pool.persistence.enabled is true but pool.persistence.size is empty." }}
{{- end }}
{{- if not (kindIs "invalid" $persist.maxClaims) }}
{{- if lt (int $persist.maxClaims) $max }}
{{- fail (printf "pool.persistence.maxClaims %d is fewer than pool.maxRunners (%d): every runner needs a volume of its own. Leave it empty to take maxRunners." (int $persist.maxClaims) $max) }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}

{{/* --- the runner NetworkPolicy ----------------------------------------- */}}
{{- if .Values.networkPolicy.enabled }}
{{- $hub := .Values.networkPolicy.hub }}
{{- $dns := .Values.networkPolicy.dns }}
{{- if not (or $hub.namespaceSelector $hub.podSelector $hub.cidrs) }}
{{- fail "networkPolicy.enabled is true but networkPolicy.hub names no destination, so the policy would refuse the hub too and no runner could ever enroll. Select the hub's Pods (networkPolicy.hub.namespaceSelector / podSelector) or give its addresses (networkPolicy.hub.cidrs)." }}
{{- end }}
{{- if not $hub.ports }}
{{- fail "networkPolicy.hub.ports is empty: name the hub's API port (8080 in the cloop-hub chart) and its git proxy's (8443)." }}
{{- end }}
{{- range $hub.ports }}
{{- if or (lt (int .) 1) (gt (int .) 65535) }}
{{- fail (printf "networkPolicy.hub.ports has %v, which is not a TCP port." .) }}
{{- end }}
{{- end }}
{{- range $c := concat (default list $hub.cidrs) (default list $dns.cidrs) }}
{{- if not (regexMatch "^[0-9a-fA-F:.]+/[0-9]{1,3}$" (toString $c)) }}
{{- fail (printf "networkPolicy CIDR %q is not an address range such as 10.0.0.0/8." (toString $c)) }}
{{- end }}
{{- if hasSuffix "/0" (toString $c) }}
{{- fail (printf "networkPolicy CIDR %q is every address, which would leave the runners nothing they cannot reach. Name the hub's addresses." (toString $c)) }}
{{- end }}
{{- end }}
{{- if not (or $dns.namespaceSelector $dns.podSelector $dns.cidrs) }}
{{- fail "networkPolicy.dns names no resolver, so runners could not resolve the hub's name. Keep the kube-system namespaceSelector, or name your resolvers in networkPolicy.dns.cidrs." }}
{{- end }}
{{- if not (include "cloop-executor-controller.dnsPorts" . | fromJsonArray) }}
{{- fail "networkPolicy.dns.ports is empty: name the port the DNS Pods listen on (53, or 5353 on OpenShift)." }}
{{- end }}
{{- range include "cloop-executor-controller.dnsPorts" . | fromJsonArray }}
{{- if or (lt (int .) 1) (gt (int .) 65535) }}
{{- fail (printf "networkPolicy.dns.ports has %v, which is not a port." .) }}
{{- end }}
{{- end }}
{{- end }}

{{- end -}}
