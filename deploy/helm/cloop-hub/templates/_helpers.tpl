{{/*
Name helpers — the standard Helm set, plus one thing worth reading:
cloop-hub.serviceAccountName is referenced by both the Deployment and the
RoleBinding, and the RoleBinding lands in a *different* namespace than the
ServiceAccount. Getting the name from one place is what keeps those two in
agreement when a release is renamed.
*/}}

{{- define "cloop-hub.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "cloop-hub.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "cloop-hub.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "cloop-hub.labels" -}}
helm.sh/chart: {{ include "cloop-hub.chart" . }}
{{ include "cloop-hub.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: control-plane
{{- end -}}

{{- define "cloop-hub.selectorLabels" -}}
app.kubernetes.io/name: {{ include "cloop-hub.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
cloop-hub.coexist is "true" when two hub Pods can run at once: more than one
replica, or a rolling update that starts the new Pod before stopping the old.
Both then have to reach the same SQLite database, which is what the storage
refusals in _validate.tpl and the co-location term in deployment.yaml key on.
*/}}
{{- define "cloop-hub.coexist" -}}
{{- if or (gt (int .Values.replicaCount) 1) (eq (toString (dig "type" "" (default dict .Values.strategy))) "RollingUpdate") -}}
true
{{- end -}}
{{- end -}}

{{- define "cloop-hub.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "cloop-hub.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "cloop-hub.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{/*
The registry host image.repository pulls from — the default allowlist for
sandbox.image_policy.

"The project's own registry" is the safe default because it is the one registry
the operator has already decided to trust: it is where the hub's own image comes
from, so a compromise there is not made worse by letting a project pull from it
too. Anything else is a registry nobody in this deployment has vouched for.

The heuristic is the one every container runtime uses: the first path component
is a host only if it looks like one. "ghcr.io/acme/cloop" yields ghcr.io;
"acme/cloop" has no registry component and means Docker Hub.
*/}}
{{- define "cloop-hub.imageRegistry" -}}
{{- $first := .Values.image.repository | splitList "/" | first -}}
{{- if or (contains "." $first) (contains ":" $first) (eq $first "localhost") -}}
{{- $first -}}
{{- else -}}
docker.io
{{- end -}}
{{- end -}}

{{/*
The Secret the Deployment reads its environment from. Exactly one of
existingSecret and create may be set; validation lives in secret.yaml so the
failure names the field rather than appearing as a missing envFrom.
*/}}
{{- define "cloop-hub.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-secrets" (include "cloop-hub.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
The namespace workload Pods are created in. Defaults to the release namespace
only if the operator explicitly emptied it — which co-locates model-authored
workloads with the hub's own Secrets, so NOTES.txt says so out loud.
*/}}
{{- define "cloop-hub.workloadNamespace" -}}
{{- default .Release.Namespace .Values.executor.kubernetes.namespace -}}
{{- end -}}

{{/*
The credential monitors (Task 20385): the git interception proxy and the
Kubernetes access monitor, two TLS listeners in the hub process. Everything
about them — the ports, the URLs sandboxes are pointed at, where their
certificate and its CA come from — is derived here once, because the
ConfigMap, the Deployment, the Service and the CA ConfigMaps all have to agree.
*/}}

{{/*
The monitors' values, each merged over its defaults and returned as JSON (read
with `include … | fromJson`). Templates read these, never
.Values.executor.gitProxy and friends directly: `helm upgrade --reuse-values`
renders with the *previous* release's chart defaults, and a release installed
from a chart before 0.3.0 has no executor.gitProxy, executor.kubeGuard or
executor.monitorTLS at all — a direct read is a nil-pointer error, and an
absent port would render as 0. The defaults are values.yaml's; CI renders the
chart with those sections deleted to keep the two in step.
*/}}
{{- define "cloop-hub.gitProxy" -}}
{{- $d := dict "enabled" false "port" 8443 "advertiseURL" "" "sessionMinutes" 0 "allowedRefs" (list) "allowDelete" false -}}
{{- toJson (mergeOverwrite $d (deepCopy (default dict .Values.executor.gitProxy))) -}}
{{- end -}}

{{- define "cloop-hub.kubeGuard" -}}
{{- $d := dict "enabled" false "port" 8444 "advertiseURL" "" "sessionMinutes" 0 "verbs" (list) "namespaces" (list) "resources" (list) "auditAllowed" false -}}
{{- toJson (mergeOverwrite $d (deepCopy (default dict .Values.executor.kubeGuard))) -}}
{{- end -}}

{{- define "cloop-hub.monitorTLS" -}}
{{- $d := dict "existingSecret" "" "selfSigned" false "caBundle" "" "workloadCAConfigMap" "" "workloadCAKey" "ca.crt" "publiclyTrusted" false -}}
{{- toJson (mergeOverwrite $d (deepCopy (default dict .Values.executor.monitorTLS))) -}}
{{- end -}}

{{/* "true" when either monitor is on. */}}
{{- define "cloop-hub.monitorsEnabled" -}}
{{- $gp := include "cloop-hub.gitProxy" . | fromJson -}}
{{- $kg := include "cloop-hub.kubeGuard" . | fromJson -}}
{{- if or $gp.enabled $kg.enabled -}}
true
{{- end -}}
{{- end -}}

{{/*
The in-cluster name both monitors are advertised under by default. Fully
qualified to the Service, not to cluster.local: the cluster domain is a kubelet
setting the chart cannot read, and every Pod's resolver completes <svc>.<ns>.svc.
*/}}
{{- define "cloop-hub.serviceHost" -}}
{{- printf "%s.%s.svc" (include "cloop-hub.fullname" .) .Release.Namespace -}}
{{- end -}}

{{- define "cloop-hub.gitProxyURL" -}}
{{- $gp := include "cloop-hub.gitProxy" . | fromJson -}}
{{- $u := trimSuffix "/" (toString (default "" $gp.advertiseURL)) -}}
{{- if $u -}}
{{- $u -}}
{{- else -}}
{{- printf "https://%s:%d" (include "cloop-hub.serviceHost" .) (int $gp.port) -}}
{{- end -}}
{{- end -}}

{{- define "cloop-hub.kubeGuardURL" -}}
{{- $kg := include "cloop-hub.kubeGuard" . | fromJson -}}
{{- $u := trimSuffix "/" (toString (default "" $kg.advertiseURL)) -}}
{{- if $u -}}
{{- $u -}}
{{- else -}}
{{- printf "https://%s:%d" (include "cloop-hub.serviceHost" .) (int $kg.port) -}}
{{- end -}}
{{- end -}}

{{/* The Secret holding the monitors' certificate and key. */}}
{{- define "cloop-hub.monitorTLSSecretName" -}}
{{- $t := include "cloop-hub.monitorTLS" . | fromJson -}}
{{- default (printf "%s-monitor-tls" (include "cloop-hub.fullname" .)) $t.existingSecret -}}
{{- end -}}

{{/*
The ConfigMap the chart writes the monitors' CA into: in the release namespace
for the hub (the kube guard embeds it in every kubeconfig it issues) and in the
workload namespace for the Pods' git. Same name in both.
*/}}
{{- define "cloop-hub.monitorCAName" -}}
{{- printf "%s-monitor-ca" (include "cloop-hub.fullname" .) -}}
{{- end -}}

{{/* "true" when the chart itself knows the CA's PEM: it generated it, or was given it. */}}
{{- define "cloop-hub.monitorCAKnown" -}}
{{- $t := include "cloop-hub.monitorTLS" . | fromJson -}}
{{- if or $t.selfSigned $t.caBundle -}}
true
{{- end -}}
{{- end -}}

{{/*
The ConfigMap in the workload namespace a Pod's git reads the proxy's CA from,
as "name/key"; empty when nothing is delivered (a publicly trusted certificate,
or no git proxy).
*/}}
{{- define "cloop-hub.workloadGitCA" -}}
{{- $t := include "cloop-hub.monitorTLS" . | fromJson -}}
{{- $gp := include "cloop-hub.gitProxy" . | fromJson -}}
{{- if and $gp.enabled (not $t.publiclyTrusted) -}}
{{- if include "cloop-hub.monitorCAKnown" . -}}
{{- printf "%s/ca.crt" (include "cloop-hub.monitorCAName" .) -}}
{{- else if $t.workloadCAConfigMap -}}
{{- printf "%s/%s" $t.workloadCAConfigMap (default "ca.crt" $t.workloadCAKey) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
The DNS names the monitors' certificate must carry: the Service in every form a
resolver completes, plus the host of any advertise URL set by hand.
*/}}
{{- define "cloop-hub.monitorDNSNames" -}}
{{- $svc := include "cloop-hub.fullname" . -}}
{{- $ns := .Release.Namespace -}}
{{- $names := list $svc (printf "%s.%s" $svc $ns) (printf "%s.%s.svc" $svc $ns) (printf "%s.%s.svc.cluster.local" $svc $ns) -}}
{{- $gp := include "cloop-hub.gitProxy" . | fromJson -}}
{{- $kg := include "cloop-hub.kubeGuard" . | fromJson -}}
{{- range $u := list $gp.advertiseURL $kg.advertiseURL -}}
{{- if $u -}}
{{- $host := regexReplaceAll "^https://([^/:]+).*$" $u "${1}" -}}
{{- if and $host (not (has $host $names)) -}}
{{- $names = append $names $host -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- join "," $names -}}
{{- end -}}
