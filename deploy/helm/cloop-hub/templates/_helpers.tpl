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
