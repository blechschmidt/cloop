{{/*
Name helpers. The controller's ServiceAccount is referenced by the Deployment
and the RoleBinding, the runner ServiceAccount by the ExecutorPool and by the
check that keeps the two apart; each name comes from one place here.
*/}}

{{- define "cloop-executor-controller.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "cloop-executor-controller.fullname" -}}
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

{{- define "cloop-executor-controller.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Labels. Nothing here is app.kubernetes.io/managed-by=cloop-executor-controller:
that is the label the controller selects its runners' Pods, Secrets and
volumes by, and an object of the chart's carrying it would be taken for one.
*/}}
{{- define "cloop-executor-controller.labels" -}}
helm.sh/chart: {{ include "cloop-executor-controller.chart" . }}
{{ include "cloop-executor-controller.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: executor-controller
app.kubernetes.io/part-of: cloop
{{- end -}}

{{- define "cloop-executor-controller.selectorLabels" -}}
app.kubernetes.io/name: {{ include "cloop-executor-controller.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "cloop-executor-controller.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "cloop-executor-controller.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* The runner ServiceAccount's name; empty when none is created or named. */}}
{{- define "cloop-executor-controller.runnerServiceAccountName" -}}
{{- if .Values.runnerServiceAccount.create -}}
{{- default (printf "%s-runner" (include "cloop-executor-controller.fullname" . | trunc 56 | trimSuffix "-")) .Values.runnerServiceAccount.name -}}
{{- else -}}
{{- .Values.runnerServiceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
The controller's image. With image.digest it is repository@digest and the tag
is left out: both forms pull the same bytes, but only the digest says which.
*/}}
{{- define "cloop-executor-controller.image" -}}
{{- $digest := toString (default "" .Values.image.digest) -}}
{{- if $digest -}}
{{- printf "%s@%s" .Values.image.repository $digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (toString (default .Chart.AppVersion .Values.image.tag)) -}}
{{- end -}}
{{- end -}}

{{/* A content digest, as image references carry them. */}}
{{- define "cloop-executor-controller.digestPattern" -}}
^(sha256:[a-f0-9]{64}|sha512:[a-f0-9]{128})$
{{- end -}}

{{/* "true" when the controller's image reference names a digest. */}}
{{- define "cloop-executor-controller.imagePinned" -}}
{{- $ref := include "cloop-executor-controller.image" . -}}
{{- if regexMatch (printf "@%s" (trimPrefix "^" (include "cloop-executor-controller.digestPattern" .))) $ref -}}
true
{{- end -}}
{{- end -}}

{{/*
cloop's own image repositories, as JSON: imagepolicy.OwnRepositories, which
pkg/kubecontroller/helm_test.go holds this list equal to. The controller
resolves one of them named by tag to a digest and verifies it, like its
default runner image.
*/}}
{{- define "cloop-executor-controller.ownRepositories" -}}
["ghcr.io/blechschmidt/cloop","ghcr.io/blechschmidt/cloop-harness","ghcr.io/blechschmidt/cloop-harness-copilot"]
{{- end -}}

{{/* A Go duration ("1m30s", "500ms") in seconds; 0 for anything else. */}}
{{- define "cloop-executor-controller.seconds" -}}
{{- $unit := dict "ns" 0.000000001 "us" 0.000001 "ms" 0.001 "s" 1.0 "m" 60.0 "h" 3600.0 -}}
{{- $total := 0.0 -}}
{{- range $part := regexFindAll "[0-9]+(\\.[0-9]+)?(ns|us|ms|s|m|h)" (toString .) -1 -}}
{{- $num := regexFind "^[0-9]+(\\.[0-9]+)?" $part -}}
{{- $total = addf $total (mulf (float64 $num) (get $unit (trimPrefix $num $part))) -}}
{{- end -}}
{{- $total -}}
{{- end -}}

{{/*
The pool's scale-down delay as the CRD takes it: 5m when unset, and a bare 0
as 0s. `default` would turn 0, a delay an operator may mean, into 5m.
*/}}
{{- define "cloop-executor-controller.scaleDownDelay" -}}
{{- $d := .Values.pool.scaleDownDelay -}}
{{- if kindIs "invalid" $d -}}
5m
{{- else if eq (toString $d) "0" -}}
0s
{{- else -}}
{{- toString $d -}}
{{- end -}}
{{- end -}}

{{/* The ports the DNS rule opens, as JSON: 53 unless networkPolicy.dns.ports says. */}}
{{- define "cloop-executor-controller.dnsPorts" -}}
{{- $dns := default dict .Values.networkPolicy.dns -}}
{{- if hasKey $dns "ports" -}}
{{- toJson (default list $dns.ports) -}}
{{- else -}}
[53]
{{- end -}}
{{- end -}}

{{/*
A map of labels, annotations or node labels with every key and value a JSON
string, one per line. A value set with --set arrives as a number or a boolean
(tier=1, gpu=true), which the API refuses where it wants a string, and a
quoted string reads back as exactly what it holds, newlines included.
*/}}
{{- define "cloop-executor-controller.stringMap" -}}
{{- range $k, $v := . }}
{{ toJson (toString $k) }}: {{ toJson (toString $v) }}
{{- end }}
{{- end -}}

{{/* The pool created from values, and the Secret its credential is in. */}}
{{- define "cloop-executor-controller.poolName" -}}
{{- default (include "cloop-executor-controller.fullname" .) .Values.pool.name -}}
{{- end -}}

{{- define "cloop-executor-controller.credentialSecretName" -}}
{{- if .Values.pool.credential.existingSecret -}}
{{- .Values.pool.credential.existingSecret -}}
{{- else -}}
{{- printf "%s-pool-credential" (include "cloop-executor-controller.fullname" . | trunc 47 | trimSuffix "-") -}}
{{- end -}}
{{- end -}}

{{/* The key the credential is under: the chart's own Secret always uses "credential". */}}
{{- define "cloop-executor-controller.credentialKey" -}}
{{- if .Values.pool.credential.existingSecret -}}
{{- default "credential" .Values.pool.credential.key -}}
{{- else -}}
credential
{{- end -}}
{{- end -}}
