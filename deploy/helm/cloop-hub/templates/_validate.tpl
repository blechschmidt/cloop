{{/*
Render-time refusals.

These live in their own template, included first thing by deployment.yaml,
because a guard that sits inside a conditionally-rendered file is a guard that
disappears exactly when someone turns that file off. The OIDC-issuer check
used to live in configmap.yaml, which meant `--set config.fromConfigMap=false
--set oidc.enabled=true` rendered clean and produced a hub with SSO "enabled"
and no issuer.

Everything here fails the render rather than warning. A warning during
`helm install` scrolls past; a hub that is open scrolls past too, for longer.
*/}}
{{- define "cloop-hub.validate" -}}

{{/* --- secrets ------------------------------------------------------- */}}
{{- if and .Values.secrets.create .Values.secrets.existingSecret }}
{{- fail "secrets.create and secrets.existingSecret are mutually exclusive: one generates a Secret from values, the other points at yours. Pick one." }}
{{- end }}

{{- if not (or .Values.secrets.create .Values.secrets.existingSecret) }}
{{- fail "no secret source configured. CLOOP_SECRET_KEY protects every brokered credential and CLOOP_UI_TOKEN is what keeps the dashboard closed before SSO exists; the hub must not start without them.\nSet secrets.existingSecret to a Secret you created, or secrets.create=true for evaluation." }}
{{- end }}

{{- if .Values.secrets.create }}
{{- if not .Values.secrets.secretKey }}
{{- fail "secrets.create is true but secrets.secretKey is empty. This is the secret broker's master key; generate one with:\n  head -c32 /dev/urandom | base64 | tr -d '='" }}
{{- end }}
{{/*
  Without OIDC the bearer token is the *only* thing between the network and
  the dashboard. An empty one is not "no token configured", it is
  authentication switched off: cloop treats an empty Server.Token as "no auth
  required" and serves /api/state to anyone who can route to the port. The
  chart used to render this happily, and NOTES.txt then told the operator to
  read a token that did not exist.
*/}}
{{- if and (not .Values.oidc.enabled) (not .Values.secrets.uiToken) }}
{{- fail "secrets.create is true, oidc.enabled is false, and secrets.uiToken is empty — that installs a hub with NO authentication at all.\nEither set secrets.uiToken:\n  head -c32 /dev/urandom | base64 | tr -d '='\nor enable oidc." }}
{{- end }}
{{- end }}

{{/* --- oidc ---------------------------------------------------------- */}}
{{- if .Values.oidc.enabled }}
{{- if not .Values.oidc.issuer }}
{{- fail "oidc.enabled is true but oidc.issuer is empty. Discovery has nowhere to go, and the hub refuses to start rather than silently falling back to token auth." }}
{{- end }}
{{- if not .Values.config.fromConfigMap }}
{{- fail "oidc.enabled is true but config.fromConfigMap is false, so no OIDC settings reach the hub at all — it would start with SSO off and this chart would report it as on.\nSet config.fromConfigMap=true, or configure OIDC in the config the hub keeps on its volume." }}
{{- end }}
{{- end }}

{{/* --- service account ----------------------------------------------- */}}
{{/*
  serviceAccount.create=false with rbac.create=true used to bind the executor
  Role to the namespace's "default" ServiceAccount — granting pod
  create/delete in the workload namespace to every Pod in this namespace that
  does not name a ServiceAccount. Silent, and exactly backwards.
*/}}
{{- if and .Values.executor.kubernetes.enabled .Values.executor.kubernetes.rbac.create }}
{{- if and (not .Values.serviceAccount.create) (not .Values.serviceAccount.name) }}
{{- fail "serviceAccount.create is false and serviceAccount.name is empty, so the executor RoleBinding would target the namespace's \"default\" ServiceAccount — granting Pod create/delete in the workload namespace to every Pod here that does not name one.\nSet serviceAccount.name to the account the hub actually runs as." }}
{{- end }}
{{- end }}

{{- if and .Values.executor.kubernetes.enabled (not .Values.serviceAccount.automountServiceAccountToken) }}
{{- fail "executor.kubernetes.enabled is true but serviceAccount.automountServiceAccountToken is false. In-cluster mode authenticates with the projected token; without it the executor cannot start anything." }}
{{- end }}

{{/* --- replicas -------------------------------------------------------
  Every replica is a member of one hub cluster serving one SQLite database
  (docs/architecture/hub-cluster.md). What makes that work is the shared
  database, so the refusals are about storage: a Pod on its own emptyDir is a
  separate hub with a separate database, and a volume only one Pod may mount
  leaves the others unable to start. SQLite's WAL additionally needs every
  process on one kernel; deployment.yaml pins the replicas to one node for that.
*/}}
{{- if include "cloop-hub.coexist" . }}
{{- if not .Values.persistence.enabled }}
{{- fail "more than one hub Pod can run at once (replicaCount > 1, or strategy.type=RollingUpdate), but persistence.enabled is false — each Pod would get its own emptyDir and so its own database: separate hubs behind one Service, each showing a different set of projects and runs.\nEnable persistence so the replicas share one volume." }}
{{- end }}
{{- if eq .Values.persistence.accessMode "ReadWriteOncePod" }}
{{- fail "more than one hub Pod can run at once, but persistence.accessMode is ReadWriteOncePod: only one of them could mount the volume, and the rest would never start.\nUse ReadWriteOnce — the replicas are pinned to one node, which is what ReadWriteOnce allows." }}
{{- end }}
{{- end }}

{{/* --- credential monitors (Task 20385) -------------------------------
  The git proxy and the kube guard are security controls a sandbox's traffic
  is routed through. Every refusal here is a combination that would render a
  hub whose monitor cannot start, cannot be reached, or cannot be trusted — and
  each of those fails at a sandbox's first clone or first kubectl, far from
  the values file that caused it.
*/}}
{{- $mon := .Values.executor }}
{{- if include "cloop-hub.monitorsEnabled" . }}
{{- if not .Values.config.fromConfigMap }}
{{- fail "executor.gitProxy or executor.kubeGuard is enabled but config.fromConfigMap is false, so neither section reaches the hub: it would start with no monitor and this chart would report one.\nSet config.fromConfigMap=true." }}
{{- end }}
{{- if and $mon.monitorTLS.existingSecret $mon.monitorTLS.selfSigned }}
{{- fail "executor.monitorTLS.existingSecret and executor.monitorTLS.selfSigned are mutually exclusive: one names your certificate, the other has the chart generate one. Pick one." }}
{{- end }}
{{- if not (or $mon.monitorTLS.existingSecret $mon.monitorTLS.selfSigned) }}
{{- fail "executor.gitProxy or executor.kubeGuard is enabled but has no certificate. The session token a sandbox presents rides every request, and cleartext would publish it rather than deliver it — the hub refuses to start a monitor without TLS.\nSet executor.monitorTLS.existingSecret to a kubernetes.io/tls Secret for the Service's names (cert-manager), or executor.monitorTLS.selfSigned=true." }}
{{- end }}
{{- if and $mon.monitorTLS.selfSigned (or $mon.monitorTLS.caBundle $mon.monitorTLS.workloadCAConfigMap $mon.monitorTLS.publiclyTrusted) }}
{{- fail "executor.monitorTLS.selfSigned has the chart generate and deliver its own CA, so caBundle, workloadCAConfigMap and publiclyTrusted would each describe a certificate that is not the one in use. Unset them, or use existingSecret." }}
{{- end }}
{{- with $mon.monitorTLS.caBundle }}
{{- if not (contains "-----BEGIN CERTIFICATE-----" .) }}
{{- fail "executor.monitorTLS.caBundle is not a PEM certificate (no BEGIN CERTIFICATE line). It is the CA that signed the monitors' certificate, as PEM." }}
{{- end }}
{{- end }}
{{- end }}
{{- range $name, $m := dict "gitProxy" $mon.gitProxy "kubeGuard" $mon.kubeGuard }}
{{- if $m.enabled }}
{{- with $m.advertiseURL }}
{{- if not (regexMatch "^https://[^/@?#[:space:]]+/?$" .) }}
{{- fail (printf "executor.%s.advertiseURL %q must be an https:// base URL with no path, query or credentials. It is what a sandbox dials, with a session token on every request: http would publish the token, and a path would be read as part of every repository's." $name .) }}
{{- end }}
{{- end }}
{{- $port := int $m.port }}
{{- if or (lt $port 1) (gt $port 65535) (eq $port 8080) }}
{{- fail (printf "executor.%s.port %d is not usable: it must be a TCP port other than 8080, which the dashboard listens on." $name $port) }}
{{- end }}
{{- $minutes := int (default 0 $m.sessionMinutes) }}
{{- if or (lt $minutes 0) (gt $minutes 720) }}
{{- fail (printf "executor.%s.sessionMinutes %d is outside 0..720. A session is a live credential; one that outlives a working day is indistinguishable from handing the sandbox the credential itself." $name $minutes) }}
{{- end }}
{{- end }}
{{- end }}
{{- if and $mon.gitProxy.enabled $mon.kubeGuard.enabled (eq (int $mon.gitProxy.port) (int $mon.kubeGuard.port)) }}
{{- fail (printf "executor.gitProxy.port and executor.kubeGuard.port are both %d; each monitor needs its own port." (int $mon.gitProxy.port)) }}
{{- end }}
{{- if and $mon.gitProxy.enabled $mon.kubernetes.enabled (not (include "cloop-hub.workloadGitCA" .)) (not $mon.monitorTLS.publiclyTrusted) }}
{{- fail "executor.gitProxy is enabled for the Kubernetes executor, but nothing delivers the proxy's CA to the workload Pods, so every Pod's git would refuse its certificate at the first clone.\nWith executor.monitorTLS.existingSecret, set one of:\n  executor.monitorTLS.caBundle             the CA as PEM; the chart delivers it\n  executor.monitorTLS.workloadCAConfigMap  a ConfigMap you maintain in the workload namespace (trust-manager)\n  executor.monitorTLS.publiclyTrusted=true the certificate chains to a CA the workload image already trusts" }}
{{- end }}
{{- if and $mon.kubernetes.enabled $mon.kubernetes.egressFilter.enabled }}
{{- /* As ints: --set yields int64, a values file float64, and has compares types. */}}
{{- $open := list }}
{{- range $mon.kubernetes.egressFilter.ports }}
{{- $open = append $open (int .) }}
{{- end }}
{{- range $name, $m := dict "gitProxy" $mon.gitProxy "kubeGuard" $mon.kubeGuard }}
{{- if and $m.enabled (not (has (int $m.port) $open)) }}
{{- fail (printf "executor.kubernetes.egressFilter is enabled but its ports do not include executor.%s.port (%d), so a workload Pod could not reach the monitor its credential was routed through.\nAdd %d to executor.kubernetes.egressFilter.ports, and the hub Pods' range (the pod CIDR) to executor.kubernetes.egressFilter.cidrs." $name (int $m.port) (int $m.port)) }}
{{- end }}
{{- end }}
{{- end }}

{{/* --- storage -------------------------------------------------------- */}}
{{- if and (not .Values.persistence.enabled) .Values.persistence.existingClaim }}
{{- fail "persistence.existingClaim is set but persistence.enabled is false, so the claim would be ignored and the hub would run on an emptyDir — discarding every project, task and sealed secret on restart, while appearing to use your volume." }}
{{- end }}

{{- end -}}
