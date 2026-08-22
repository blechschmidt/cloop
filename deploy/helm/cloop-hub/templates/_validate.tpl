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

{{/* --- storage -------------------------------------------------------- */}}
{{- if and (not .Values.persistence.enabled) .Values.persistence.existingClaim }}
{{- fail "persistence.existingClaim is set but persistence.enabled is false, so the claim would be ignored and the hub would run on an emptyDir — discarding every project, task and sealed secret on restart, while appearing to use your volume." }}
{{- end }}

{{- end -}}
