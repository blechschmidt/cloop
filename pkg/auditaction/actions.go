package auditaction

// One constant per registered action.
//
// These are what emission sites reference. Writing the literal again at an
// emission site is what tests/arch/auditaction_test.go exists to catch, so a
// new action means a new constant here and a new entry in registry.go —
// adding one without the other fails the build rather than shipping a name no
// consumer can match.
//
// The constants are grouped and ordered to mirror registry.go. Keeping the two
// files in the same order is not cosmetic: it is how a reviewer reads a diff
// that adds an action and sees both halves of it at once.
const (
	// ── task ───────────────────────────────────────────────────────────────

	// ActionTaskUpsert records a task whose audited fields changed.
	ActionTaskUpsert Action = "task.upsert"
	// ActionTaskDelete records a task leaving the plan.
	ActionTaskDelete Action = "task.delete"
	// ActionTaskStatus records a hand-made status change.
	ActionTaskStatus Action = "task.status"
	// ActionTaskDispatch records a task being handed to an executor.
	ActionTaskDispatch Action = "task.dispatch"
	// ActionTaskFinish records a dispatched task reaching a terminal outcome.
	ActionTaskFinish Action = "task.finish"

	// ── run ────────────────────────────────────────────────────────────────

	// ActionRunCapPaused records a run parked by a Claude Code subscription
	// cap, together with when the window reopens.
	ActionRunCapPaused Action = "run.cap_paused"
	// ActionRunCapResumed records the hub restarting such a run once the
	// window rolled over, with no human involved.
	ActionRunCapResumed Action = "run.cap_resumed"

	// ── step ───────────────────────────────────────────────────────────────

	// ActionStepAppend records one execution step's transcript.
	ActionStepAppend Action = "step.append"

	// ── state / config ─────────────────────────────────────────────────────

	// ActionStateSave records a plan-level state write.
	ActionStateSave Action = "state.save"
	// ActionConfigSet records a configuration write.
	ActionConfigSet Action = "config.set"

	// ── executor ───────────────────────────────────────────────────────────

	// ActionExecutorEnroll records an agent joining the fleet.
	ActionExecutorEnroll Action = "executor.enroll"
	// ActionExecutorRevoke records an agent's credential being revoked.
	ActionExecutorRevoke Action = "executor.revoke"
	// ActionExecutorCordon records an executor being closed to new work.
	ActionExecutorCordon Action = "executor.cordon"
	// ActionExecutorUncordon records a cordoned executor returning to service.
	ActionExecutorUncordon Action = "executor.uncordon"
	// ActionExecutorDrain records an executor being told to shed work.
	ActionExecutorDrain Action = "executor.drain"
	// ActionExecutorBind records a project being pinned to one executor.
	ActionExecutorBind Action = "executor.bind"
	// ActionExecutorUnbind records a project's executor pin being cleared.
	ActionExecutorUnbind Action = "executor.unbind"
	// ActionExecutorSandbox records an executor's sandbox configuration being
	// set: whether its payloads run on the device's host or in a container on
	// it, and under which engine, runtime and image (Task 20307).
	//
	// Auditable because it is a change to a containment boundary, which makes it
	// the one executor setting whose *previous* value a reviewer needs. The
	// payload carries both, so "when did this device stop isolating its
	// workloads, and who decided that" is answerable from the trail alone.
	ActionExecutorSandbox Action = "executor.sandbox"
	// ActionExecutorLimits records an executor's resource ceiling being set:
	// the most CPU, memory, disk and processes any one workload on that device
	// may be given, whatever it asks for (Task 20310).
	//
	// Auditable for the reason the sandbox action is: it bounds what code
	// running on that machine can consume, so raising it is a change an
	// incident reviewer needs attributed. The payload carries the previous
	// ceiling as well as the new one, because "who raised the memory cap on
	// the build fleet the day it fell over" is not answerable from the new
	// value alone.
	ActionExecutorLimits Action = "executor.limits"
	// ActionExecutorAudience records a change to who may run work on one
	// executor (Task 20310).
	//
	// The one executor action that is an access-control decision rather than a
	// configuration change. It is emitted for the add and the removal alike,
	// and carries whether the list became restricted or unrestricted as a
	// result — an executor's last audience entry being withdrawn widens access
	// to the whole fleet, which reads as a small edit and is not one.
	ActionExecutorAudience Action = "executor.audience"
	// ActionExecutorStateChange records a health-state transition nobody asked for.
	ActionExecutorStateChange Action = "executor.state_change"
	// ActionExecutorFailover records a session moving off a failed executor.
	ActionExecutorFailover Action = "executor.failover"

	// ── workspace ──────────────────────────────────────────────────────────

	// ActionWorkspaceProvisionStart records the beginning of source provisioning.
	ActionWorkspaceProvisionStart Action = "workspace.provision_start"
	// ActionWorkspaceProvisionEnd records provisioning finishing, with or without an error.
	ActionWorkspaceProvisionEnd Action = "workspace.provision_end"

	// ── sandbox ────────────────────────────────────────────────────────────

	// ActionSandboxImageDenied records an image refused by trust policy.
	ActionSandboxImageDenied Action = "sandbox.image_denied"

	// ── sandbox.attach ─────────────────────────────────────────────────────

	// ActionSandboxAttachOpen records a shell being opened inside a running sandbox.
	ActionSandboxAttachOpen Action = "sandbox.attach.open"
	// ActionSandboxAttachClose records an attached session ending.
	ActionSandboxAttachClose Action = "sandbox.attach.close"
	// ActionSandboxAttachDenied records an attach request being refused.
	ActionSandboxAttachDenied Action = "sandbox.attach.denied"

	// ── secret ─────────────────────────────────────────────────────────────

	// ActionSecretMint records a credential being sealed into a new secret.
	ActionSecretMint Action = "secret.mint"
	// ActionSecretDelete records a secret being destroyed.
	ActionSecretDelete Action = "secret.delete"
	// ActionSecretGrant records authority to lease a secret being written.
	ActionSecretGrant Action = "secret.grant"
	// ActionSecretRevoke records a grant being marked unusable.
	ActionSecretRevoke Action = "secret.revoke"
	// ActionSecretLease records a lease being issued or refused.
	ActionSecretLease Action = "secret.lease"
	// ActionSecretRenew records a live lease being re-issued.
	ActionSecretRenew Action = "secret.renew"
	// ActionSecretRelease records a lease ending in the ordinary way.
	ActionSecretRelease Action = "secret.release"
	// ActionSecretAccessCheck records an access decision against a grant's constraints.
	ActionSecretAccessCheck Action = "secret.access_check"
	// ActionSecretRequest records a self-service access request being filed.
	ActionSecretRequest Action = "secret.request"
	// ActionSecretRequestApprove records a request being approved.
	ActionSecretRequestApprove Action = "secret.request_approve"
	// ActionSecretRequestDeny records a request being refused.
	ActionSecretRequestDeny Action = "secret.request_deny"
	// ActionSecretRequestWithdraw records a requester withdrawing their request.
	ActionSecretRequestWithdraw Action = "secret.request_withdraw"
	// ActionSecretRequestExpire records a request lapsing undecided.
	ActionSecretRequestExpire Action = "secret.request_expire"
	// ActionSecretLeaseSweep records one run of the expired-lease sweeper.
	ActionSecretLeaseSweep Action = "secret.lease.sweep"

	// ── lease ──────────────────────────────────────────────────────────────

	// ActionLeaseRevokeSent records a revocation being queued for delivery.
	ActionLeaseRevokeSent Action = "lease.revoke_sent"
	// ActionLeaseRevokeAcked records an executor confirming it destroyed the material.
	ActionLeaseRevokeAcked Action = "lease.revoke_acked"
	// ActionLeaseRevokeFailed records a revocation that did not land.
	ActionLeaseRevokeFailed Action = "lease.revoke_failed"

	// ── github_app ─────────────────────────────────────────────────────────

	// ActionGitHubAppTokenDestroy records a GitHub App installation token deleted at GitHub.
	ActionGitHubAppTokenDestroy Action = "github_app.token_destroy"

	// ── egress ─────────────────────────────────────────────────────────────

	// ActionEgressGrant records authority to reach the network being written.
	ActionEgressGrant Action = "egress.grant"
	// ActionEgressRevoke records an egress authorisation being withdrawn.
	ActionEgressRevoke Action = "egress.revoke"
	// ActionEgressRedeem records a proxy session being minted against a grant.
	ActionEgressRedeem Action = "egress.redeem"
	// ActionEgressConnect records a connection attempt being evaluated.
	ActionEgressConnect Action = "egress.connect"
	// ActionEgressRequest records an HTTP request passing through the proxy.
	ActionEgressRequest Action = "egress.request"
	// ActionEgressClose records a proxy session closing with its byte counts.
	ActionEgressClose Action = "egress.close"

	// ── gitproxy ───────────────────────────────────────────────────────────

	// ActionGitProxySessionMinted records a git proxy session being created.
	ActionGitProxySessionMinted Action = "gitproxy.session_minted"
	// ActionGitProxySessionClosed records a git proxy session ending.
	ActionGitProxySessionClosed Action = "gitproxy.session_closed"
	// ActionGitProxyPushAllowed records a push admitted by branch policy.
	ActionGitProxyPushAllowed Action = "gitproxy.push_allowed"
	// ActionGitProxyPushDenied records a push refused by branch policy.
	ActionGitProxyPushDenied Action = "gitproxy.push_denied"
	// ActionGitProxyFetch records a read passing through the proxy.
	ActionGitProxyFetch Action = "gitproxy.fetch"
	// ActionGitProxyRejected records a request refused before policy evaluation.
	ActionGitProxyRejected Action = "gitproxy.rejected"

	// ── kubeguard ──────────────────────────────────────────────────────────

	// ActionKubeGuardSessionMinted records a Kubernetes proxy session being created.
	ActionKubeGuardSessionMinted Action = "kubeguard.session_minted"
	// ActionKubeGuardSessionClosed records a Kubernetes proxy session ending.
	ActionKubeGuardSessionClosed Action = "kubeguard.session_closed"
	// ActionKubeGuardRequestDenied records a Kubernetes request refused by policy.
	ActionKubeGuardRequestDenied Action = "kubeguard.request_denied"
	// ActionKubeGuardRequestAllowed records a Kubernetes request admitted by policy.
	ActionKubeGuardRequestAllowed Action = "kubeguard.request_allowed"
	// ActionKubeGuardRejected records a request refused before its session was identified.
	ActionKubeGuardRejected Action = "kubeguard.rejected"

	// ── ci ─────────────────────────────────────────────────────────────────

	// ActionCIRejected records a relay request refused before a session existed.
	ActionCIRejected Action = "ci.rejected"
	// ActionCISessionMinted records a relay session being issued to a pipeline.
	ActionCISessionMinted Action = "ci.session.minted"
	// ActionCISessionClosed records a relay session ending.
	ActionCISessionClosed Action = "ci.session.closed"
	// ActionCISessionRevoked records an operator revoking a live relay session.
	ActionCISessionRevoked Action = "ci.session.revoked"
	// ActionCIExchangeAccepted records a pipeline's OIDC token being exchanged.
	ActionCIExchangeAccepted Action = "ci.exchange.accepted"
	// ActionCIExchangeRejected records a token exchange being refused.
	ActionCIExchangeRejected Action = "ci.exchange.rejected"
	// ActionCIRelayAllowed records a relayed API call being forwarded.
	ActionCIRelayAllowed Action = "ci.relay.allowed"
	// ActionCIRelayDenied records a relayed API call being refused.
	ActionCIRelayDenied Action = "ci.relay.denied"
	// ActionCIRuleCreated records an allowlist rule being added.
	ActionCIRuleCreated Action = "ci.rule.created"
	// ActionCIRuleUpdated records an allowlist rule being edited.
	ActionCIRuleUpdated Action = "ci.rule.updated"
	// ActionCIRuleDeleted records an allowlist rule being removed.
	ActionCIRuleDeleted Action = "ci.rule.deleted"
	// ActionCIConfigUpdated records the relay's own settings changing.
	ActionCIConfigUpdated Action = "ci.config.updated"

	// ── authz ──────────────────────────────────────────────────────────────

	// ActionAuthzGranted records a privileged permission being exercised.
	ActionAuthzGranted Action = "authz.granted"
	// ActionAuthzDenied records a permission check refusing a caller.
	ActionAuthzDenied Action = "authz.denied"

	// ── api_token ──────────────────────────────────────────────────────────

	// ActionAPITokenCreated records a token or glasses link being minted.
	ActionAPITokenCreated Action = "api_token.created"
	// ActionAPITokenRevoked records a token or glasses link being revoked.
	ActionAPITokenRevoked Action = "api_token.revoked"
	// ActionAPITokenAuthFailed records a presented token failing to authenticate.
	ActionAPITokenAuthFailed Action = "api_token.auth_failed"
	// ActionAPITokenCreateDenied records a mint refused by the anti-escalation check.
	ActionAPITokenCreateDenied Action = "api_token.create_denied"

	// ── session ────────────────────────────────────────────────────────────

	// ActionSessionCreated records a sign-in completing.
	ActionSessionCreated Action = "session.created"
	// ActionSessionExpired records the janitor removing a deadline-expired session.
	ActionSessionExpired Action = "session.expired"
	// ActionSessionRevoked records a logout or an operator termination.
	ActionSessionRevoked Action = "session.revoked"
	// ActionSessionIdPRevoked records the IdP reporting the authorisation is gone.
	ActionSessionIdPRevoked Action = "session.idp_revoked"
	// ActionSessionRoleNarrowed records a re-assertion demoting a live session.
	ActionSessionRoleNarrowed Action = "session.role_narrowed"
	// ActionSessionClaimsUnverified records the hub failing to reach the IdP.
	ActionSessionClaimsUnverified Action = "session.claims_unverified"
	// ActionSessionClaimsRejected records the IdP refusing a re-assertion.
	ActionSessionClaimsRejected Action = "session.claims_rejected"
	// ActionSessionClaimsStale records a privileged operation blocked on claim age.
	ActionSessionClaimsStale Action = "session.claims_stale"

	// ── role_binding ───────────────────────────────────────────────────────

	// ActionRoleBindingGranted records a runtime binding granting a role.
	ActionRoleBindingGranted Action = "role_binding.granted"
	// ActionRoleBindingDenied records a runtime binding taking a role away.
	ActionRoleBindingDenied Action = "role_binding.denied"
	// ActionRoleBindingDeleted records a runtime binding being removed.
	ActionRoleBindingDeleted Action = "role_binding.deleted"

	// ── quota ──────────────────────────────────────────────────────────────

	// ActionQuotaDenied records admission control refusing an operation.
	ActionQuotaDenied Action = "quota.denied"
	// ActionQuotaOverrideSet records a per-identity quota override being written.
	ActionQuotaOverrideSet Action = "quota.override_set"
	// ActionQuotaOverrideCleared records an override being removed.
	ActionQuotaOverrideCleared Action = "quota.override_cleared"
	// ActionQuotaSpendRefused records a run stopped for exceeding a spend limit.
	ActionQuotaSpendRefused Action = "quota.spend_refused"

	// ── resource_ceiling ───────────────────────────────────────────────────

	// ActionResourceCeilingSet records a per-project resource ceiling being
	// written (Task 20301).
	//
	// Beside the quota overrides above, and for the same reason they are on the
	// trail: the authority to edit one is the authority to decide how much of
	// the machine a tenant gets. The fleet ceiling has no action of its own
	// because it is not editable at runtime — it comes from config.yaml, which
	// is reviewed and deployed rather than written through an API.
	ActionResourceCeilingSet Action = "resource_ceiling.set"
	// ActionResourceCeilingCleared records a per-project ceiling being removed,
	// after which the project is bounded by the fleet ceiling alone.
	ActionResourceCeilingCleared Action = "resource_ceiling.cleared"

	// ── sealing_key ────────────────────────────────────────────────────────

	// ActionSealingKeyRotated records the secret store's sealing key being rotated.
	ActionSealingKeyRotated Action = "sealing_key.rotated"
	// ActionSealingKeyRetired records a superseded sealing key being retired.
	ActionSealingKeyRetired Action = "sealing_key.retired"

	// ── oidc ───────────────────────────────────────────────────────────────

	// ActionOIDCConfigUpdated records the hub's single sign-on configuration
	// being changed.
	ActionOIDCConfigUpdated Action = "oidc.config.updated"

	// ── stt.credential ─────────────────────────────────────────────────────

	// ActionSTTCredentialSet records the speech-to-text key being configured.
	ActionSTTCredentialSet Action = "stt.credential.set"
	// ActionSTTCredentialCleared records the speech-to-text key being removed.
	ActionSTTCredentialCleared Action = "stt.credential.cleared"

	// ── user ───────────────────────────────────────────────────────────────

	// ActionUserOffboard is the offboarding summary row.
	ActionUserOffboard Action = "user.offboard"
	// ActionUserOffboardSession records sessions revoked during offboarding.
	ActionUserOffboardSession Action = "user.offboard_session"
	// ActionUserOffboardToken records API tokens revoked during offboarding.
	ActionUserOffboardToken Action = "user.offboard_token"
	// ActionUserOffboardGlasses records glasses links revoked during offboarding.
	ActionUserOffboardGlasses Action = "user.offboard_glasses"
	// ActionUserOffboardDeny records deny bindings written during offboarding.
	ActionUserOffboardDeny Action = "user.offboard_deny"
	// ActionUserOffboardMembership records project memberships dropped during offboarding.
	ActionUserOffboardMembership Action = "user.offboard_membership"
	// ActionUserOffboardLease records secret leases released during offboarding.
	ActionUserOffboardLease Action = "user.offboard_lease"
	// ActionUserOffboardTask records tasks stopped during offboarding.
	ActionUserOffboardTask Action = "user.offboard_task"
	// ActionUserOffboardProject records projects reported as needing a new owner.
	ActionUserOffboardProject Action = "user.offboard_project"

	// ── project.member ─────────────────────────────────────────────────────

	// ActionProjectMemberGrant records an identity joining a project's roster.
	ActionProjectMemberGrant Action = "project.member.grant"
	// ActionProjectMemberRevoke records a maintainer removing a member.
	ActionProjectMemberRevoke Action = "project.member.revoke"
	// ActionProjectMemberLeave records a member removing themselves.
	ActionProjectMemberLeave Action = "project.member.leave"
)
