# Remediation Plan

## Purpose

This document tracks security findings that remain after the initial remediation work and defines the recommended next actions.

## Residual Risk 1 — Debian util-linux vulnerabilities

**Severity:** High  
**Status:** Open  
**Component:** `util-linux`, `util-linux-extra`  
**Finding:** Trivy reports multiple 2026 vulnerabilities in the Debian `util-linux` packages. The current scan does not provide a fixed version.

### Why it is not fully fixed

The vulnerable packages are part of the underlying Debian base image and are not application dependencies. Manually replacing distribution packages could create unsupported package combinations and reduce image stability.

### Remediation plan

1. Monitor Debian security updates for fixed `util-linux` packages.
2. Rebuild the image when a fixed package is available.
3. Continue using a supported, digest-pinned Python base image.
4. Re-run Trivy after every base-image update.
5. Consider moving to a newer supported Python/Debian base when compatible.

**Owner:** Platform/DevSecOps  
**Target:** Next base-image maintenance cycle

## Residual Risk 2 — Bandit bearer false positive

**Severity:** Low  
**Status:** Accepted  
**Component:** `app/main.py`

Bandit identifies the literal `bearer` authentication scheme as a possible hardcoded password.

### Why it is not fixed

`Bearer` is a standard HTTP authentication scheme identifier and is not a secret or credential. Changing it would make the authentication implementation incorrect.

### Remediation plan

- Keep the standard `Bearer` scheme.
- Document the finding as a false positive.
- Review the finding again if authentication implementation changes.

**Owner:** Application Engineering  
**Target:** No code change required

## Residual Risk 3 — External secret-management integration

**Severity:** Medium  
**Status:** Partially addressed  
**Component:** Kubernetes deployment

The Helm chart references an existing Kubernetes Secret for `SECRET_KEY`, `DATABASE_URL`, and `ADMIN_API_KEY`, but the repository does not contain the actual secret values.

### Why it is not fully implemented

The production secret provider is environment/platform-specific. Storing provider credentials or real secret values in the repository would introduce a new security risk.

### Remediation plan

1. Integrate the cluster with an approved external secret manager such as Azure Key Vault, AWS Secrets Manager, or HashiCorp Vault.
2. Use workload identity/service-account federation rather than static cloud credentials.
3. Populate `vulntracker-secrets` through the external secret integration.
4. Enable secret rotation.
5. Audit secret access.

**Owner:** Platform/DevSecOps  
**Target:** Before production deployment

## Additional hardening backlog

### Container image lifecycle

- Run container scans on every CI build.
- Fail CI on newly introduced Critical findings.
- Review High findings according to the organization's risk policy.
- Refresh the immutable base-image digest regularly.

### Kubernetes

- Enforce the restricted Pod Security Standard at the namespace level.
- Use a dedicated production namespace.
- Keep resource requests and limits mandatory.
- Maintain NetworkPolicy coverage as additional services are introduced.
- Review egress restrictions when database and notification service topology is finalized.

### Application

- Add automated security regression tests for authentication and share-link authorization.
- Add rate limiting for authentication and public share endpoints.
- Add structured audit logging for share-link creation and access.
- Review token expiry and revocation requirements before production use.

## Acceptance criteria

A residual finding can be closed when:

1. A vendor-supported fixed version is available and deployed, or
2. The risk is formally accepted with documented rationale, or
3. The affected component is removed from the runtime image.

All changes should be followed by SAST, SCA, container, IaC, and application test validation.
