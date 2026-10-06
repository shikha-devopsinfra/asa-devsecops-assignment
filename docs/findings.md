# Security Findings and Remediation

## 1. Executive finding summary

The initial security review identified application-level secret exposure, unsafe SQL query construction, unsafe JWT algorithm acceptance, vulnerable Python dependencies, and vulnerabilities in the original container base image. The application and deployment configuration were hardened, dependencies were upgraded, and the container was rebuilt on a newer digest-pinned base image.

## 2. SAST findings

### Hardcoded application secrets

- Tool: Bandit
- Type: SAST / Secret exposure
- Initial severity: Medium
- Location: `app/config.py`
- Finding: JWT and database-related credentials were embedded in application configuration.
- Business impact: Source-code exposure could disclose credentials and allow unauthorized access to application resources.
- Remediation: Secrets were removed from source code and are now supplied through environment variables. Production mode fails if `SECRET_KEY` is not configured.
- Status: Remediated.

### SQL injection risk

- Tool: Bandit
- Type: SAST / Injection
- Initial severity: Medium
- Location: `app/database.py`
- Finding: Search SQL was constructed through string-based query handling.
- Business impact: Crafted input could potentially alter database query behavior or expose unauthorized data.
- Remediation: The search query now uses SQLAlchemy `text()` with a bound `:pattern` parameter.
- Status: Remediated.

### JWT algorithm handling

- Type: Application security review
- Initial risk: High
- Location: `app/auth.py`
- Finding: Token decoding previously allowed an unsafe algorithm option.
- Business impact: Unsafe JWT verification can undermine authentication if an attacker can submit a forged token.
- Remediation: JWT decoding now accepts only the configured algorithm.
- Status: Remediated.

### Bandit bearer-token false positive

- Tool: Bandit
- Type: SAST
- Severity: Low
- Location: `app/main.py`
- Finding: Bandit reported the literal string `bearer` as a possible hardcoded password.
- Assessment: False positive. `Bearer` is the standard HTTP authentication scheme and is not a credential.
- Remediation: No code change required.
- Status: Accepted false positive.

## 3. SCA findings

- Tool: pip-audit
- Type: Software Composition Analysis
- Initial risk: High/Critical dependency exposure
- Finding: The original dependency set included vulnerable authentication and cryptography-related packages.
- Remediation:
  - Replaced `python-jose` with `PyJWT`.
  - Removed the vulnerable `ecdsa` dependency chain.
  - Upgraded FastAPI and related dependencies.
  - Upgraded `cryptography`.
  - Updated `python-multipart`, `pyasn1`, and test tooling.
- Final status: `pip-audit` reports no known vulnerabilities.

## 4. Container findings

- Tool: Trivy
- Type: Container vulnerability scanning

### Original base-image findings

The original Debian-based Python image contained a critical `zlib1g` vulnerability and high-severity Python packaging vulnerabilities involving `wheel` and `jaraco.context`.

### Remediation

- Migrated from the older Debian 12-based Python image to a Debian Trixie Python 3.11 image.
- Pinned the base image by immutable SHA-256 digest.
- Installed pinned packaging tools only during image construction.
- Removed `wheel`, `setuptools`, and `jaraco.context` from the final runtime image.
- Application runs as a non-root user.
- Added a container health check.
- No application secrets are embedded in the image.

### Residual container findings

Trivy continues to report several HIGH findings in Debian `util-linux` packages. Trivy does not currently report a fixed version for these vulnerabilities.

These are OS-level vulnerabilities in the underlying distribution rather than application dependencies. They should be monitored and remediated when the distribution publishes fixed packages or when a newer supported base image containing those fixes is available.

## 5. IaC findings

- Tool: Trivy
- Type: Kubernetes/Helm misconfiguration scanning
- Initial finding: Medium — mutable `:latest` image tag.
- Remediation: Deployment now references the immutable application image digest.
- Additional hardening:
  - Non-root UID/GID.
  - Restricted security context.
  - Dropped Linux capabilities.
  - Read-only root filesystem.
  - Resource requests and limits.
  - Dedicated namespace with restricted Pod Security labels.
  - ClusterIP service.
  - NetworkPolicy restricting ingress.
  - Service-account token automount disabled.
  - Secrets referenced from an existing Kubernetes Secret rather than stored in Helm values.
- Final status: No Trivy IaC findings reported.

## 6. Task 1 security hardening

The shared-report feature was hardened as part of the implementation:

- Share tokens are generated using cryptographically secure random values.
- Only a SHA-256 token hash is persisted.
- Share passwords are stored as password hashes rather than plaintext.
- Links expire after a defined lifetime.
- Share access validates token length and expiry.
- A scan can only be shared by its owner.
- Password-protected links reject missing or invalid passwords.

These controls reduce the risk of token disclosure, unauthorized report access, and credential exposure.

## 7. Priority

| Priority | Finding | Status |
|---|---|---|
| Critical | Original container `zlib1g` vulnerability | Remediated by base-image migration |
| High | Original Python packaging vulnerabilities | Remediated |
| High | SQL injection risk | Remediated |
| High | Unsafe JWT algorithm handling | Remediated |
| Medium | Hardcoded application secrets | Remediated |
| Medium | Mutable Helm `:latest` image | Remediated |
| High | Current Debian `util-linux` findings | Residual; no fixed version reported |
| Low | Bandit `bearer` false positive | Accepted |
