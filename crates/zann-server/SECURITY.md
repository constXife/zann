# Security for zann-server

This document summarizes common attack vectors against zann-server and the
primary mitigations implemented in the codebase.

IMPORTANT: This codebase is written by an LLM, has not undergone a
formal security audit, and is not recommended for production use.

## Scope and assumptions

- This applies to the `zann-server` service only.
- Transport security (TLS) is expected to be provided by the deployment
  environment (for example, a reverse proxy).
- Operational controls such as firewalls and network segmentation are expected
  to protect the database and internal endpoints.
- Out of scope: physical access, root or kernel compromise, memory scraping,
  hypervisor or container escape, compromised build tooling, and exposure of
  secrets in the runtime environment (for example, leaked env vars or disk
  snapshots).

## Attack vectors and mitigations

### Unauthorized API access (auth bypass)

- Protected routes are wrapped by an auth middleware; public routes are limited
  to authentication and system info handlers.
- OIDC mode validates JWT signatures via JWKS and enforces issuer/audience when
  configured.
- Internal auth mode is configurable and can be disabled entirely.

### Credential theft and brute-force attempts

- Passwords and service-account tokens are processed with Argon2id using per-user
  salts and configurable KDF parameters.
- A server-side pepper is required for password hashing and token hashing.
- Password comparisons use constant-time equality to reduce timing leaks.
- An Argon2 semaphore limits concurrent KDF work to reduce CPU exhaustion.
- Internal registration can be disabled or restricted via configuration.

### Token replay and session abuse

- Access and refresh tokens have explicit TTLs.
- TTLs are enforced during identity resolution (expired tokens are rejected).
- Refresh rotates both access and refresh tokens and replaces stored hashes.
- Stored tokens are hashed with a server-side pepper before persistence.
- Logout deletes the session associated with the refresh token hash.
- CLI supports server fingerprint pinning to reduce MITM or server impersonation
  risk; set a known fingerprint on clients to prevent token exfiltration.

### Privilege escalation and data overreach

- Vault access is enforced via role-based checks (admin/operator/member/readonly)
  with explicit action scopes.
- Service accounts are restricted to read/list actions and only for shared
  server-encrypted vaults.
- Service-account scopes are parsed and matched against vault IDs, slugs, tags,
  or patterns.
- Optional IP allowlists restrict service-account token usage to known sources.

### Denial of service (resource exhaustion)

- Request body size is capped by `server.max_body_bytes`.
- Pagination parameters are clamped in handlers to limit query sizes.
- Argon2 concurrency is throttled with a semaphore.
- OIDC JWKS/userinfo HTTP requests use a short client timeout.

### Secrets and configuration hardening

- A server master key is required; missing keys fail preflight.
- On Unix, master key file permissions are checked to prevent group/other access.
- Sensitive parameters (`ZANN_PASSWORD_PEPPER`, `ZANN_TOKEN_PEPPER`, `ZANN_SMK`)
  are loaded from environment or secure config paths rather than being hard-coded.
- Forwarded headers are only trusted when `server.trusted_proxies` is configured.
  Otherwise client IPs are derived from the direct peer address.
- `ZANN_SMK` (data encryption) and `ZANN_PASSWORD_PEPPER`/`ZANN_TOKEN_PEPPER`
  (hash hardening) are separate to limit blast radius if one secret is compromised.

### Cryptography used for vault payloads

- Encrypted payloads are handled via `zann-core` helpers.
- Payloads are encrypted with XChaCha20-Poly1305 using per-item data encryption
  keys (DEKs), which are wrapped by a master key (KEK) using the same algorithm.
- The server stores encrypted blobs and wrapped keys; it does not depend on
  plaintext payloads at rest.

### Observability and incident response

- Request IDs are set and propagated for tracing and auditing.
- Panic recovery prevents crashes from returning stack traces to clients.
- Optional metrics and Sentry integrations support monitoring and alerting.

## Deployment recommendations

- Terminate TLS at the edge and only expose HTTP to trusted internal networks.
- Protect the `/metrics` endpoint behind network ACLs or authentication.
- Run the database with least-privilege credentials and restricted network
  access.
- Configure registration settings, auth mode, and token TTLs appropriate to the
  deployment environment.

## File permissions and secrets hygiene

- Config and secret files should be owned by the service user and set to `0600`.
- Data directories should be `0700` (or `0750` if a trusted admin group exists).
- Avoid storing peppers/tokens in world-readable locations or shared `/tmp`.
- For Docker, mount config as read-only and keep data on a separate volume.
- Distroless runs as nonroot (uid/gid 65532); ensure volume permissions match.

## Secret lifecycle and rotation

- Store `ZANN_SMK`/`ZANN_SMK_FILE`, `ZANN_PASSWORD_PEPPER`/`ZANN_PASSWORD_PEPPER_FILE`,
  and `ZANN_TOKEN_PEPPER`/`ZANN_TOKEN_PEPPER_FILE` in a dedicated secret manager
  or mounted secret files.
- Keep separate backups for SMK and data; losing SMK makes shared vaults
  unrecoverable.

### `ZANN_SMK` / `ZANN_SMK_FILE`

- Purpose: server master key for shared vault encryption (DEK wrapping).
- Storage: prefer `ZANN_SMK_FILE` or secret manager; keep permissions `0400`.
- Rotation: long-lived; rotate only with a planned re-encryption process.

### `ZANN_TOKEN_PEPPER` / `ZANN_TOKEN_PEPPER_FILE`

- Purpose: pepper for access/refresh/service token hashing and server fingerprint.
- Storage: can be separate from password pepper; defaults to password pepper if
  unset.
- Rotation: invalidates access/refresh tokens and service account tokens; re-issue
  all service tokens after rotation.

### `ZANN_PASSWORD_PEPPER` / `ZANN_PASSWORD_PEPPER_FILE` (optional)

- Purpose: pepper for password hashing on in (Argon2id).
- Storage: secret manager or file; never commit to repo or bake into images.
- Required when internal auth is enabled; optional for OIDC-only deployments.
- Rotation: invalidates stored password hashes; users must reset credentials.
