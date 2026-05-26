# SSO/OIDC/Auth0 Auditor

A practical CLI toolkit for **authorized** testing of your organization's SSO, Auth0, OAuth 2.0, and OIDC implementation.

It is designed for security teams and bug bounty / red-team style internal assessments. It avoids brute force, credential attacks, real-user targeting, and destructive actions. Auth0 tenant checks are read-only.

## What it tests

| Module | Purpose |
|---|---|
| `discovery` | Fetches `/.well-known/openid-configuration` and flags risky metadata such as implicit/hybrid flow support, issuer mismatch, risky algorithms, and sensitive grants. |
| `redirects` | Generates redirect URI mutation test cases and optionally sends non-following `/authorize` requests. Useful for redirect allowlist, parser, and callback-chain review. |
| `callback-canary` | Sends harmless canary parameters to callback/error pages to detect reflection and external redirects. |
| `pkce-generate` | Creates PKCE S256 verifier/challenge pairs for manual testing. |
| `token-test` | Runs token endpoint negative tests with your own test authorization code: missing verifier, wrong verifier, wrong redirect URI, optional correct exchange and replay. |
| `jwt-lint` | Decodes/lints JWT/ID Tokens and optionally verifies ID Token signature/issuer/audience with PyJWT. |
| `jwt-variants` | Generates local negative-test JWT variants. It does not send them anywhere. |
| `auth0-audit` | Uses a read-only Auth0 Management API token to review clients, callbacks, connections, APIs/resource servers, and client grants. |
| `all-safe` | Runs discovery, redirect checks/generation, callback canaries, and optionally Auth0 read-only audit. |

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

Or run without installing:

```bash
python -m sso_auditor --help
```

## Configure

Create a config:

```bash
python -m sso_auditor init-config --out sso-auditor.config.json
```

Edit it:

```json
{
  "issuer": "https://YOUR_TENANT.auth0.com/",
  "client_id": "YOUR_TEST_CLIENT_ID",
  "redirect_uri": "https://app.example.com/callback",
  "scope": "openid profile email",
  "audience": "https://api.example.com/",
  "callback_urls": [
    "https://app.example.com/callback",
    "https://app.example.com/oauth/callback"
  ],
  "allowed_hosts": [
    "app.example.com"
  ],
  "owned_test_redirect_uri": "https://collector.security-test.example.com/cb",
  "owned_parent_domain": "security-test.example.com",
  "auth0_management": {
    "domain": "https://YOUR_TENANT.auth0.com",
    "token_env": "AUTH0_MGMT_TOKEN"
  }
}
```

`owned_test_redirect_uri` should be a host you control and are authorized to use. The tool does not follow login redirects or collect real-user tokens.

## Usage examples

### 1. Discovery metadata audit

```bash
python -m sso_auditor discovery \
  --config sso-auditor.config.json \
  --out reports/discovery.md
```

### 2. Redirect URI testing

Generate manual authorization URLs only:

```bash
python -m sso_auditor redirects \
  --config sso-auditor.config.json \
  --dry-run \
  --out reports/redirects.md
```

Send non-following `/authorize` requests:

```bash
python -m sso_auditor redirects \
  --config sso-auditor.config.json \
  --out reports/redirects.md
```

### 3. Callback/error canary testing

```bash
python -m sso_auditor callback-canary \
  --config sso-auditor.config.json \
  --out reports/callbacks.md
```

Optionally include a harmless reflected-XSS probe string:

```bash
python -m sso_auditor callback-canary \
  --config sso-auditor.config.json \
  --include-xss-probe \
  --out reports/callbacks-xss.md
```

### 4. PKCE generation

```bash
python -m sso_auditor pkce-generate
```

Use the generated `code_challenge` in a test login and keep the `code_verifier` for token exchange validation.

### 5. Token endpoint negative tests

After capturing an authorization code from **your own test login**:

```bash
python -m sso_auditor token-test \
  --config sso-auditor.config.json \
  --code 'AUTHORIZATION_CODE_FROM_TEST_LOGIN' \
  --code-verifier 'CORRECT_CODE_VERIFIER' \
  --out reports/pkce-token.md
```

To consume the code correctly and then test code replay:

```bash
python -m sso_auditor token-test \
  --config sso-auditor.config.json \
  --code 'AUTHORIZATION_CODE_FROM_TEST_LOGIN' \
  --code-verifier 'CORRECT_CODE_VERIFIER' \
  --include-correct-exchange \
  --out reports/pkce-token-replay.md
```

For confidential clients, store the secret in an environment variable:

```bash
export CLIENT_SECRET='...'
python -m sso_auditor token-test \
  --config sso-auditor.config.json \
  --code 'AUTHORIZATION_CODE_FROM_TEST_LOGIN' \
  --code-verifier 'CORRECT_CODE_VERIFIER' \
  --client-secret-env CLIENT_SECRET
```

### 6. JWT / ID Token linting and verification

Decode/lint:

```bash
python -m sso_auditor jwt-lint \
  --config sso-auditor.config.json \
  --token-file id_token.txt \
  --out reports/jwt-lint.md
```

Verify ID Token signature and core claims:

```bash
python -m sso_auditor jwt-lint \
  --config sso-auditor.config.json \
  --token-file id_token.txt \
  --verify \
  --expected-nonce 'NONCE_FROM_LOGIN_TRANSACTION' \
  --out reports/id-token-verify.md
```

Generate local negative-test variants:

```bash
python -m sso_auditor jwt-variants \
  --token-file id_token.txt \
  --outfile jwt-negative-variants.json \
  --out reports/jwt-variants.md
```

### 7. Auth0 tenant read-only audit

Create a Management API token with read-only scopes such as:

```text
read:clients
read:connections
read:resource_servers
read:client_grants
```

Then run:

```bash
export AUTH0_MGMT_TOKEN='...'
python -m sso_auditor auth0-audit \
  --config sso-auditor.config.json \
  --out reports/auth0-audit.md
```

### 8. Combined safe audit

```bash
python -m sso_auditor all-safe \
  --config sso-auditor.config.json \
  --redirect-dry-run \
  --out reports/all-safe.md
```

Include Auth0 read-only checks:

```bash
export AUTH0_MGMT_TOKEN='...'
python -m sso_auditor all-safe \
  --config sso-auditor.config.json \
  --include-auth0 \
  --out reports/all-safe-auth0.md
```

## Operational safety

- Use dedicated test tenants, test clients, and test accounts wherever possible.
- Do not target real users or collect real-user tokens.
- Use only redirect collector hosts you control and that are in scope.
- Keep reports private because they may contain internal tenant, client, and URL details.
- The tool redacts common token fields, but you should still review reports before sharing.
- Auth0 audit mode performs GET requests only.

## Interpreting results

`potential` means the tool found a condition that needs manual confirmation. OAuth/OIDC flows often require browser state and login interaction, so automated checks are intentionally conservative.

`passed` means a specific negative test appeared to be rejected. It is not a full guarantee of security.

`observed` is informational context for review.

## Recommended workflow

1. Run `discovery` and `redirects --dry-run` first.
2. Review generated authorization URLs and test manually with controlled accounts.
3. Run `callback-canary` against known callback/error pages.
4. Generate a fresh PKCE pair and run `token-test` with a code from your own test login.
5. Capture an ID Token from your own login and run `jwt-lint --verify`.
6. If you have tenant admin authorization, run `auth0-audit` with read-only Management API scopes.
7. Convert `potential` findings into manual proof-of-concept evidence using only test accounts.
