# Burp SSO / OAuth / OIDC Passive Auditor

A single-file **Jython Burp extension** that passively watches traffic while you browse an SSO/OAuth/OIDC/Auth0 application and flags likely issues.

It is designed as a companion to the SSO/OIDC/Auth0 audit CLI toolkit. It does **not** actively attack, replay, fuzz, brute force, or mutate requests. It gives you live findings/leads inside Burp while you browse the login, callback, token exchange, logout, account linking, and API flows.

## What it detects passively

- OAuth/OIDC `/authorize` requests and important parameters.
- Missing/short `state`.
- Missing/short `nonce`.
- Implicit/hybrid front-channel token flows.
- Missing PKCE challenge on Authorization Code flows.
- PKCE method not equal to `S256`.
- Redirect URIs outside configured trusted/callback hosts.
- OAuth callback requests carrying `code`, `state`, `id_token`, or `access_token`.
- Callback pages lacking strong `Referrer-Policy` or CSP.
- Reflection of OAuth callback/error parameters.
- Token endpoint exchanges missing `code_verifier` for public-looking clients.
- Short PKCE `code_verifier`.
- Possible authorization code reuse in observed traffic.
- Token endpoint cache/CORS concerns.
- External redirects carrying OAuth code/token parameters.
- OAuth code/token leakage in `Referer` headers.
- Auth/session-like cookies missing `Secure`, `HttpOnly`, or `SameSite`.
- JWTs observed in traffic, including `alg=none`, issuer/audience mismatches, and rough token-use inference.
- Auth0/Universal Login traffic markers.

## Limitations

This extension is passive. It cannot prove server-side validation failures by itself. It cannot know whether a state/nonce/PKCE check is truly enforced unless you perform manual replay/mutation tests or use the CLI toolkit. Treat most findings as leads unless they show direct code/token leakage to an external host.

## Install

1. Download Jython standalone 2.7.x if Burp does not already have it configured.
2. In Burp: **Extensions / Extender > Settings > Python environment**, set the Jython standalone JAR path.
3. Go to **Extensions / Extender > Installed > Add**.
4. Extension type: **Python**.
5. Select `burp_sso_oauth_auditor.py`.
6. Open the new **SSO Auditor** tab.

## Configure for your current UAT flow

From your screenshots, these values were prefilled:

```text
Allowed hosts:
auth.uat.airmiles.ai
dashboard.uat.snapportal.airmiles.ca

Callback URLs:
https://dashboard.uat.snapportal.airmiles.ca
https://dashboard.uat.snapportal.airmiles.ca/

Expected issuer:
https://auth.uat.airmiles.ai/

Expected client_id:
GRNyNndNnI8cz65OCLj5miZ7KU3gqc5i

Expected audience:
https://adminportal.airmiles.ca/
```

Paste your Burp Collaborator hostname into the optional collector field, for example:

```text
abc123xyz.oastify.com
```

Do **not** add the Collaborator hostname to allowed hosts. It should remain external so the extension can flag redirects/leaks to it.

You can also click **Load CLI JSON config** and select your `airmiles_uat_sso_auditor.config.json`; the extension will import allowed hosts, callback URLs, issuer, client ID, audience, and collector host.

## Recommended browsing order

1. Clear browser cookies for the test app.
2. Start Burp intercept/proxy logging.
3. Load the target app unauthenticated.
4. Start login.
5. Complete Universal Login / social login / enterprise login with a test account.
6. Let the app land on the callback URL and dashboard.
7. Browse a few authenticated API pages.
8. Logout and log back in.
9. If in scope, test account linking and signup/invite flows.
10. Export findings with **Export Markdown**.

## How to interpret severity

| Severity | Meaning |
|---|---|
| Critical | Direct observed code/token leakage or token forgery indicator such as `alg=none`. |
| High | Likely ATO/token theft class if confirmed, such as missing state, implicit flow, external redirect with sensitive params, public token exchange without verifier. |
| Medium | Strong security lead requiring manual confirmation. |
| Low | Hardening issue or weak posture. |
| Info | Flow inventory and evidence. |

## Safety notes

Use dedicated test accounts. Do not target real users. Redact tokens/codes/cookies in reports. If a real token or authorization code appears in the Collaborator or findings, treat it as sensitive and revoke/logout the test session.
