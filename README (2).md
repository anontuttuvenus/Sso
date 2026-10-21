# PHP Surface Inventory

This read-only helper inventories PHP clues visible from approved web URLs. It does not determine whether a server is vulnerable to PHP2Shell.

## Request behavior

- Sends one ordinary `HEAD` request to each exact URL in the target file.
- Does not follow redirects, send a request body, read response bodies, or send cookies or authentication.
- Records the HTTP status, PHP hints in response metadata, and a PHP version only when a response header explicitly discloses one.
- Never stores `Set-Cookie` values.
- Requests are sequential, with no retries. Maximum 250 unique URLs.

The ZIP you shared contains PoC and worker-crash material; this helper does not import or run that code.

## Run

Use Python 3.9 or later. Build `targets.txt` from the exact URLs approved for ASF 78. `targets.example.txt` is only a template.

```sh
python3 php_surface_check.py --targets targets.txt --output php-surface-report.json
```

For approved internal assets using private IP literals or `localhost`, include `--allow-private`:

```sh
python3 php_surface_check.py --targets targets.txt --allow-private --output php-surface-report.json
```

The checker refuses to overwrite an existing report. Choose a new filename for each run. Omit `--output` to print JSON to the terminal.

## Interpret the report

- `php_indicated` means a visible hint was present. It is an inventory lead, not proof of a vulnerable runtime.
- `no_php_signal_in_response` means the response disclosed no PHP hint. It does not prove PHP is absent behind a proxy or gateway.
- `reported_php_version` is only a version string exposed in a response header. A proxy can set or remove it, and it may not match the PHP-FPM or container build.
- `patch_status` is always `unknown`. Confirm the running package/build with the platform owner and compare it with the current official PHP security advisory.
- Redirects are not followed. Add a redirect destination only if it is explicitly in scope.

This helper does not send multipart requests or test the vulnerable code path. Do not use exploit PoCs against production to fill the remaining evidence gap.
