# -*- coding: utf-8 -*-
"""
Burp SSO / OAuth / OIDC Passive Auditor

Single-file Jython 2.7 Burp extension for authorized SSO/OIDC/Auth0 testing.
It passively observes Burp HTTP traffic while you browse and flags common SSO issues.

Load in Burp: Extensions/Extender -> Add -> Extension type: Python -> select this file.
Requires Burp's Python/Jython environment to be configured.

Safety: this extension is passive. It does not brute force, mutate requests, replay tokens,
or send active traffic. Use it only on systems you are authorized to test.
"""

from burp import IBurpExtender, IHttpListener, ITab, IScanIssue

from java.io import PrintWriter
from java.lang import Runnable
from javax.swing import (JPanel, JSplitPane, JScrollPane, JTable, JTextArea, JButton,
                         JLabel, JTextField, JCheckBox, JFileChooser, JOptionPane,
                         SwingUtilities, BorderFactory)
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, GridLayout
from java.awt.event import ActionListener, MouseAdapter

import base64
import json
import re
import time
import traceback

try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse

try:
    from urllib import unquote_plus
except ImportError:
    from urllib.parse import unquote_plus


EXTENSION_NAME = "SSO/OAuth/OIDC Passive Auditor"
VERSION = "1.0.0"

SENSITIVE_PARAM_NAMES = set([
    "code", "access_token", "id_token", "refresh_token", "token", "assertion",
    "client_secret", "code_verifier", "password", "samlresponse", "samlrequest",
    "state", "nonce", "auth0client", "session_state"
])

TOKENISH_PARAM_NAMES = set([
    "code", "access_token", "id_token", "refresh_token", "token", "assertion"
])

SESSION_COOKIE_HINTS = [
    "session", "sid", "connect.sid", "auth", "auth0", "did", "jwt", "token",
    "sso", "csrf", "xsrf"
]

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*")


class RunnableFn(Runnable):
    def __init__(self, fn):
        self.fn = fn

    def run(self):
        self.fn()


class ButtonAction(ActionListener):
    def __init__(self, fn):
        self.fn = fn

    def actionPerformed(self, event):
        self.fn()


class NonEditableTableModel(DefaultTableModel):
    def isCellEditable(self, row, column):
        return False


class TableClickListener(MouseAdapter):
    def __init__(self, extender):
        self.extender = extender

    def mouseClicked(self, event):
        self.extender.update_detail_from_selection()


class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        self._callbacks.setExtensionName(EXTENSION_NAME)

        self.findings = []
        self.finding_fingerprints = set([])
        self.observed_authz = {}       # state -> metadata
        self.observed_codes = {}       # code -> state
        self.observed_code_uses = {}   # code -> count
        self.observed_issuers = set([])
        self.observed_clients = set([])
        self.observed_redirects = set([])

        self._build_ui()

        self._callbacks.registerHttpListener(self)
        self._callbacks.addSuiteTab(self)
        self._stdout.println("%s %s loaded" % (EXTENSION_NAME, VERSION))

    # ----------------------------------------------------------------------
    # Burp tab
    # ----------------------------------------------------------------------
    def getTabCaption(self):
        return "SSO Auditor"

    def getUiComponent(self):
        return self.root_panel

    def _build_ui(self):
        self.root_panel = JPanel(BorderLayout())

        settings_panel = JPanel(BorderLayout())
        settings_panel.setBorder(BorderFactory.createTitledBorder("Settings"))

        field_panel = JPanel(GridLayout(0, 2))
        field_panel.add(JLabel("Allowed hosts / trusted hosts, one per line"))
        field_panel.add(JLabel("Callback URLs, one per line"))

        self.allowed_hosts_area = JTextArea(6, 42)
        self.allowed_hosts_area.setText("auth.uat.airmiles.ai\ndashboard.uat.snapportal.airmiles.ca")
        self.callback_urls_area = JTextArea(6, 42)
        self.callback_urls_area.setText("https://dashboard.uat.snapportal.airmiles.ca\nhttps://dashboard.uat.snapportal.airmiles.ca/")

        field_panel.add(JScrollPane(self.allowed_hosts_area))
        field_panel.add(JScrollPane(self.callback_urls_area))

        field_panel.add(JLabel("Burp Collaborator / owned collector host, optional"))
        field_panel.add(JLabel("Expected issuer, optional"))
        self.collab_host_field = JTextField(42)
        self.issuer_field = JTextField(42)
        self.issuer_field.setText("https://auth.uat.airmiles.ai/")
        field_panel.add(self.collab_host_field)
        field_panel.add(self.issuer_field)

        field_panel.add(JLabel("Expected client_id, optional"))
        field_panel.add(JLabel("Expected audience, optional"))
        self.client_id_field = JTextField(42)
        self.client_id_field.setText("GRNyNndNnI8cz65OCLj5miZ7KU3gqc5i")
        self.audience_field = JTextField(42)
        self.audience_field.setText("https://adminportal.airmiles.ca/")
        field_panel.add(self.client_id_field)
        field_panel.add(self.audience_field)

        settings_panel.add(field_panel, BorderLayout.CENTER)

        control_panel = JPanel()
        self.add_burp_issues_checkbox = JCheckBox("Add Burp issues", False)
        self.scan_cookies_checkbox = JCheckBox("Flag weak cookie attrs", True)
        self.scan_jwts_checkbox = JCheckBox("Decode/lint JWTs", True)
        self.monitor_only_proxy_checkbox = JCheckBox("Proxy only", False)
        control_panel.add(self.add_burp_issues_checkbox)
        control_panel.add(self.scan_cookies_checkbox)
        control_panel.add(self.scan_jwts_checkbox)
        control_panel.add(self.monitor_only_proxy_checkbox)

        load_button = JButton("Load CLI JSON config")
        load_button.addActionListener(ButtonAction(self.load_config_from_file))
        clear_button = JButton("Clear findings")
        clear_button.addActionListener(ButtonAction(self.clear_findings))
        export_button = JButton("Export Markdown")
        export_button.addActionListener(ButtonAction(self.export_markdown))
        control_panel.add(load_button)
        control_panel.add(clear_button)
        control_panel.add(export_button)

        settings_panel.add(control_panel, BorderLayout.SOUTH)

        columns = ["Time", "Severity", "Title", "Host", "Evidence", "URL"]
        self.table_model = NonEditableTableModel(columns, 0)
        self.findings_table = JTable(self.table_model)
        self.findings_table.addMouseListener(TableClickListener(self))
        self.findings_table.getColumnModel().getColumn(0).setPreferredWidth(125)
        self.findings_table.getColumnModel().getColumn(1).setPreferredWidth(80)
        self.findings_table.getColumnModel().getColumn(2).setPreferredWidth(260)
        self.findings_table.getColumnModel().getColumn(3).setPreferredWidth(180)
        self.findings_table.getColumnModel().getColumn(4).setPreferredWidth(360)
        self.findings_table.getColumnModel().getColumn(5).setPreferredWidth(520)

        findings_panel = JPanel(BorderLayout())
        findings_panel.setBorder(BorderFactory.createTitledBorder("Passive findings while browsing"))
        findings_panel.add(JScrollPane(self.findings_table), BorderLayout.CENTER)

        self.detail_area = JTextArea(10, 100)
        self.detail_area.setEditable(False)
        self.detail_area.setText(
            "Load the extension, browse the SSO flow through Burp, and watch this tab.\n\n"
            "This extension is passive. It flags suspicious OAuth/OIDC/Auth0 behavior but does not prove every issue.\n"
            "Use test accounts and only systems you are authorized to test.\n"
        )
        detail_panel = JPanel(BorderLayout())
        detail_panel.setBorder(BorderFactory.createTitledBorder("Finding detail / notes"))
        detail_panel.add(JScrollPane(self.detail_area), BorderLayout.CENTER)

        middle_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, findings_panel, detail_panel)
        middle_split.setResizeWeight(0.65)

        main_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, settings_panel, middle_split)
        main_split.setResizeWeight(0.22)
        self.root_panel.add(main_split, BorderLayout.CENTER)

    # ----------------------------------------------------------------------
    # UI actions
    # ----------------------------------------------------------------------
    def load_config_from_file(self):
        chooser = JFileChooser()
        result = chooser.showOpenDialog(self.root_panel)
        if result != JFileChooser.APPROVE_OPTION:
            return
        path = chooser.getSelectedFile().getAbsolutePath()
        try:
            fh = open(path, "r")
            cfg = json.loads(fh.read())
            fh.close()
            allowed_hosts = cfg.get("allowed_hosts") or []
            callbacks = cfg.get("callback_urls") or []
            if cfg.get("authorization_endpoint"):
                allowed_hosts.append(urlparse.urlparse(cfg.get("authorization_endpoint")).hostname or "")
            if cfg.get("redirect_uri"):
                callbacks.append(cfg.get("redirect_uri"))
                allowed_hosts.append(urlparse.urlparse(cfg.get("redirect_uri")).hostname or "")
            if allowed_hosts:
                self.allowed_hosts_area.setText("\n".join(sorted(set([x for x in allowed_hosts if x]))))
            if callbacks:
                self.callback_urls_area.setText("\n".join(sorted(set([x for x in callbacks if x]))))
            if cfg.get("owned_test_redirect_uri"):
                h = urlparse.urlparse(cfg.get("owned_test_redirect_uri")).hostname
                if h:
                    self.collab_host_field.setText(h)
            elif cfg.get("owned_parent_domain"):
                self.collab_host_field.setText(cfg.get("owned_parent_domain"))
            if cfg.get("issuer"):
                self.issuer_field.setText(cfg.get("issuer"))
            if cfg.get("client_id"):
                self.client_id_field.setText(cfg.get("client_id"))
            if cfg.get("audience"):
                self.audience_field.setText(cfg.get("audience"))
            JOptionPane.showMessageDialog(self.root_panel, "Loaded config:\n" + path)
        except Exception as e:
            self._stderr.println(traceback.format_exc())
            JOptionPane.showMessageDialog(self.root_panel, "Failed to load config: " + str(e))

    def clear_findings(self):
        self.findings = []
        self.finding_fingerprints = set([])
        self.table_model.setRowCount(0)
        self.detail_area.setText("Findings cleared.\n")

    def export_markdown(self):
        chooser = JFileChooser()
        chooser.setSelectedFile(java_file("sso-oauth-oidc-passive-findings.md"))
        result = chooser.showSaveDialog(self.root_panel)
        if result != JFileChooser.APPROVE_OPTION:
            return
        path = chooser.getSelectedFile().getAbsolutePath()
        try:
            out = []
            out.append("# SSO / OAuth / OIDC Passive Findings\n")
            out.append("Generated: %s\n" % time.strftime("%Y-%m-%d %H:%M:%S"))
            out.append("Extension: %s %s\n" % (EXTENSION_NAME, VERSION))
            out.append("\n## Scope settings\n")
            out.append("\n**Allowed hosts**\n\n```text\n%s\n```\n" % self.allowed_hosts_area.getText().strip())
            out.append("\n**Callback URLs**\n\n```text\n%s\n```\n" % self.callback_urls_area.getText().strip())
            out.append("\n## Findings\n")
            if not self.findings:
                out.append("\nNo findings recorded.\n")
            for idx, f in enumerate(self.findings):
                out.append("\n### %d. [%s] %s\n" % (idx + 1, f.get("severity"), f.get("title")))
                out.append("\n- **Time:** %s" % f.get("time"))
                out.append("\n- **Host:** %s" % f.get("host"))
                out.append("\n- **URL:** `%s`" % f.get("url"))
                out.append("\n- **Evidence:** `%s`\n" % f.get("evidence"))
                if f.get("detail"):
                    out.append("\n**Detail**\n\n%s\n" % f.get("detail"))
                if f.get("remediation"):
                    out.append("\n**Suggested validation/remediation**\n\n%s\n" % f.get("remediation"))
            fh = open(path, "w")
            fh.write("".join(out))
            fh.close()
            JOptionPane.showMessageDialog(self.root_panel, "Exported:\n" + path)
        except Exception as e:
            self._stderr.println(traceback.format_exc())
            JOptionPane.showMessageDialog(self.root_panel, "Failed to export: " + str(e))

    def update_detail_from_selection(self):
        row = self.findings_table.getSelectedRow()
        if row < 0 or row >= len(self.findings):
            return
        f = self.findings[row]
        text = []
        text.append("[%s] %s\n" % (f.get("severity"), f.get("title")))
        text.append("Time: %s\n" % f.get("time"))
        text.append("Host: %s\n" % f.get("host"))
        text.append("URL: %s\n" % f.get("url"))
        text.append("Evidence: %s\n\n" % f.get("evidence"))
        text.append(f.get("detail") or "")
        if f.get("remediation"):
            text.append("\n\nSuggested validation/remediation:\n%s" % f.get("remediation"))
        self.detail_area.setText("".join(text))
        self.detail_area.setCaretPosition(0)

    # ----------------------------------------------------------------------
    # HTTP listener
    # ----------------------------------------------------------------------
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        try:
            if self.monitor_only_proxy_checkbox.isSelected():
                try:
                    if self._callbacks.getToolName(toolFlag) != "Proxy":
                        return
                except Exception:
                    pass

            # Most useful checks need both request and response, so process on responses.
            if messageIsRequest:
                return
            request = messageInfo.getRequest()
            response = messageInfo.getResponse()
            if request is None:
                return

            req_info = self._helpers.analyzeRequest(messageInfo)
            url = req_info.getUrl()
            method = req_info.getMethod()
            host = safe_lower(url.getHost())
            full_url = str(url)
            path = url.getPath() or "/"
            query_params = parse_qs(url.getQuery())
            req_headers = headers_to_dict(req_info.getHeaders())
            req_body = self._get_request_body(request, req_info)
            req_body_params = parse_qs(req_body) if looks_form_encoded(req_headers, req_body) else {}

            resp_info = None
            status = None
            resp_headers = {}
            resp_body = ""
            if response is not None:
                resp_info = self._helpers.analyzeResponse(response)
                status = int(resp_info.getStatusCode())
                resp_headers = headers_to_dict(resp_info.getHeaders())
                resp_body = self._get_response_body(response, resp_info, 200000)

            self._check_auth0_markers(host, full_url, resp_headers, messageInfo)
            self._check_referrer_leak(host, full_url, req_headers, messageInfo)
            self._check_authorize_request(host, full_url, path, query_params, messageInfo)
            self._check_callback_request(host, full_url, path, query_params, resp_headers, resp_body, messageInfo)
            self._check_token_request_response(host, full_url, path, method, req_headers, req_body_params, resp_headers, resp_body, messageInfo)
            self._check_redirect_response(host, full_url, status, resp_headers, messageInfo)

            if self.scan_cookies_checkbox.isSelected():
                self._check_cookies(host, full_url, resp_headers, messageInfo)
            if self.scan_jwts_checkbox.isSelected():
                self._check_jwts(host, full_url, query_params, req_body_params, resp_body, messageInfo)

        except Exception:
            self._stderr.println(traceback.format_exc())

    # ----------------------------------------------------------------------
    # Passive checks
    # ----------------------------------------------------------------------
    def _check_auth0_markers(self, host, full_url, resp_headers, messageInfo):
        if "auth0" in host or "x-auth0-requestid" in resp_headers or "x-auth0-l" in resp_headers:
            self.add_finding(
                "Info",
                "Auth0 / Universal Login traffic observed",
                host,
                "Auth0 response headers or host observed",
                full_url,
                "Observed Auth0-style host or response headers. Use this to confirm the issuer/custom domain and tenant boundary.",
                "Confirm the issuer in discovery metadata and make sure applications validate exact issuer, audience, and JWKS.",
                messageInfo
            )

    def _check_authorize_request(self, host, full_url, path, params, messageInfo):
        if not is_authorize_path(path):
            return

        response_type = first(params, "response_type")
        scope = first(params, "scope")
        client_id = first(params, "client_id")
        redirect_uri = first(params, "redirect_uri")
        state = first(params, "state")
        nonce = first(params, "nonce")
        code_challenge = first(params, "code_challenge")
        method = first(params, "code_challenge_method")
        audience = first(params, "audience")
        connection = first(params, "connection")

        if state:
            self.observed_authz[state] = {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "response_type": response_type,
                "scope": scope,
                "nonce": nonce,
                "code_challenge_method": method,
                "audience": audience,
                "url": redact_url(full_url),
                "time": time.time()
            }
        if client_id:
            self.observed_clients.add(client_id)
        if redirect_uri:
            self.observed_redirects.add(redirect_uri)

        details = []
        details.append("OAuth/OIDC authorization request observed.")
        details.append("response_type=%s" % safe_value(response_type))
        details.append("scope=%s" % safe_value(scope))
        details.append("redirect_uri=%s" % safe_value(redirect_uri))
        details.append("audience=%s" % safe_value(audience))
        if connection:
            details.append("connection=%s" % safe_value(connection))
        self.add_finding(
            "Info",
            "OAuth/OIDC authorization request observed",
            host,
            "client_id=%s response_type=%s" % (shorten(client_id), safe_value(response_type)),
            full_url,
            "\n".join(details),
            "Review parameters, redirect URI, state/nonce, PKCE, response type, and selected connection.",
            messageInfo
        )

        expected_client = self.client_id_field.getText().strip()
        if expected_client and client_id and client_id != expected_client:
            self.add_finding(
                "Medium",
                "Unexpected OAuth client_id observed",
                host,
                "client_id=%s" % shorten(client_id),
                full_url,
                "The observed client_id did not match the configured expected client_id. This may be another app, an unintended client, or a test-scope issue.",
                "Verify whether this client is in scope and whether it has the correct callback URLs, grants, and connections.",
                messageInfo
            )

        expected_aud = self.audience_field.getText().strip()
        if expected_aud and audience and audience != expected_aud:
            self.add_finding(
                "Medium",
                "Unexpected OAuth audience observed",
                host,
                "audience=%s" % safe_value(audience),
                full_url,
                "The authorization request used an audience different from the configured expected API audience.",
                "Check for audience confusion. APIs should reject tokens minted for other audiences.",
                messageInfo
            )

        if not state:
            self.add_finding(
                "High",
                "Authorization request missing state",
                host,
                "state parameter absent",
                full_url,
                "No state parameter was present in the authorization request. This can enable OAuth login CSRF or response injection.",
                "Generate high-entropy state values, bind them to the browser session, expire them quickly, and enforce one-time use.",
                messageInfo
            )
        elif len(state) < 16:
            self.add_finding(
                "Medium",
                "Authorization request uses short state value",
                host,
                "state length=%d" % len(state),
                full_url,
                "The state value appears short. Low-entropy state increases CSRF/replay risk.",
                "Use at least 128 bits of unpredictable entropy and bind state to the session.",
                messageInfo
            )

        if "openid" in (scope or ""):
            if not nonce:
                sev = "Medium" if ("id_token" in (response_type or "") or "token" in (response_type or "")) else "Low"
                self.add_finding(
                    sev,
                    "OIDC request missing nonce",
                    host,
                    "nonce parameter absent",
                    full_url,
                    "An OIDC request was observed without nonce. This is most dangerous for implicit/hybrid flows and still worth reviewing for browser clients.",
                    "Use high-entropy nonce values and validate the ID Token nonce before creating a session.",
                    messageInfo
                )
            elif len(nonce) < 16:
                self.add_finding(
                    "Medium",
                    "OIDC request uses short nonce value",
                    host,
                    "nonce length=%d" % len(nonce),
                    full_url,
                    "The nonce value appears short. Low-entropy nonce weakens ID Token replay protection.",
                    "Use unpredictable nonce values, bind them to the login transaction, and enforce one-time use.",
                    messageInfo
                )

        if "token" in (response_type or "") or "id_token" in (response_type or ""):
            self.add_finding(
                "High",
                "Implicit or hybrid front-channel token flow observed",
                host,
                "response_type=%s" % safe_value(response_type),
                full_url,
                "The authorization request asks for tokens or ID Tokens in the browser front-channel. These flows increase token leakage risk through history, referrer, XSS, and redirects.",
                "Prefer Authorization Code + PKCE. Remove implicit/hybrid response types unless there is a documented exception and strict nonce/token handling.",
                messageInfo
            )

        if "code" in (response_type or ""):
            if not code_challenge:
                self.add_finding(
                    "Medium",
                    "Authorization Code flow without visible PKCE challenge",
                    host,
                    "code_challenge absent",
                    full_url,
                    "The authorization request uses response_type=code but has no code_challenge. For public/browser/mobile clients this is a serious risk if codes leak.",
                    "Require PKCE with S256 for public clients and consider PKCE for confidential clients as defense in depth.",
                    messageInfo
                )
            elif method != "S256":
                self.add_finding(
                    "High",
                    "PKCE challenge method is not S256",
                    host,
                    "code_challenge_method=%s" % safe_value(method),
                    full_url,
                    "PKCE is present but not using S256. plain or missing challenge method allows weaker code interception defenses.",
                    "Require code_challenge_method=S256 and reject plain/missing methods.",
                    messageInfo
                )

        if redirect_uri:
            self._check_redirect_uri_value(host, full_url, redirect_uri, messageInfo)

    def _check_redirect_uri_value(self, host, full_url, redirect_uri, messageInfo):
        p = urlparse.urlparse(redirect_uri)
        rhost = safe_lower(p.hostname)
        allowed_hosts = self.get_allowed_hosts()
        callback_hosts = self.get_callback_hosts()
        if redirect_uri.startswith("http://") and rhost not in ["localhost", "127.0.0.1"]:
            self.add_finding(
                "High",
                "OAuth redirect_uri uses plaintext HTTP",
                host,
                "redirect_uri=%s" % safe_value(redirect_uri),
                full_url,
                "The authorization request uses a non-HTTPS redirect URI. Codes or tokens may be exposed on the network or through downgrade chains.",
                "Use exact HTTPS redirect URIs in production. Allow localhost HTTP only for local development clients.",
                messageInfo
            )
        if rhost and allowed_hosts and rhost not in allowed_hosts and rhost not in callback_hosts:
            self.add_finding(
                "High",
                "Authorization request uses redirect_uri outside configured allowed hosts",
                host,
                "redirect_uri_host=%s" % rhost,
                full_url,
                "The redirect_uri host is not in the configured allowed/callback host list. This may indicate a redirect URI validation bypass, unintended client, or missing extension configuration.",
                "Confirm scope. If unintended, restrict callback URLs to exact expected HTTPS origins and remove wildcards/placeholders.",
                messageInfo
            )
        if "*" in redirect_uri or "%2a" in redirect_uri.lower():
            self.add_finding(
                "High",
                "Wildcard-like redirect_uri observed",
                host,
                "redirect_uri contains wildcard marker",
                full_url,
                "The redirect_uri contains a wildcard-like marker. Wildcards in redirect allowlists are commonly exploitable through parser and open redirect chains.",
                "Use exact redirect URI matching and avoid wildcards in production.",
                messageInfo
            )

    def _check_callback_request(self, host, full_url, path, params, resp_headers, resp_body, messageInfo):
        has_code = "code" in params
        has_token = any([name in params for name in ["access_token", "id_token", "token"]])
        has_state = "state" in params
        if not (has_code or has_token or ("callback" in path.lower() and has_state)):
            return

        state = first(params, "state")
        code = first(params, "code")
        if code and state:
            self.observed_codes[code] = state
        if has_code or has_token:
            self.add_finding(
                "Info",
                "OAuth callback carrying code/token observed",
                host,
                "params=%s" % ",".join(sorted(params.keys())),
                full_url,
                "A callback-like request carried OAuth/OIDC response parameters. The extension will check referrer, response headers, cookie attributes, and later token exchange behavior.",
                "Ensure state/nonce are validated before session creation, strip query/fragment quickly, and avoid third-party scripts on callback pages.",
                messageInfo
            )

        if state and state not in self.observed_authz:
            self.add_finding(
                "Medium",
                "Callback state was not observed in prior authorization request",
                host,
                "state not in local transaction cache",
                full_url,
                "The callback contains a state value that this extension did not observe in a prior /authorize request. This can happen if browsing started mid-flow, but it is worth validating for state/session binding issues.",
                "Test state replay/swap manually with two test accounts. The callback should reject missing, stale, or cross-session state.",
                messageInfo
            )

        ref_pol = resp_headers.get("referrer-policy", "")
        if has_code and (not ref_pol or ref_pol.lower() not in ["no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"]):
            self.add_finding(
                "Low",
                "Callback response lacks strong Referrer-Policy",
                host,
                "Referrer-Policy=%s" % safe_value(ref_pol),
                full_url,
                "The callback handled an authorization code but the response did not include a strong Referrer-Policy. Subsequent external navigations or resources may leak the full callback URL.",
                "Set Referrer-Policy: no-referrer or same-origin on callback and post-login pages.",
                messageInfo
            )

        csp = resp_headers.get("content-security-policy", "")
        if has_code and not csp:
            self.add_finding(
                "Low",
                "Callback response lacks Content-Security-Policy",
                host,
                "CSP absent on callback response",
                full_url,
                "The callback response handled OAuth parameters without a CSP header. XSS or supply-chain issues on callback pages can directly expose codes/tokens.",
                "Apply a strict CSP. Avoid third-party scripts and inline scripts on callback pages before OAuth parameters are cleared.",
                messageInfo
            )
        elif has_code and "script-src" in csp.lower() and "'unsafe-inline'" in csp.lower():
            self.add_finding(
                "Medium",
                "Callback CSP allows unsafe inline script",
                host,
                "script-src contains unsafe-inline",
                full_url,
                "The callback response has CSP but allows inline script. If any OAuth parameter is reflected or DOM-parsed unsafely, token/code theft becomes easier.",
                "Remove unsafe-inline from script-src on callback pages; use nonces/hashes and sanitize reflected parameters.",
                messageInfo
            )

        # Passive reflection heuristic for dangerous OAuth parameters.
        body_lower = (resp_body or "").lower()
        for pname in ["state", "error", "error_description", "returnto", "next", "redirect"]:
            if pname in params:
                val = first(params, pname)
                if val and len(val) >= 8 and val.lower() in body_lower:
                    self.add_finding(
                        "Medium",
                        "Callback/error page reflects OAuth parameter",
                        host,
                        "%s reflected in response body" % pname,
                        full_url,
                        "A callback or error page appears to reflect an OAuth parameter value in the response body. This can become XSS if encoding is incomplete.",
                        "Verify output encoding manually with harmless canaries. Avoid reflecting raw state/error/appState/returnTo values.",
                        messageInfo
                    )

    def _check_token_request_response(self, host, full_url, path, method, req_headers, body_params, resp_headers, resp_body, messageInfo):
        if not is_token_path(path):
            return
        grant_type = first(body_params, "grant_type")
        if grant_type != "authorization_code":
            return

        code = first(body_params, "code")
        verifier = first(body_params, "code_verifier")
        redirect_uri = first(body_params, "redirect_uri")
        client_secret = first(body_params, "client_secret")
        authz = req_headers.get("authorization", "")

        public_like = (not client_secret and not authz)

        if code:
            self.observed_code_uses[code] = self.observed_code_uses.get(code, 0) + 1
            if self.observed_code_uses.get(code, 0) > 1:
                self.add_finding(
                    "Medium",
                    "Authorization code observed more than once at token endpoint",
                    host,
                    "same code value seen %d times" % self.observed_code_uses.get(code, 0),
                    full_url,
                    "The same authorization code appeared in multiple token endpoint requests in this Burp session. This may be a replay/retry or testing artifact.",
                    "Confirm the server rejects code reuse with invalid_grant and does not issue tokens more than once for the same code.",
                    messageInfo
                )

        if public_like and not verifier:
            self.add_finding(
                "High",
                "Public-looking token exchange missing code_verifier",
                host,
                "grant_type=authorization_code no client auth no code_verifier",
                full_url,
                "The token exchange appears to be from a public browser/mobile client and lacks a PKCE code_verifier. If accepted, stolen codes could be redeemed.",
                "Require PKCE S256 for public clients and reject authorization_code exchanges without a matching code_verifier.",
                messageInfo
            )
        elif verifier and len(verifier) < 43:
            self.add_finding(
                "Medium",
                "Short PKCE code_verifier observed",
                host,
                "code_verifier length=%d" % len(verifier),
                full_url,
                "PKCE code_verifier should be high entropy and at least 43 characters per the PKCE syntax range.",
                "Generate a high-entropy verifier of 43-128 allowed characters and use S256 challenge method.",
                messageInfo
            )

        if code and code in self.observed_codes:
            state = self.observed_codes.get(code)
            meta = self.observed_authz.get(state, {})
            expected_redirect = meta.get("redirect_uri")
            if expected_redirect and redirect_uri and expected_redirect != redirect_uri:
                self.add_finding(
                    "High",
                    "Token exchange redirect_uri differs from authorization request",
                    host,
                    "authorize redirect_uri != token redirect_uri",
                    full_url,
                    "The token request redirect_uri differs from the redirect_uri observed for the matching authorization response state/code in this Burp session.",
                    "Ensure the authorization server binds code to exact client_id, redirect_uri, and PKCE verifier.",
                    messageInfo
                )

        # Token endpoint response header/cache/CORS checks.
        has_tokens = ("access_token" in resp_body or "id_token" in resp_body or JWT_RE.search(resp_body or "") is not None)
        if has_tokens:
            cc = resp_headers.get("cache-control", "")
            pragma = resp_headers.get("pragma", "")
            if "no-store" not in cc.lower():
                self.add_finding(
                    "Medium",
                    "Token endpoint response missing Cache-Control no-store",
                    host,
                    "Cache-Control=%s" % safe_value(cc),
                    full_url,
                    "A token endpoint response appeared to contain tokens but lacked Cache-Control: no-store.",
                    "Set Cache-Control: no-store and Pragma: no-cache on token responses.",
                    messageInfo
                )
            if "no-cache" not in pragma.lower() and "no-cache" not in cc.lower():
                self.add_finding(
                    "Low",
                    "Token endpoint response missing no-cache directive",
                    host,
                    "Pragma=%s Cache-Control=%s" % (safe_value(pragma), safe_value(cc)),
                    full_url,
                    "Token responses should not be cached by intermediaries or browsers.",
                    "Use Cache-Control: no-store and Pragma: no-cache.",
                    messageInfo
                )
            acao = resp_headers.get("access-control-allow-origin", "")
            origin = req_headers.get("origin", "")
            if acao == "*":
                self.add_finding(
                    "High",
                    "Token endpoint allows wildcard CORS on token response",
                    host,
                    "Access-Control-Allow-Origin=*",
                    full_url,
                    "The token endpoint returned tokens and wildcard CORS. This can expose token responses to arbitrary origins when credentials or bearer-like flows are involved.",
                    "Restrict CORS to exact trusted application origins and avoid wildcard CORS on token endpoints.",
                    messageInfo
                )
            elif acao and origin and acao != origin:
                self.add_finding(
                    "Low",
                    "Token endpoint CORS origin differs from request origin",
                    host,
                    "Origin=%s ACAO=%s" % (origin, acao),
                    full_url,
                    "The token response CORS header did not match the request Origin. This may be benign but is worth reviewing.",
                    "Restrict token endpoint CORS to intended origins only.",
                    messageInfo
                )

    def _check_redirect_response(self, host, full_url, status, resp_headers, messageInfo):
        if status is None or status < 300 or status >= 400:
            return
        loc = resp_headers.get("location", "")
        if not loc:
            return
        abs_loc = make_absolute_url(full_url, loc)
        lparsed = urlparse.urlparse(abs_loc)
        lhost = safe_lower(lparsed.hostname)
        allowed_hosts = self.get_allowed_hosts()
        callback_hosts = self.get_callback_hosts()
        collab_host = self.get_collab_host()
        loc_params = parse_qs(lparsed.query)
        fragment_params = parse_qs(lparsed.fragment)
        combined_names = set(loc_params.keys()) | set(fragment_params.keys())
        sensitive = sorted(list(combined_names.intersection(TOKENISH_PARAM_NAMES)))
        external = bool(lhost and allowed_hosts and lhost not in allowed_hosts and lhost not in callback_hosts)
        is_collab = bool(collab_host and (lhost == collab_host or lhost.endswith("." + collab_host)))

        if sensitive and external:
            sev = "Critical" if ("access_token" in sensitive or "id_token" in sensitive or "code" in sensitive) else "High"
            self.add_finding(
                sev,
                "OAuth code/token redirected to external host",
                host,
                "Location host=%s params=%s" % (lhost, ",".join(sensitive)),
                full_url,
                "A redirect response points to an external host and carries OAuth-sensitive parameters in the query or fragment. This can lead to token or authorization code theft.",
                "Confirm with test accounts only. Fix by exact redirect URI allowlisting, removing callback open redirects, and stripping sensitive parameters before navigation.",
                messageInfo
            )
        elif external:
            evidence = "Location host=%s" % lhost
            if is_collab:
                evidence += " collaborator/collector match"
            self.add_finding(
                "Medium" if is_collab else "Low",
                "External redirect observed in SSO path",
                host,
                evidence,
                full_url,
                "A redirect to a host outside the configured allowed/callback list was observed. It may be benign, an IdP redirect, or an open redirect chain depending on context.",
                "Review whether this external redirect is expected. If it is a returnTo/next/appState redirect, enforce a strict allowlist or local-path-only policy.",
                messageInfo
            )

    def _check_referrer_leak(self, host, full_url, req_headers, messageInfo):
        ref = req_headers.get("referer", "") or req_headers.get("referrer", "")
        if not ref:
            return
        parsed_ref = urlparse.urlparse(ref)
        ref_params = parse_qs(parsed_ref.query)
        frag_params = parse_qs(parsed_ref.fragment)
        sensitive = sorted(list((set(ref_params.keys()) | set(frag_params.keys())).intersection(TOKENISH_PARAM_NAMES)))
        if not sensitive:
            return
        allowed_hosts = self.get_allowed_hosts()
        callback_hosts = self.get_callback_hosts()
        current_host_allowed = (not allowed_hosts) or host in allowed_hosts or host in callback_hosts
        if not current_host_allowed:
            self.add_finding(
                "High",
                "OAuth code/token leaked in Referer to external host",
                host,
                "Referer contains params=%s" % ",".join(sensitive),
                full_url,
                "The request's Referer header contains OAuth-sensitive parameters from a previous URL and was sent to a host outside the configured allowed/callback list.",
                "Set Referrer-Policy: no-referrer or same-origin on callback pages. Strip query/fragment immediately after processing OAuth response parameters.",
                messageInfo
            )
        else:
            self.add_finding(
                "Medium",
                "OAuth code/token present in Referer header",
                host,
                "Referer contains params=%s" % ",".join(sensitive),
                full_url,
                "The request's Referer header contains OAuth-sensitive parameters. It was sent to a trusted host, but this still increases leakage risk if any third-party resources are loaded.",
                "Avoid leaving codes/tokens in URLs. Use strong Referrer-Policy and immediate history.replaceState cleanup.",
                messageInfo
            )

    def _check_cookies(self, host, full_url, resp_headers, messageInfo):
        set_cookies = resp_headers_all(resp_headers, "set-cookie")
        for cookie in set_cookies:
            cname = cookie.split("=", 1)[0].strip()
            lower = cookie.lower()
            is_sessionish = any([hint in cname.lower() for hint in SESSION_COOKIE_HINTS])
            if not is_sessionish:
                continue
            missing = []
            if "secure" not in lower:
                missing.append("Secure")
            if "httponly" not in lower and "csrf" not in cname.lower() and "xsrf" not in cname.lower():
                missing.append("HttpOnly")
            if "samesite" not in lower:
                missing.append("SameSite")
            if "samesite=none" in lower and "secure" not in lower:
                self.add_finding(
                    "High",
                    "Cookie uses SameSite=None without Secure",
                    host,
                    "cookie=%s" % cname,
                    full_url,
                    "A session/auth-like cookie uses SameSite=None but does not include Secure. Modern browsers may reject it, and it weakens transport protection.",
                    "Set Secure on all authentication cookies, especially SameSite=None cookies.",
                    messageInfo
                )
            elif missing:
                sev = "Medium" if ("Secure" in missing or "HttpOnly" in missing) else "Low"
                self.add_finding(
                    sev,
                    "Session/auth-like cookie missing security attributes",
                    host,
                    "cookie=%s missing=%s" % (cname, ",".join(missing)),
                    full_url,
                    "A cookie that appears auth/session-related is missing one or more hardening attributes.",
                    "Use Secure, HttpOnly for server-side session cookies, and an appropriate SameSite value. CSRF tokens may intentionally be readable by JavaScript, but auth cookies should not be.",
                    messageInfo
                )

    def _check_jwts(self, host, full_url, query_params, body_params, resp_body, messageInfo):
        sources = []
        for pname, vals in query_params.items():
            for val in vals:
                if JWT_RE.match(val or ""):
                    sources.append(("query:%s" % pname, val))
        for pname, vals in body_params.items():
            for val in vals:
                if JWT_RE.match(val or ""):
                    sources.append(("body:%s" % pname, val))
        body_hits = JWT_RE.findall(resp_body or "")
        for tok in body_hits[:5]:
            sources.append(("response-body", tok))
        for source, token in sources[:10]:
            decoded = decode_jwt_unverified(token)
            if not decoded:
                continue
            header, payload = decoded
            alg = header.get("alg")
            typ = header.get("typ")
            iss = payload.get("iss")
            aud = payload.get("aud")
            exp = payload.get("exp")
            nonce = payload.get("nonce")
            token_use = infer_token_use(payload)
            detail = []
            detail.append("JWT observed at %s." % source)
            detail.append("header.alg=%s typ=%s" % (safe_value(alg), safe_value(typ)))
            detail.append("payload.iss=%s" % safe_value(iss))
            detail.append("payload.aud=%s" % safe_value(aud))
            detail.append("payload.token_use/inferred=%s" % token_use)
            if exp:
                try:
                    ttl = int(exp) - int(time.time())
                    detail.append("approx TTL seconds=%d" % ttl)
                except Exception:
                    pass
            self.add_finding(
                "Info",
                "JWT observed and decoded passively",
                host,
                "source=%s alg=%s use=%s" % (source, safe_value(alg), token_use),
                full_url,
                "\n".join(detail),
                "Validate JWT signature, issuer, audience, expiry, nonce, and token type in the application/API. Do not treat this passive decode as verification.",
                messageInfo
            )
            if alg and str(alg).lower() == "none":
                self.add_finding(
                    "Critical",
                    "JWT uses alg=none",
                    host,
                    "source=%s" % source,
                    full_url,
                    "A JWT was observed with alg=none. If accepted by the application/API, this can allow token forgery.",
                    "Reject alg=none. Allowlist expected signing algorithms and verify signatures against trusted keys.",
                    messageInfo
                )
            if iss:
                expected_issuer = self.issuer_field.getText().strip()
                if expected_issuer and str(iss) != expected_issuer:
                    self.add_finding(
                        "Medium",
                        "JWT issuer differs from configured issuer",
                        host,
                        "iss=%s" % safe_value(iss),
                        full_url,
                        "A JWT issuer did not match the configured expected issuer. This may be a different IdP, a custom-domain mismatch, or issuer mix-up risk.",
                        "Applications and APIs should pin exact issuer and not accept tokens from unintended tenants or IdPs.",
                        messageInfo
                    )
            if aud:
                expected_aud = self.audience_field.getText().strip()
                expected_client = self.client_id_field.getText().strip()
                aud_values = aud if isinstance(aud, list) else [aud]
                aud_values = [str(x) for x in aud_values]
                if expected_aud and expected_aud not in aud_values and expected_client and expected_client not in aud_values:
                    self.add_finding(
                        "Medium",
                        "JWT audience differs from configured audience/client",
                        host,
                        "aud=%s" % safe_value(str(aud_values)),
                        full_url,
                        "A JWT audience does not include the configured API audience or client_id. This can indicate audience confusion if the token is accepted by this app/API.",
                        "APIs must reject tokens with the wrong aud. Web apps must validate ID Token aud against their client_id.",
                        messageInfo
                    )
            if token_use == "possible_id_token" and "openid" in (str(payload.get("scope", ""))):
                pass

    # ----------------------------------------------------------------------
    # Finding helpers
    # ----------------------------------------------------------------------
    def add_finding(self, severity, title, host, evidence, url, detail, remediation, messageInfo=None):
        redacted_url = redact_url(url)
        redacted_evidence = redact_string(evidence)
        key = "%s|%s|%s|%s|%s" % (severity, title, host, redacted_evidence, strip_query(redacted_url))
        if key in self.finding_fingerprints:
            return
        self.finding_fingerprints.add(key)
        f = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "severity": severity,
            "title": title,
            "host": host,
            "evidence": redacted_evidence,
            "url": redacted_url,
            "detail": redact_string(detail or ""),
            "remediation": remediation or "",
            "messageInfo": messageInfo
        }
        self.findings.append(f)

        def update():
            self.table_model.addRow([f["time"], f["severity"], f["title"], f["host"], f["evidence"], f["url"]])
        SwingUtilities.invokeLater(RunnableFn(update))

        if messageInfo is not None and self.add_burp_issues_checkbox.isSelected():
            try:
                self._callbacks.addScanIssue(CustomScanIssue(
                    messageInfo.getHttpService(),
                    self.safe_url_object(url),
                    [messageInfo],
                    title,
                    severity,
                    f.get("detail"),
                    remediation
                ))
            except Exception:
                # Burp issue creation should never break passive scanning.
                pass

    def safe_url_object(self, url):
        try:
            return self._helpers.analyzeRequest(self._helpers.buildHttpRequest(java_url(url))).getUrl()
        except Exception:
            try:
                from java.net import URL
                return URL(url)
            except Exception:
                return None

    # ----------------------------------------------------------------------
    # Config helpers
    # ----------------------------------------------------------------------
    def get_allowed_hosts(self):
        hosts = []
        text = self.allowed_hosts_area.getText() or ""
        for line in text.splitlines():
            v = line.strip()
            if not v:
                continue
            if "://" in v:
                h = urlparse.urlparse(v).hostname
                if h:
                    hosts.append(safe_lower(h))
            else:
                hosts.append(safe_lower(v))
        return set([h for h in hosts if h])

    def get_callback_hosts(self):
        hosts = []
        text = self.callback_urls_area.getText() or ""
        for line in text.splitlines():
            v = line.strip()
            if not v:
                continue
            if "://" in v:
                h = urlparse.urlparse(v).hostname
                if h:
                    hosts.append(safe_lower(h))
            else:
                hosts.append(safe_lower(v))
        return set([h for h in hosts if h])

    def get_collab_host(self):
        v = self.collab_host_field.getText().strip()
        if not v:
            return ""
        if "://" in v:
            h = urlparse.urlparse(v).hostname
            return safe_lower(h)
        return safe_lower(v.split("/")[0])

    # ----------------------------------------------------------------------
    # Body helpers
    # ----------------------------------------------------------------------
    def _get_request_body(self, request, req_info):
        try:
            s = self._helpers.bytesToString(request)
            return s[req_info.getBodyOffset():]
        except Exception:
            return ""

    def _get_response_body(self, response, resp_info, max_len):
        try:
            s = self._helpers.bytesToString(response)
            start = resp_info.getBodyOffset()
            return s[start:start + max_len]
        except Exception:
            return ""


class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, severity, detail, remediation):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._severity = severity
        self._detail = detail
        self._remediation = remediation

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return "SSO Auditor: " + self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        if self._severity == "Critical":
            return "High"
        if self._severity == "Info":
            return "Information"
        return self._severity

    def getConfidence(self):
        return "Tentative"

    def getIssueBackground(self):
        return "Passive OAuth/OIDC/Auth0 observation generated while browsing through Burp. Treat as a lead unless the detail clearly demonstrates code/token leakage."

    def getRemediationBackground(self):
        return "Use exact redirect URI allowlists, Authorization Code + PKCE S256, strict state/nonce validation, strict JWT issuer/audience/signature validation, secure callback pages, and least-privilege Auth0 tenant configuration."

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return self._remediation

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService


# --------------------------------------------------------------------------
# Standalone helper functions
# --------------------------------------------------------------------------

def java_url(url):
    from java.net import URL
    return URL(url)


def java_file(path):
    from java.io import File
    return File(path)


def safe_lower(v):
    if v is None:
        return ""
    return str(v).lower()


def first(params, name):
    vals = params.get(name)
    if not vals:
        # case-insensitive fallback for Auth0Client/auth0client and similar
        lname = name.lower()
        for k, v in params.items():
            if k.lower() == lname and v:
                return v[0]
        return ""
    return vals[0]


def parse_qs(qs):
    if not qs:
        return {}
    try:
        # If a full URL accidentally arrives, parse its query/fragment.
        if "://" in qs:
            p = urlparse.urlparse(qs)
            qs = p.query or p.fragment or ""
        return urlparse.parse_qs(str(qs), keep_blank_values=True)
    except Exception:
        return {}


def headers_to_dict(headers):
    d = {}
    mult = {}
    try:
        for h in list(headers)[1:]:
            h = str(h)
            if ":" not in h:
                continue
            k, v = h.split(":", 1)
            lk = k.strip().lower()
            val = v.strip()
            if lk in d:
                # Keep first value for simple lookups, all values for set-cookie etc.
                mult.setdefault(lk, [d[lk]]).append(val)
            else:
                d[lk] = val
        for k, vals in mult.items():
            d["__multi__" + k] = vals
    except Exception:
        pass
    return d


def resp_headers_all(headers, name):
    lname = name.lower()
    vals = []
    if lname in headers:
        vals.append(headers.get(lname))
    vals.extend(headers.get("__multi__" + lname, []))
    return [v for v in vals if v]


def looks_form_encoded(headers, body):
    ct = headers.get("content-type", "").lower()
    if "application/x-www-form-urlencoded" in ct:
        return True
    if body and "grant_type=" in body and "&" in body:
        return True
    return False


def is_authorize_path(path):
    p = (path or "").lower()
    return p.endswith("/authorize") or p == "/authorize"


def is_token_path(path):
    p = (path or "").lower()
    return p.endswith("/oauth/token") or p.endswith("/token")


def safe_value(v):
    if v is None:
        return ""
    s = str(v)
    if len(s) > 160:
        return s[:80] + "..." + s[-40:]
    return s


def shorten(v):
    if not v:
        return ""
    s = str(v)
    if len(s) <= 12:
        return s
    return s[:6] + "..." + s[-4:]


def strip_query(url):
    try:
        p = urlparse.urlparse(url)
        return urlparse.urlunparse((p.scheme, p.netloc, p.path, "", "", ""))
    except Exception:
        return url


def redact_string(s):
    if s is None:
        return ""
    s = str(s)
    s = JWT_RE.sub("[JWT_REDACTED]", s)
    # Redact common query/body parameter values in free-form text.
    for name in SENSITIVE_PARAM_NAMES:
        s = re.sub(r"(?i)(%s=)[^&\s]+" % re.escape(name), r"\1[REDACTED]", s)
    s = re.sub(r"(?i)(authorization:\s*bearer\s+)[A-Za-z0-9._\-]+", r"\1[REDACTED]", s)
    return s


def redact_url(url):
    try:
        p = urlparse.urlparse(str(url))
        q = redact_qs(p.query)
        f = redact_qs(p.fragment)
        return urlparse.urlunparse((p.scheme, p.netloc, p.path, p.params, q, f))
    except Exception:
        return redact_string(url)


def redact_qs(qs):
    if not qs:
        return qs
    parts = []
    for part in qs.split("&"):
        if "=" not in part:
            parts.append(part)
            continue
        k, v = part.split("=", 1)
        if k.lower() in SENSITIVE_PARAM_NAMES:
            parts.append(k + "=[REDACTED]")
        else:
            parts.append(k + "=" + v)
    return "&".join(parts)


def make_absolute_url(base, loc):
    try:
        return urlparse.urljoin(base, loc)
    except Exception:
        return loc


def b64url_decode(data):
    try:
        s = str(data)
        s = s.replace("-", "+").replace("_", "/")
        s += "=" * ((4 - len(s) % 4) % 4)
        return base64.b64decode(s)
    except Exception:
        return None


def decode_jwt_unverified(token):
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        header_raw = b64url_decode(parts[0])
        payload_raw = b64url_decode(parts[1])
        if not header_raw or not payload_raw:
            return None
        header = json.loads(header_raw)
        payload = json.loads(payload_raw)
        return header, payload
    except Exception:
        return None


def infer_token_use(payload):
    if not payload:
        return "unknown"
    if "nonce" in payload or "auth_time" in payload:
        return "possible_id_token"
    if "scope" in payload or "permissions" in payload or "azp" in payload:
        return "possible_access_token"
    return "jwt"
