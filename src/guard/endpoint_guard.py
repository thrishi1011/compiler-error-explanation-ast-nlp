"""
endpoint_guard.py
-----------------
EndpointGuard inspects incoming HTTP request headers and payload bodies
to protect the local IDE web server from cross-site requests, clickjacking,
resource exhaustion, malformed JSON, and unauthorized access.
"""

from __future__ import annotations

import hmac
import json
from typing import Any
from urllib.parse import urlparse

from .base import GuardAgent, GuardContext
from .config import ENDPOINT_MAX_BODY, ENDPOINT_MAX_CODE_CHARS
from .models import Finding, InputKind


class EndpointGuard(GuardAgent):
    """
    Guards HTTP requests at two stages:
    1. 'headers': Host, Origin, Sec-Fetch-*, Content-Type, Content-Length,
       Transfer-Encoding, and X-Guard-Token.
    2. 'body': Validates JSON format, object structure, code type, size cap,
       and absence of NUL bytes.
    """

    name = "EndpointGuard"
    handles = {InputKind.HTTP_REQUEST}
    agent_type = "attack"

    def quick_match(self, ctx: GuardContext) -> bool:
        return ctx.kind == InputKind.HTTP_REQUEST

    def analyze(self, ctx: GuardContext) -> list[Finding]:
        findings: list[Finding] = []
        meta = ctx.meta or {}
        stage = meta.get("stage", "headers")
        method = str(meta.get("method", "GET")).upper()
        path = str(meta.get("path", "/"))
        server_port = meta.get("server_port")
        expected_token = meta.get("expected_token")

        headers_raw = meta.get("headers", {})
        headers = {str(k).lower(): str(v) for k, v in headers_raw.items()}

        if stage == "headers":
            # 1. bad_host (403)
            host = headers.get("host")
            if host:
                host_val = host.strip().lower()
                valid_hosts = {"localhost", "127.0.0.1"}
                if server_port is not None:
                    valid_hosts.add(f"localhost:{server_port}")
                    valid_hosts.add(f"127.0.0.1:{server_port}")
                if host_val not in valid_hosts:
                    findings.append(
                        self._make_finding(
                            category="bad_host",
                            http_status=403,
                            title="Invalid Host Header",
                            description="Host header does not match local server address.",
                            evidence="Host header mismatch",
                        )
                    )

            # 2. bad_origin (403)
            if "origin" in headers:
                origin_val = headers["origin"].strip()
                if origin_val.lower() == "null":
                    findings.append(
                        self._make_finding(
                            category="bad_origin",
                            http_status=403,
                            title="Invalid Origin Header",
                            description="Origin 'null' is rejected.",
                            evidence="Origin header is null",
                        )
                    )
                else:
                    parsed = urlparse(origin_val)
                    origin_port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
                    port_mismatch = False
                    if server_port is not None:
                        if parsed.port is not None and parsed.port != server_port:
                            port_mismatch = True
                        elif parsed.port is None and server_port not in (80, 443):
                            port_mismatch = True

                    if parsed.hostname not in {"localhost", "127.0.0.1"} or port_mismatch:
                        findings.append(
                            self._make_finding(
                                category="bad_origin",
                                http_status=403,
                                title="Invalid Origin Header",
                                description="Origin does not match loopback server origin and port.",
                                evidence="Origin header mismatch",
                            )
                        )

            # 3. cross_site_request (403)
            sec_site = headers.get("sec-fetch-site")
            if sec_site and sec_site.strip().lower() not in {"same-origin", "none"}:
                findings.append(
                    self._make_finding(
                        category="cross_site_request",
                        http_status=403,
                        title="Cross-Site Request Blocked",
                        description="Sec-Fetch-Site indicates a cross-site or cross-origin request.",
                        evidence="Sec-Fetch-Site violation",
                    )
                )

            sec_dest = headers.get("sec-fetch-dest")
            if sec_dest and sec_dest.strip().lower() in {"iframe", "frame", "embed", "object"}:
                findings.append(
                    self._make_finding(
                        category="cross_site_request",
                        http_status=403,
                        title="Embedded Context Request Blocked",
                        description="Sec-Fetch-Dest indicates request originating from framing/embedding context.",
                        evidence="Sec-Fetch-Dest framing violation",
                    )
                )

            # POST-specific header checks
            if method == "POST":
                # 4. unsupported_encoding (400)
                if "transfer-encoding" in headers:
                    findings.append(
                        self._make_finding(
                            category="unsupported_encoding",
                            http_status=400,
                            title="Unsupported Transfer-Encoding",
                            description="Chunked or non-standard transfer encodings are not supported.",
                            evidence="Transfer-Encoding header present",
                        )
                    )

                # 5. bad_content_type (415)
                ct = headers.get("content-type", "")
                base_ct = ct.split(";")[0].strip().lower()
                if base_ct != "application/json":
                    findings.append(
                        self._make_finding(
                            category="bad_content_type",
                            http_status=415,
                            title="Unsupported Content-Type",
                            description="POST endpoints require 'application/json' media type.",
                            evidence="Content-Type header mismatch",
                        )
                    )

                # 6. Content-Length checks: missing_length (411), bad_length (400), body_too_large (413)
                cl = headers.get("content-length")
                if cl is None:
                    findings.append(
                        self._make_finding(
                            category="missing_length",
                            http_status=411,
                            title="Missing Content-Length Header",
                            description="POST requests must specify Content-Length.",
                            evidence="Content-Length header missing",
                        )
                    )
                else:
                    try:
                        cl_int = int(cl.strip())
                        if cl_int < 0:
                            findings.append(
                                self._make_finding(
                                    category="bad_length",
                                    http_status=400,
                                    title="Invalid Content-Length",
                                    description="Content-Length must be non-negative.",
                                    evidence="Content-Length header negative",
                                )
                            )
                        elif cl_int > ENDPOINT_MAX_BODY:
                            findings.append(
                                self._make_finding(
                                    category="body_too_large",
                                    http_status=413,
                                    title="Payload Too Large",
                                    description=f"Content-Length exceeds maximum allowed body size of {ENDPOINT_MAX_BODY} bytes.",
                                    evidence="Content-Length header exceeds limit",
                                )
                            )
                    except ValueError:
                        findings.append(
                            self._make_finding(
                                category="bad_length",
                                http_status=400,
                                title="Invalid Content-Length",
                                description="Content-Length must be an integer.",
                                evidence="Content-Length header invalid integer",
                            )
                        )

                # 7. bad_token (403)
                token = headers.get("x-guard-token")
                token_valid = (
                    token is not None
                    and expected_token is not None
                    and hmac.compare_digest(str(token), str(expected_token))
                )
                if not token_valid:
                    findings.append(
                        self._make_finding(
                            category="bad_token",
                            http_status=403,
                            title="Missing or Invalid Session Token",
                            description="POST requests require a valid X-Guard-Token header.",
                            evidence="X-Guard-Token header mismatch or missing",
                        )
                    )

        elif stage == "body":
            raw_body = ctx.payload or ""
            # 1. bad_json (400)
            try:
                data = json.loads(raw_body)
                if not isinstance(data, dict):
                    findings.append(
                        self._make_finding(
                            category="bad_json",
                            http_status=400,
                            title="Malformed JSON Body",
                            description="JSON payload must be an object.",
                            evidence="Body is not a JSON object",
                        )
                    )
                    return findings
            except Exception:
                findings.append(
                    self._make_finding(
                        category="bad_json",
                        http_status=400,
                        title="Malformed JSON Syntax",
                        description="Failed to parse request body as JSON.",
                        evidence="Invalid JSON syntax",
                    )
                )
                return findings

            # 2. bad_body (400)
            code = data.get("code")
            if code is None or not isinstance(code, str):
                findings.append(
                    self._make_finding(
                        category="bad_body",
                        http_status=400,
                        title="Missing Code Field",
                        description="Request body must contain string field 'code'.",
                        evidence="Missing or non-string code field",
                    )
                )
            elif len(code) > ENDPOINT_MAX_CODE_CHARS:
                findings.append(
                    self._make_finding(
                        category="bad_body",
                        http_status=400,
                        title="Code Exceeds Character Limit",
                        description=f"Source code exceeds {ENDPOINT_MAX_CODE_CHARS} characters limit.",
                        evidence="Code length exceeds maximum allowed characters",
                    )
                )
            elif "\0" in code:
                findings.append(
                    self._make_finding(
                        category="bad_body",
                        http_status=400,
                        title="NUL Character in Source Code",
                        description="Source code contains embedded NUL byte.",
                        evidence="NUL byte present in code string",
                    )
                )

        return findings

    def _make_finding(
        self,
        *,
        category: str,
        http_status: int,
        title: str,
        description: str,
        evidence: str,
    ) -> Finding:
        return Finding(
            agents=[self.name],
            origin="attack",
            category=category,
            severity="High",
            title=title,
            description=description,
            recommendation="Adhere to web API requirements and session security policies.",
            line=1,
            column=1,
            evidence=evidence,
            action="block",
            confidence=1.0,
            blocks_on={"request"},
            details={"http_status": http_status},
        )
