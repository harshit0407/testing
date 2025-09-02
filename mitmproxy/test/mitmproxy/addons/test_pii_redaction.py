import json
import sys
import types

sys.modules.setdefault("mitmproxy_rs", types.SimpleNamespace())
from mitmproxy.addons.savehar import SaveHar
from mitmproxy.test import tflow, tutils


def build_flow_with_pii():
    req = tutils.treq(
        content=b"{"
        b"\"email\":\"user@example.com\","  # email
        b"\"token\":\"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc.def\","  # jwt-ish
        b"\"cc\":\"4111 1111 1111 1111\","  # credit card
        b"\"ip\":\"192.168.1.10\"}"  # ipv4
    )

    req.headers["X-Auth"] = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc.def"
    req.headers["X-Contact"] = "user@example.com"
    req.query["ip"] = "192.168.1.10"
    
    resp = tutils.tresp(
        content=b"{"
        b"\"email\":\"resp@example.com\","  # email
        b"\"cc\":\"4111-1111-1111-1111\"}"  # credit card
    )
    resp.headers["Location"] = "http://192.168.1.10/redirect?email=user@example.com"
    f = tflow.tflow(req=req, resp=resp)
    return f

def test_pii_redaction_in_har():
    s = SaveHar()
    har = s.make_har([build_flow_with_pii()])
    entry = har["log"]["entries"][0]

    # URL redacted
    assert "<redacted:ipv4>" in entry["request"]["url"]
    assert "user@example.com" not in entry["request"]["url"]

    # Headers redacted
    rh = {h["name"]: h["value"] for h in entry["request"]["headers"]}
    assert "<redacted:jwt>" in rh["X-Auth"]
    assert "<redacted:email>" == rh["X-Contact"]

    rq = {q["name"]: q["value"] for q in entry["request"]["queryString"]}
    assert rq["ip"] == "<redacted:ipv4>"

    assert "postData" not in entry["request"] or "<redacted:" not in json.dumps(entry["request"])  # no accidental redact marker

    rheaders = {h["name"]: h["value"] for h in entry["response"]["headers"]}
    assert "<redacted:ipv4>" in entry["response"]["redirectURL"]
    assert "<redacted:email>" in entry["response"]["redirectURL"]

    body = entry["response"]["content"].get("text", "")
    if entry["response"]["content"].get("encoding") != "base64":
        assert "<redacted:email>" in body
        assert "<redacted:cc>" in body


def test_post_body_redaction():
    s = SaveHar()

    req = tutils.treq(method=b"POST", content=b"email=post@example.com&ip=10.0.0.1")
    req.headers["Content-Type"] = "application/x-www-form-urlencoded"
    f = tflow.tflow(req=req, resp=tutils.tresp(content=b"ok"))
    har = s.make_har([f])
    entry = har["log"]["entries"][0]
    pd = entry["request"]["postData"]
    assert "<redacted:email>" in pd["text"]
    assert "<redacted:ipv4>" in pd["text"]
    params = {p["name"]: p["value"] for p in pd["params"]}
    assert params["email"] == "<redacted:email>"
    assert params["ip"] == "<redacted:ipv4>"