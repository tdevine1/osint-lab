from flask import Flask, request, jsonify, make_response, render_template_string, abort
import sqlite3
import json
import uuid
import ipaddress
import os
import time
from datetime import datetime, timezone

import requests
from ipwhois import IPWhois

app = Flask(__name__)
DB = "osint_lab.db"
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "change-this-now")

TOR_EXIT_CACHE = {
    "fetched_at": 0,
    "ips": set(),
    "error": None,
}

TOR_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"

PAGE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Connection Logged</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      max-width: 980px;
      margin: 32px auto;
      line-height: 1.5;
      background: #f7f7f7;
      color: #222;
    }
    .box {
      border: 1px solid #c33;
      border-radius: 12px;
      padding: 24px;
      background: #fff5f5;
      margin-bottom: 18px;
    }
    .panel {
      border: 1px solid #ddd;
      border-radius: 12px;
      padding: 20px;
      background: white;
      margin-bottom: 18px;
    }
    h1 { margin-top: 0; color: #a11; }
    h2 { margin-top: 0; }
    .small { color: #555; font-size: 0.95em; }
    .muted { color: #666; }
    ul { margin-top: 8px; }
    code {
      background: #f2f2f2;
      border-radius: 6px;
      padding: 2px 6px;
    }
  </style>
</head>
<body>
  <div class="box">
    <h1>Connection Logged</h1>
    <p>
      This is a monitored cybersecurity research and training endpoint.
      Standard connection metadata associated with your visit has been recorded.
    </p>
    <p>
      Records associated with suspected fraud or scam activity may be preserved
      for incident documentation and may be submitted through relevant platform
      abuse channels or lawful reporting processes.
    </p>
    <p class="small">
      Do not submit passwords, payment information, or personal documents on this page.
    </p>
  </div>

  <div class="panel">
    <h2>What this site can see from a normal visit</h2>
    <ul>
      <li><strong>Network address:</strong> <span id="ip">Loading...</span></li>
      <li><strong>Approximate network owner / ASN:</strong> <span id="asn">Loading...</span></li>
      <li><strong>Network type guess:</strong> <span id="network_type">Loading...</span></li>
      <li><strong>Tor exit node:</strong> <span id="tor">Loading...</span></li>
      <li><strong>Browser:</strong> <span id="ua">Loading...</span></li>
      <li><strong>Language:</strong> <span id="lang">Loading...</span></li>
      <li><strong>Timezone:</strong> <span id="tz">Loading...</span></li>
      <li><strong>Platform:</strong> <span id="platform">Loading...</span></li>
      <li><strong>Screen:</strong> <span id="screen">Loading...</span></li>
      <li><strong>CPU cores exposed:</strong> <span id="cores">Loading...</span></li>
      <li><strong>Cookie enabled:</strong> <span id="cookies">Loading...</span></li>
      <li><strong>Touch points:</strong> <span id="touch">Loading...</span></li>
      <li><strong>Referrer:</strong> <span id="ref">Loading...</span></li>
    </ul>
  </div>

  <div class="panel">
    <h2>Why this matters</h2>
    <p class="muted">
      A single click to a controlled page can reveal standard metadata that helps
      defenders document abuse, study attribution limits, and teach safe browsing practices.
    </p>
  </div>

  <script>
    async function collectClientInfo() {
      const payload = {
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || null,
        language: navigator.language || null,
        languages: navigator.languages || [],
        platform: navigator.platform || null,
        userAgent: navigator.userAgent || null,
        hardwareConcurrency: navigator.hardwareConcurrency || null,
        cookieEnabled: navigator.cookieEnabled,
        touchPoints: navigator.maxTouchPoints || 0,
        screen: {
          width: window.screen.width,
          height: window.screen.height,
          availWidth: window.screen.availWidth,
          availHeight: window.screen.availHeight,
          colorDepth: window.screen.colorDepth
        },
        windowSize: {
          innerWidth: window.innerWidth,
          innerHeight: window.innerHeight
        },
        referrer: document.referrer || null
      };

      document.getElementById("ua").textContent = payload.userAgent || "Unknown";
      document.getElementById("lang").textContent = payload.language || "Unknown";
      document.getElementById("tz").textContent = payload.timezone || "Unknown";
      document.getElementById("platform").textContent = payload.platform || "Unknown";
      document.getElementById("screen").textContent =
        payload.screen.width + " x " + payload.screen.height;
      document.getElementById("cores").textContent =
        payload.hardwareConcurrency ?? "Unknown";
      document.getElementById("cookies").textContent =
        payload.cookieEnabled ? "Yes" : "No";
      document.getElementById("touch").textContent =
        payload.touchPoints;
      document.getElementById("ref").textContent =
        payload.referrer || "None";

      try {
        const r = await fetch("/collect", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify(payload),
          credentials: "include"
        });

        const data = await r.json();

        document.getElementById("ip").textContent =
          data.client_ip || "Unavailable";

        document.getElementById("asn").textContent =
          data.asn_summary || "Unavailable";

        document.getElementById("network_type").textContent =
          data.network_type || "Unknown";

        document.getElementById("tor").textContent =
          data.is_tor_exit === true ? "Likely yes" :
          data.is_tor_exit === false ? "No current Tor match" :
          "Unknown";
      } catch (e) {
        document.getElementById("ip").textContent = "Unavailable";
        document.getElementById("asn").textContent = "Unavailable";
        document.getElementById("network_type").textContent = "Unavailable";
        document.getElementById("tor").textContent = "Unavailable";
      }
    }

    collectClientInfo();
  </script>
</body>
</html>
"""

def init_db():
    with sqlite3.connect(DB) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS visits (
                id TEXT PRIMARY KEY,
                created_utc TEXT NOT NULL,
                path TEXT,
                query_string TEXT,
                client_ip TEXT,
                x_forwarded_for TEXT,
                x_azure_clientip TEXT,
                remote_addr TEXT,
                user_agent_header TEXT,
                accept_language TEXT,
                referer_header TEXT,
                cookie_id TEXT,
                asn_json TEXT,
                network_classification_json TEXT,
                client_json TEXT,
                headers_json TEXT
            )
        """)
        conn.commit()

def is_public_ip(ip: str) -> bool:
    try:
        parsed = ipaddress.ip_address(ip)
        return not (
            parsed.is_private
            or parsed.is_loopback
            or parsed.is_reserved
            or parsed.is_link_local
            or parsed.is_multicast
            or parsed.is_unspecified
        )
    except ValueError:
        return False

def get_client_ip():
    """
    Prefer Azure/App Service forwarding headers.
    In X-Forwarded-For, the first IP is typically the original client.
    """
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        candidates = [ip.strip() for ip in xff.split(",") if ip.strip()]
        for ip in candidates:
            if is_public_ip(ip):
                return ip
        for ip in candidates:
            try:
                ipaddress.ip_address(ip)
                return ip
            except ValueError:
                pass

    azure_client_ip = request.headers.get("X-Azure-ClientIP")
    if azure_client_ip:
        azure_client_ip = azure_client_ip.strip()
        if is_public_ip(azure_client_ip):
            return azure_client_ip
        try:
            ipaddress.ip_address(azure_client_ip)
            return azure_client_ip
        except ValueError:
            pass

    remote = request.remote_addr
    if remote:
        return remote

    return None

def enrich_ip(ip):
    if not ip:
        return None

    try:
        parsed = ipaddress.ip_address(ip)
        if (
            parsed.is_private
            or parsed.is_loopback
            or parsed.is_reserved
            or parsed.is_link_local
            or parsed.is_multicast
            or parsed.is_unspecified
        ):
            return {
                "ip": ip,
                "note": "Non-public or reserved address"
            }
    except ValueError:
        return {
            "ip": ip,
            "note": "Invalid IP format"
        }

    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap(depth=1)

        network = result.get("network") or {}

        return {
            "ip": ip,
            "asn": result.get("asn"),
            "asn_description": result.get("asn_description"),
            "network_name": network.get("name"),
            "network_cidr": network.get("cidr"),
            "network_country": network.get("country"),
            "network_handle": network.get("handle")
        }
    except Exception as e:
        return {
            "ip": ip,
            "note": f"ASN lookup failed: {type(e).__name__}"
        }

def format_asn_summary(asn_data):
    if not asn_data:
        return None

    if asn_data.get("asn") or asn_data.get("asn_description") or asn_data.get("network_name"):
        parts = []
        if asn_data.get("asn"):
            parts.append(f"AS{asn_data['asn']}")
        if asn_data.get("asn_description"):
            parts.append(asn_data["asn_description"])
        if asn_data.get("network_name"):
            parts.append(f"Network: {asn_data['network_name']}")
        return " | ".join(parts)

    return asn_data.get("note")

def get_tor_exit_ips(force_refresh=False):
    """
    Fetch Tor exit list and cache it for 1 hour.
    If fetch fails, return stale cache if available.
    """
    now = time.time()
    cache_age = now - TOR_EXIT_CACHE["fetched_at"]

    if not force_refresh and TOR_EXIT_CACHE["ips"] and cache_age < 3600:
        return TOR_EXIT_CACHE["ips"]

    try:
        resp = requests.get(TOR_EXIT_LIST_URL, timeout=10)
        resp.raise_for_status()
        ips = {
            line.strip()
            for line in resp.text.splitlines()
            if line.strip() and not line.startswith("#")
        }
        TOR_EXIT_CACHE["ips"] = ips
        TOR_EXIT_CACHE["fetched_at"] = now
        TOR_EXIT_CACHE["error"] = None
        return ips
    except Exception as e:
        TOR_EXIT_CACHE["error"] = type(e).__name__
        return TOR_EXIT_CACHE["ips"]

def is_tor_exit_node(ip):
    if not ip or not is_public_ip(ip):
        return None
    tor_ips = get_tor_exit_ips()
    if not tor_ips:
        return None
    return ip in tor_ips

def classify_network(ip, asn_data):
    """
    Best-effort heuristic classification.
    This is intentionally conservative and should be treated as a guess.
    """
    result = {
        "network_type": "Unknown",
        "confidence": "low",
        "reasons": [],
        "is_tor_exit": is_tor_exit_node(ip)
    }

    if not ip:
        result["network_type"] = "Unavailable"
        result["reasons"].append("No client IP available")
        return result

    if not is_public_ip(ip):
        result["network_type"] = "Internal / reserved"
        result["confidence"] = "high"
        result["reasons"].append("IP is non-public or reserved")
        return result

    haystack = " ".join(
        str(x or "")
        for x in [
            asn_data.get("asn_description") if asn_data else "",
            asn_data.get("network_name") if asn_data else "",
            asn_data.get("network_handle") if asn_data else "",
        ]
    ).lower()

    if result["is_tor_exit"] is True:
        result["network_type"] = "Tor exit node"
        result["confidence"] = "high"
        result["reasons"].append("IP appears in current Tor exit list")
        return result

    cloud_keywords = [
        "amazon", "aws", "ec2", "microsoft", "azure", "google", "gcp",
        "digitalocean", "linode", "akamai", "oracle", "ovh", "vultr",
        "choopa", "hetzner", "alibaba", "tencent", "scaleway", "contabo"
    ]
    vpn_keywords = [
        "vpn", "virtual private", "hosting", "datacenter", "data center",
        "m247", "colo", "colocation", "anonymous", "anonymizer", "proxy"
    ]
    mobile_keywords = [
        "wireless", "cellular", "mobile", "t-mobile", "verizon wireless",
        "at&t mobility", "att mobility", "sprint", "us cellular"
    ]
    residential_keywords = [
        "comcast", "xfinity", "charter", "spectrum", "cox", "optimum",
        "frontier", "rogers", "shaw", "bell canada", "residential",
        "consumer", "broadband", "cable", "fios"
    ]
    business_keywords = [
        "business", "enterprise", "corp", "corporation", "university",
        "college", "school district", "hospital", "bank", "government"
    ]

    if any(k in haystack for k in cloud_keywords):
        result["network_type"] = "Cloud / hosting provider"
        result["confidence"] = "medium"
        result["reasons"].append("ASN/network name matches known cloud or hosting keywords")

    if any(k in haystack for k in vpn_keywords):
        result["network_type"] = "VPN / anonymizer likely"
        result["confidence"] = "medium"
        result["reasons"].append("ASN/network name contains VPN / hosting / proxy indicators")

    if any(k in haystack for k in mobile_keywords):
        result["network_type"] = "Mobile carrier"
        result["confidence"] = "medium"
        result["reasons"].append("ASN/network name matches mobile carrier indicators")

    if any(k in haystack for k in residential_keywords):
        result["network_type"] = "Residential / consumer ISP likely"
        result["confidence"] = "medium"
        result["reasons"].append("ASN/network name matches consumer ISP indicators")

    if any(k in haystack for k in business_keywords):
        result["network_type"] = "Business / enterprise network likely"
        result["confidence"] = "low"
        result["reasons"].append("ASN/network name contains enterprise-style terms")

    if result["network_type"] == "Unknown":
        if asn_data and (asn_data.get("asn_description") or asn_data.get("network_name")):
            result["network_type"] = "Public network (type unclear)"
            result["confidence"] = "low"
            result["reasons"].append("Public IP with ASN ownership data, but no strong category match")

    return result

def get_request_headers_json():
    return json.dumps(dict(request.headers), default=str)

@app.route("/")
@app.route("/documents/notice")
def landing():
    init_db()

    visit_id = str(uuid.uuid4())
    cookie_id = request.cookies.get("lab_id") or str(uuid.uuid4())

    client_ip = get_client_ip()
    asn_data = enrich_ip(client_ip)
    classification = classify_network(client_ip, asn_data)

    with sqlite3.connect(DB) as conn:
        conn.execute("""
            INSERT INTO visits (
                id, created_utc, path, query_string, client_ip,
                x_forwarded_for, x_azure_clientip, remote_addr,
                user_agent_header, accept_language, referer_header,
                cookie_id, asn_json, network_classification_json,
                client_json, headers_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            visit_id,
            datetime.now(timezone.utc).isoformat(),
            request.path,
            request.query_string.decode("utf-8", errors="replace"),
            client_ip,
            request.headers.get("X-Forwarded-For"),
            request.headers.get("X-Azure-ClientIP"),
            request.remote_addr,
            request.headers.get("User-Agent"),
            request.headers.get("Accept-Language"),
            request.headers.get("Referer"),
            cookie_id,
            json.dumps(asn_data) if asn_data else None,
            json.dumps(classification) if classification else None,
            None,
            get_request_headers_json()
        ))
        conn.commit()

    response = make_response(render_template_string(PAGE))
    response.set_cookie("lab_id", cookie_id, max_age=60*60*24*30, httponly=False, samesite="Lax")
    response.set_cookie("visit_id", visit_id, max_age=60*10, httponly=False, samesite="Lax")
    return response

@app.route("/collect", methods=["POST"])
def collect():
    visit_id = request.cookies.get("visit_id")
    payload = request.get_json(silent=True) or {}

    client_ip = get_client_ip()
    asn_data = enrich_ip(client_ip)
    classification = classify_network(client_ip, asn_data)

    with sqlite3.connect(DB) as conn:
        conn.execute("""
            UPDATE visits
            SET client_json = ?
            WHERE id = ?
        """, (json.dumps(payload), visit_id))
        conn.commit()

    return jsonify({
        "ok": True,
        "client_ip": client_ip,
        "asn_summary": format_asn_summary(asn_data),
        "network_type": classification.get("network_type") if classification else None,
        "is_tor_exit": classification.get("is_tor_exit") if classification else None
    })

@app.route("/admin/visits")
def admin_visits():
    if request.args.get("token") != ADMIN_TOKEN:
        abort(403)

    with sqlite3.connect(DB) as conn:
        rows = conn.execute("""
            SELECT created_utc, client_ip, x_forwarded_for, x_azure_clientip,
                   remote_addr, user_agent_header, accept_language,
                   referer_header, path, query_string, cookie_id,
                   asn_json, network_classification_json, client_json, headers_json
            FROM visits
            ORDER BY created_utc DESC
            LIMIT 200
        """).fetchall()

    out = []
    for r in rows:
        out.append({
            "created_utc": r[0],
            "client_ip": r[1],
            "x_forwarded_for": r[2],
            "x_azure_clientip": r[3],
            "remote_addr": r[4],
            "user_agent_header": r[5],
            "accept_language": r[6],
            "referer_header": r[7],
            "path": r[8],
            "query_string": r[9],
            "cookie_id": r[10],
            "asn": json.loads(r[11]) if r[11] else None,
            "network_classification": json.loads(r[12]) if r[12] else None,
            "client_json": json.loads(r[13]) if r[13] else None,
            "headers": json.loads(r[14]) if r[14] else None
        })

    return jsonify(out)

@app.route("/admin/tor-status")
def tor_status():
    if request.args.get("token") != ADMIN_TOKEN:
        abort(403)

    return jsonify({
        "cached_count": len(TOR_EXIT_CACHE["ips"]),
        "fetched_at_unix": TOR_EXIT_CACHE["fetched_at"],
        "last_error": TOR_EXIT_CACHE["error"]
    })

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)