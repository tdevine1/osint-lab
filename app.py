from flask import Flask, request, jsonify, make_response, render_template_string
import sqlite3
import json
import uuid
import ipaddress
from datetime import datetime, timezone
from ipwhois import IPWhois

app = Flask(__name__)
DB = "osint_lab.db"

PAGE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Connection Logged</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      max-width: 860px;
      margin: 40px auto;
      line-height: 1.5;
      background: #fafafa;
      color: #222;
    }
    .box {
      border: 1px solid #a61b1b;
      border-radius: 10px;
      padding: 24px;
      background: #fff8f8;
      margin-bottom: 18px;
    }
    .panel {
      border: 1px solid #ddd;
      border-radius: 10px;
      padding: 18px;
      background: white;
      margin-bottom: 16px;
    }
    h1 { margin-top: 0; color: #a61b1b; }
    h2 { margin-top: 0; }
    .small { color: #555; font-size: 0.95em; }
    code, pre {
      background: #f4f4f4;
      border-radius: 6px;
      padding: 2px 6px;
    }
    ul { margin-top: 8px; }
    .muted { color: #666; }
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

        if (data.asn_summary) {
          document.getElementById("asn").textContent = data.asn_summary;
        } else {
          document.getElementById("asn").textContent = "Unavailable";
        }
      } catch (e) {
        document.getElementById("ip").textContent = "Unavailable";
        document.getElementById("asn").textContent = "Unavailable";
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
                user_agent_header TEXT,
                accept_language TEXT,
                referer_header TEXT,
                cookie_id TEXT,
                asn_json TEXT,
                client_json TEXT
            )
        """)
        conn.commit()

def get_client_ip():
    """
    Prefer the first public IP in X-Forwarded-For.
    Fall back to remote_addr.
    """
    xff = request.headers.get("X-Forwarded-For", "")
    candidates = [ip.strip() for ip in xff.split(",") if ip.strip()]

    if request.remote_addr:
        candidates.append(request.remote_addr)

    for ip in candidates:
        try:
            parsed = ipaddress.ip_address(ip)
            # Keep private/reserved out if we can find a public address first
            if not (parsed.is_private or parsed.is_loopback or parsed.is_reserved or parsed.is_link_local):
                return ip
        except ValueError:
            continue

    # If nothing public found, return first usable candidate
    for ip in candidates:
        try:
            ipaddress.ip_address(ip)
            return ip
        except ValueError:
            continue

    return None

def enrich_ip(ip):
    """
    RDAP-based ASN enrichment.
    Returns a small dict safe to store/show.
    """
    if not ip:
        return None

    try:
        parsed = ipaddress.ip_address(ip)
        if parsed.is_private or parsed.is_loopback or parsed.is_reserved or parsed.is_link_local:
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

        network_name = None
        network_cidr = None
        asn = result.get("asn")
        asn_description = result.get("asn_description")

        network = result.get("network") or {}
        network_name = network.get("name")
        network_cidr = network.get("cidr")

        return {
            "ip": ip,
            "asn": asn,
            "asn_description": asn_description,
            "network_name": network_name,
            "network_cidr": network_cidr
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

@app.route("/")
@app.route("/documents/notice")
def landing():
    init_db()

    visit_id = str(uuid.uuid4())
    cookie_id = request.cookies.get("lab_id") or str(uuid.uuid4())
    client_ip = get_client_ip()
    asn_data = enrich_ip(client_ip)

    with sqlite3.connect(DB) as conn:
        conn.execute("""
            INSERT INTO visits (
                id, created_utc, path, query_string, client_ip,
                x_forwarded_for, user_agent_header, accept_language,
                referer_header, cookie_id, asn_json, client_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            visit_id,
            datetime.now(timezone.utc).isoformat(),
            request.path,
            request.query_string.decode("utf-8", errors="replace"),
            client_ip,
            request.headers.get("X-Forwarded-For"),
            request.headers.get("User-Agent"),
            request.headers.get("Accept-Language"),
            request.headers.get("Referer"),
            cookie_id,
            json.dumps(asn_data) if asn_data else None,
            None
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
        "asn_summary": format_asn_summary(asn_data)
    })

@app.route("/admin/visits")
def admin_visits():
    # Protect this in production.
    with sqlite3.connect(DB) as conn:
        rows = conn.execute("""
            SELECT created_utc, client_ip, x_forwarded_for, user_agent_header,
                   accept_language, referer_header, path, query_string,
                   cookie_id, asn_json, client_json
            FROM visits
            ORDER BY created_utc DESC
            LIMIT 100
        """).fetchall()

    out = []
    for r in rows:
        out.append({
            "created_utc": r[0],
            "client_ip": r[1],
            "x_forwarded_for": r[2],
            "user_agent_header": r[3],
            "accept_language": r[4],
            "referer_header": r[5],
            "path": r[6],
            "query_string": r[7],
            "cookie_id": r[8],
            "asn": json.loads(r[9]) if r[9] else None,
            "client_json": json.loads(r[10]) if r[10] else None
        })

    return jsonify(out)

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)