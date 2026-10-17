"""
NetSentry - Flask Web Application
---------------------------------
Multi-threaded network port scanner web dashboard.
Provides Web routes for initiating port scans and viewing network probe results.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import socket
import time
import json
import re
import ssl
import urllib.parse
import urllib.request
import dns.resolver

# Key security headers and best-practice rules
SECURITY_HEADERS_RULES = {
    "Strict-Transport-Security": {
        "title": "HTTP Strict Transport Security (HSTS)",
        "description": "Enforces secure HTTPS connections and prevents SSL stripping attacks.",
    },
    "Content-Security-Policy": {
        "title": "Content Security Policy (CSP)",
        "description": "Prevents Cross-Site Scripting (XSS), code injection, and unauthorized data exfiltration.",
    },
    "X-Frame-Options": {
        "title": "X-Frame-Options",
        "description": "Protects against Clickjacking attacks by restricting framing.",
    },
    "X-Content-Type-Options": {
        "title": "X-Content-Type-Options",
        "description": "Prevents MIME-sniffing attacks by enforcing declared content types.",
    },
    "Referrer-Policy": {
        "title": "Referrer-Policy",
        "description": "Controls how much referrer information is sent with outbound HTTP requests.",
    },
    "Permissions-Policy": {
        "title": "Permissions Policy",
        "description": "Restricts browser feature access (e.g. camera, microphone, geolocation).",
    },
}

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

# Mapping of well-known port numbers to standard network service names
COMMON_SERVICES = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    119: "NNTP",
    123: "NTP",
    135: "MS-RPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    194: "IRC",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP-Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9000: "SonarQube/PHP-FPM",
    27017: "MongoDB",
}


def resolve_host(target: str) -> tuple[str | None, str | None]:
    """Resolve a hostname or IP to an IPv4 address.

    Returns:
        tuple of (ip_address, error_message)
    """
    target = target.strip()
    # Strip URL schemes if user pasted http(s)://
    target = re.sub(r"^https?://", "", target, flags=re.IGNORECASE).split("/")[0]

    if not target:
        return None, "Target host cannot be empty."

    try:
        ip = socket.gethostbyname(target)
        return ip, None
    except socket.gaierror:
        return None, f"Failed to resolve host '{target}'. Please check domain or IP."
    except Exception as exc:
        return None, f"Error resolving '{target}': {str(exc)}"


def check_port(target_ip: str, port: int, timeout: float = 0.8) -> tuple[int, bool]:
    """Perform TCP connect probe on target_ip and port.

    Returns:
        Tuple of (port, is_open).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((target_ip, port))
        return port, result == 0
    except Exception:
        return port, False
    finally:
        sock.close()


def scan_port_range(
    target_ip: str,
    start_port: int,
    end_port: int,
    max_threads: int = 100,
    timeout: float = 0.8,
) -> list[dict]:
    """Concurrently scan a port range on target_ip.

    Returns:
        A list of dicts describing open ports.
    """
    total_ports = end_port - start_port + 1
    worker_count = min(max_threads, total_ports)
    open_ports = []

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {
            executor.submit(check_port, target_ip, p, timeout): p
            for p in range(start_port, end_port + 1)
        }
        for future in as_completed(futures):
            port, is_open = future.result()
            if is_open:
                service_name = COMMON_SERVICES.get(port, "Unknown / Custom Service")
                open_ports.append({
                    "port": port,
                    "service": service_name,
                    "status": "OPEN",
                })

    # Sort results by port number
    open_ports.sort(key=lambda item: item["port"])
    return open_ports


@app.route("/")
def index():
    """Render the dashboard UI."""
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    """API endpoint to run a port scan."""
    data = request.get_json(silent=True) or request.form

    target_raw = data.get("target", "").strip()
    start_str = data.get("start_port", "").strip()
    end_str = data.get("end_port", "").strip()
    threads_str = data.get("threads", "100").strip()

    # Input validations
    if not target_raw:
        return jsonify({"success": False, "error": "Target host or IP address is required."}), 400

    try:
        start_port = int(start_str)
        end_port = int(end_str)
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "Starting and ending ports must be valid integers."}), 400

    if not (1 <= start_port <= 65535) or not (1 <= end_port <= 65535):
        return jsonify({"success": False, "error": "Port numbers must be between 1 and 65535."}), 400

    if start_port > end_port:
        return jsonify({"success": False, "error": "Starting port cannot be greater than ending port."}), 400

    # Max range safeguard for web requests (up to 5000 ports per batch)
    if (end_port - start_port + 1) > 5000:
        return jsonify({"success": False, "error": "Maximum scan range in web interface is 5,000 ports."}), 400

    try:
        threads = int(threads_str) if threads_str else 100
        threads = max(1, min(threads, 500))
    except ValueError:
        threads = 100

    # DNS Resolution
    resolved_ip, resolve_err = resolve_host(target_raw)
    if resolve_err:
        return jsonify({"success": False, "error": resolve_err}), 400

    # Execute Scan
    start_time = time.time()
    open_ports = scan_port_range(
        target_ip=resolved_ip,
        start_port=start_port,
        end_port=end_port,
        max_threads=threads,
        timeout=0.8,
    )
    duration = time.time() - start_time

    return jsonify({
        "success": True,
        "target": target_raw,
        "target_ip": resolved_ip,
        "start_port": start_port,
        "end_port": end_port,
        "total_ports": end_port - start_port + 1,
        "threads": threads,
        "open_count": len(open_ports),
        "open_ports": open_ports,
        "duration_seconds": round(duration, 2),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })



@app.route("/audit-headers", methods=["POST"])
def audit_headers():
    """API endpoint to inspect and score HTTP security headers of a web application."""
    data = request.get_json(silent=True) or request.form
    target_raw = data.get("target", "").strip()

    if not target_raw:
        return jsonify({"success": False, "error": "Target URL or domain is required."}), 400

    url = target_raw if re.match(r"^https?://", target_raw, re.I) else f"https://{target_raw}"

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NetSentry/2.0"},
        method="GET",
    )

    try:
        start_time = time.time()
        with urllib.request.urlopen(req, timeout=5.0, context=ctx) as response:
            headers = dict(response.headers)
            status_code = response.status
            final_url = response.url
        duration = time.time() - start_time

    except urllib.error.HTTPError as err:
        headers = dict(err.headers)
        status_code = err.code
        final_url = url
        duration = 0.5
    except Exception as exc:
        return jsonify({"success": False, "error": f"Failed to connect to '{url}': {str(exc)}"}), 400

    header_results = []
    present_count = 0

    for header_name, meta in SECURITY_HEADERS_RULES.items():
        header_val = None
        for h_k, h_v in headers.items():
            if h_k.lower() == header_name.lower():
                header_val = h_v
                break

        is_present = header_val is not None
        if is_present:
            present_count += 1

        header_results.append({
            "header": header_name,
            "title": meta["title"],
            "description": meta["description"],
            "status": "PRESENT" if is_present else "MISSING",
            "value": header_val if is_present else None,
        })

    score_pct = int((present_count / len(SECURITY_HEADERS_RULES)) * 100)
    if score_pct >= 80:
        grade = "A"
    elif score_pct >= 60:
        grade = "B"
    elif score_pct >= 40:
        grade = "C"
    elif score_pct >= 20:
        grade = "D"
    else:
        grade = "F"

    server_info = headers.get("Server") or headers.get("server") or "Hidden / Not Disclosed"
    powered_by = headers.get("X-Powered-By") or headers.get("x-powered-by") or "Hidden / Not Disclosed"

    return jsonify({
        "success": True,
        "target_url": final_url,
        "status_code": status_code,
        "grade": grade,
        "score_pct": score_pct,
        "present_count": present_count,
        "total_rules": len(SECURITY_HEADERS_RULES),
        "headers": header_results,
        "server_info": server_info,
        "powered_by": powered_by,
        "duration_seconds": round(duration, 2),
    })


@app.route("/dns-lookup", methods=["POST"])
def dns_lookup():
    """API endpoint to query DNS records (A, AAAA, MX, NS, TXT)."""
    data = request.get_json(silent=True) or request.form
    target_raw = data.get("domain", "").strip()

    domain = re.sub(r"^https?://", "", target_raw, flags=re.IGNORECASE).split("/")[0]
    if not domain:
        return jsonify({"success": False, "error": "Domain name is required."}), 400

    record_types = ["A", "AAAA", "MX", "NS", "TXT"]
    results = {}

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 3.0

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            records = []
            for rdata in answers:
                if rtype == "MX":
                    records.append({"preference": rdata.preference, "exchange": str(rdata.exchange)})
                elif rtype == "TXT":
                    records.append(str(rdata.to_text()))
                else:
                    records.append(str(rdata))
            results[rtype] = records
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            results[rtype] = []
        except Exception as exc:
            results[rtype] = [f"Lookup error: {str(exc)}"]

    return jsonify({
        "success": True,
        "domain": domain,
        "records": results,
    })


@app.route("/ip-info", methods=["POST"])
def ip_info():
    """API endpoint to query IP Geolocation and Network ASN data."""
    data = request.get_json(silent=True) or request.form
    target_raw = data.get("target", "").strip()

    if not target_raw:
        return jsonify({"success": False, "error": "Target IP or domain is required."}), 400

    target_ip, resolve_err = resolve_host(target_raw)
    if resolve_err:
        return jsonify({"success": False, "error": resolve_err}), 400

    try:
        req_url = f"http://ip-api.com/json/{target_ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        req = urllib.request.Request(req_url, headers={"User-Agent": "NetSentry/2.0"})
        with urllib.request.urlopen(req, timeout=4.0) as resp:
            geo_data = json.loads(resp.read().decode("utf-8"))

        if geo_data.get("status") != "success":
            return jsonify({"success": False, "error": geo_data.get("message", "IP Geolocation lookup failed.")}), 400

        return jsonify({
            "success": True,
            "target": target_raw,
            "ip": geo_data.get("query"),
            "country": geo_data.get("country"),
            "country_code": geo_data.get("countryCode"),
            "region": geo_data.get("regionName"),
            "city": geo_data.get("city"),
            "zip": geo_data.get("zip"),
            "lat": geo_data.get("lat"),
            "lon": geo_data.get("lon"),
            "timezone": geo_data.get("timezone"),
            "isp": geo_data.get("isp"),
            "org": geo_data.get("org"),
            "asn": geo_data.get("as"),
        })

    except Exception as exc:
        return jsonify({"success": False, "error": f"Geolocation lookup failed: {str(exc)}"}), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
