#!/usr/bin/env python3
"""
SD-WAN Combined Collector
=========================

Connects once to a Cisco Catalyst SD-WAN Manager (vManage) and runs two
collection stages behind a single authentication:

  - Stage 1: full operational data collection (produces the Stage 1 archive).
  - Stage 2: configuration backup collection (produces the Stage 2 archive).

The user provides only: manager IP address or FQDN, port, username and password.
SSL verification is disabled (intended for isolated lab environments).

A SINGLE login is performed: one j_security_check + token retrieval. The
resulting session cookie and X-XSRF-TOKEN are reused for every subsequent API
call made by BOTH stages. Each stage generates its own, unmodified output
files; this orchestrator simply bundles the two resulting archives into one
combined zip for convenience.

Usage (CLI):
    python combined.py
    python combined.py -a 10.0.0.1 --port 8443 -u admin -p admin

The module also exposes run_collection(...) used by the bundled web app.
"""
import argparse
import datetime
import os
import platform
import socket
import subprocess
import sys
import zipfile
from getpass import getpass

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR = os.path.join(BASE_DIR, "tools")
OUTPUT_DIR = os.path.join(BASE_DIR, "runs")

# The Stage 2 engine stores its data under this root directory. It must be set
# before importing the engine, as the value is captured at import time.
os.environ.setdefault("SDWAN_DATA_ROOT", OUTPUT_DIR)

# Make the tools importable (stage1, stage2 and the backup engine package).
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)

REST_TIMEOUT = 300


class CombinedError(Exception):
    """Raised for user-facing orchestration errors."""


# --------------------------------------------------------------------------- #
# Network reachability check (runs before any login attempt)
# --------------------------------------------------------------------------- #
def check_reachability(ip_address, port, timeout=4):
    """Test whether the SD-WAN Manager is reachable before attempting a login.

    Runs an ICMP ping and a TCP connect test to the management port.

    @return: dict with ping_ok, ping_detail, port, port_open, port_detail and a
             top-level 'reachable' flag (True only if the TCP port is open).
    """
    target_port = int(port) if port else 443

    # --- ICMP ping ---
    count_flag = "-n" if platform.system().lower() == "windows" else "-c"
    ping_ok = False
    ping_detail = ""
    try:
        proc = subprocess.run(
            ["ping", count_flag, "1", ip_address],
            capture_output=True,
            text=True,
            timeout=timeout + 3,
        )
        ping_ok = proc.returncode == 0
        ping_detail = (proc.stdout or proc.stderr or "").strip().splitlines()
        ping_detail = ping_detail[-1] if ping_detail else ("reply received" if ping_ok else "no reply")
    except subprocess.TimeoutExpired:
        ping_detail = "request timed out"
    except Exception as ex:  # noqa: BLE001
        ping_detail = str(ex)

    # --- TCP port test ---
    port_open = False
    port_detail = ""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip_address, target_port))
        port_open = True
        port_detail = "open"
    except Exception as ex:  # noqa: BLE001
        port_detail = str(ex)
    finally:
        sock.close()

    return {
        "ip": ip_address,
        "port": target_port,
        "ping_ok": ping_ok,
        "ping_detail": ping_detail,
        "port_open": port_open,
        "port_detail": port_detail,
        "reachable": port_open,
    }


def format_reachability(result):
    """Human-readable summary of a reachability result."""
    ping = "reachable" if result["ping_ok"] else "no response"
    port = "OPEN" if result["port_open"] else "CLOSED/unreachable"
    return (
        "Network test for %s:\n"
        "  - Ping (ICMP): %s (%s)\n"
        "  - TCP port %s: %s (%s)"
        % (
            result["ip"],
            ping,
            result["ping_detail"],
            result["port"],
            port,
            result["port_detail"],
        )
    )


# --------------------------------------------------------------------------- #
# Workload estimation (for the progress bar)
# --------------------------------------------------------------------------- #
#
# Many API calls are performed per device, so the total number of calls scales
# with the device inventory (and the number of device templates). The estimate
# below is grounded in the actual collection structure but is necessarily
# approximate; the UI clamps progress to <100% until the run truly completes.
#
# Stage 1 per-device "dataservice" catalog (counted from the endpoint groups):
#   - 6 calls for every device (groups that target all device types)
#   - 13 calls for every WAN edge (vedge-only groups, incl. shared ones)
#   - 6 calls for every vManage, 4 per vSmart, 4 per vBond
#   - 1 call per controller (vSmart/vManage/vBond)
def estimate_total_calls(auth, timeout=REST_TIMEOUT):
    """Estimate the total number of API calls for the whole collection.

    @return: (total_estimate:int, info:dict) where info has device/template counts.
    """
    session = requests.Session()
    session.headers.update(auth.header)

    def get_data(path):
        resp = session.get(auth.base_url + path, verify=False, timeout=timeout)
        resp.raise_for_status()
        return resp.json().get("data", []) or []

    devices = get_data("/dataservice/device")
    counts = {"vedge": 0, "vmanage": 0, "vbond": 0, "vsmart": 0}
    for dev in devices:
        dtype = dev.get("device-type")
        if dtype in counts:
            counts[dtype] += 1
    n_total = len(devices)
    v, m, b, s = counts["vedge"], counts["vmanage"], counts["vbond"], counts["vsmart"]

    # Device templates drive both the Stage 1 template walk and Stage 2.
    try:
        n_templates = len(get_data("/dataservice/template/device"))
    except Exception:  # noqa: BLE001
        n_templates = 0

    # Stage 1 - per-device dataservice catalog (see notes above).
    stage1_dataservice = 6 * n_total + 13 * v + 6 * m + 4 * s + 4 * b + (s + m + b)
    # Stage 1 - per-device troubleshooting / network-summary loop.
    stage1_uuid = n_total + 1
    # Stage 1 - vEdge template walk (device template object + features/sub-templates).
    stage1_walk = n_templates * 14
    # Stage 1 - static one-off endpoints + detail/bfd/cluster overhead.
    stage1_static = 60
    stage1 = stage1_dataservice + stage1_uuid + stage1_walk + stage1_static

    # Stage 2 - configuration backup: scales with device templates and devices.
    stage2 = n_templates * 3 + n_total * 2 + 150

    total = stage1 + stage2
    info = {"devices": n_total, "templates": n_templates, **counts}
    return total, info


# --------------------------------------------------------------------------- #
# Single authentication
# --------------------------------------------------------------------------- #
class Auth:
    """Holds the result of a single authentication against the SD-WAN Manager.

    Reused by both stages: Stage 1 via the header dict, Stage 2 via an injected,
    pre-authenticated session.
    """

    def __init__(self, base_url, jsessionid, token, username, password, server_facts):
        self.base_url = base_url
        self.jsessionid = jsessionid
        self.token = token
        self.username = username
        self.password = password
        self.server_facts = server_facts

    @property
    def header(self):
        return {
            "Content-Type": "application/json",
            "Cookie": self.jsessionid,
            "X-XSRF-TOKEN": self.token,
        }

    @property
    def version(self):
        """SD-WAN Manager software version, if available."""
        return (self.server_facts or {}).get("platformVersion")

    @property
    def hostname(self):
        """SD-WAN Manager hostname, best-effort from server facts."""
        facts = self.server_facts or {}
        for key in ("host-name", "hostName", "vmanageHostName", "vdeviceHostName", "deviceName"):
            value = facts.get(key)
            if value:
                return value
        return None


def authenticate(ip_address, port, username, password, timeout=REST_TIMEOUT):
    """Perform a single login and return an Auth object.

    Handles the with-port / without-port discovery against j_security_check and
    /dataservice/client/token. After the token is obtained, the SD-WAN Manager
    server facts are fetched once (required by Stage 2) using the same headers.
    """
    import stage1

    if port:
        base_url = "https://%s:%s" % (ip_address, port)
    else:
        base_url = "https://%s" % (ip_address)

    token, jsessionid, cond = stage1.get_token(base_url, username, password)
    if token is None and jsessionid == 400:
        raise CombinedError("Authentication failed - check address/port/credentials.")
    if not token or "<html>" in token:
        raise CombinedError("Authentication failed - invalid token returned.")

    # If login succeeded without the port, subsequent calls must drop the port.
    if cond != "port" and port:
        base_url = "https://%s" % (ip_address)

    # Fetch server facts once (needed by Stage 2).
    session = requests.Session()
    session.headers.update(
        {
            "Content-Type": "application/json",
            "Cookie": jsessionid,
            "X-XSRF-TOKEN": token,
        }
    )
    resp = session.get(
        base_url + "/dataservice/client/server", verify=False, timeout=timeout
    )
    resp.raise_for_status()
    server_facts = resp.json().get("data")
    if not server_facts:
        raise CombinedError("Could not retrieve SD-WAN Manager server information.")

    return Auth(base_url, jsessionid, token, username, password, server_facts)


# --------------------------------------------------------------------------- #
# Stage 1
# --------------------------------------------------------------------------- #
def run_stage1(auth, log=print, endpoint_log=None):
    """Run the Stage 1 collection reusing the single authenticated session.

    @return: absolute path to the Stage 1 zip archive.
    """
    import stage1

    log("Starting Stage 1 collection ...")
    stage1.endpoint_hook = endpoint_log
    try:
        zip_path = stage1.run(
            auth.base_url,
            auth.header,
            admin_username=auth.username,
            admin_password=auth.password,
            sso_enabled="N",
        )
    finally:
        stage1.endpoint_hook = None
    if not zip_path or not os.path.exists(zip_path):
        raise CombinedError("Stage 1 collection did not produce a zip archive.")
    log("Stage 1 collection complete: %s" % os.path.basename(zip_path))
    return zip_path


# --------------------------------------------------------------------------- #
# Stage 2
# --------------------------------------------------------------------------- #
def run_stage2(auth, archive_path, log=print, endpoint_log=None):
    """Run the Stage 2 configuration backup reusing the single session.

    @return: absolute path to the Stage 2 zip archive.
    """
    import stage2

    return stage2.run(auth, archive_path, log=log, endpoint_log=endpoint_log)


# --------------------------------------------------------------------------- #
# Bundling
# --------------------------------------------------------------------------- #
def bundle(stage1_zip, stage2_zip, combined_path, log=print):
    """Bundle the two archives into a single combined zip (stored, not
    recompressed) so the original archives remain byte-for-byte intact inside.
    """
    os.makedirs(os.path.dirname(combined_path), exist_ok=True)
    with zipfile.ZipFile(combined_path, "w", zipfile.ZIP_STORED) as zf:
        zf.write(stage1_zip, arcname="stage1/" + os.path.basename(stage1_zip))
        zf.write(stage2_zip, arcname="stage2/" + os.path.basename(stage2_zip))
    log("Combined bundle created: %s" % os.path.basename(combined_path))
    return combined_path


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def run_collection(ip_address, port, username, password, log=print, endpoint_log=None, event=None):
    """Full flow: single login -> Stage 1 -> Stage 2 -> combined zip.

    @param log: callback for high-level status messages.
    @param endpoint_log: callback invoked with each API endpoint URL used.
    @param event: optional callback receiving structured phase events (dicts).
    @return: absolute path to the combined zip archive.
    """
    def emit(**kwargs):
        if event is not None:
            try:
                event(kwargs)
            except Exception:  # noqa: BLE001
                pass

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")

    # 1) Verify the manager is reachable BEFORE attempting any login.
    emit(button="Checking manager reachability", status1="Checking manager reachability...", level1="info")
    log("Checking SD-WAN Manager reachability ...")
    reach = check_reachability(ip_address, port)
    for line in format_reachability(reach).splitlines():
        log(line)
    if not reach["reachable"]:
        emit(status1="Manager is not reachable", level1="err")
        raise CombinedError(
            "SD-WAN Manager %s is not reachable.\n%s"
            % (ip_address, format_reachability(reach))
        )
    log("Reachability check passed.")
    emit(
        status1="Manager reachable (TCP port %s open)" % reach["port"],
        level1="ok",
        button="Authenticating to manager",
    )

    # 2) Single authentication.
    log("Authenticating to SD-WAN Manager %s ..." % ip_address)
    try:
        auth = authenticate(ip_address, port, username, password)
    except Exception:
        emit(status1="Authentication failed", level1="err")
        raise
    log("Authentication successful (single session established).")
    emit(
        status1="Authentication successful",
        level1="ok",
        button="Collecting data",
        connected=True,
        address=ip_address,
        hostname=auth.hostname or "SD-WAN Manager",
        version=auth.version or "unknown",
    )

    # Estimate the total number of API calls (scales with device inventory) so
    # the UI can render a progress bar.
    log("Estimating workload (counting devices) ...")
    try:
        total_calls, info = estimate_total_calls(auth)
        log(
            "Estimated ~%d API calls across %d devices and %d device templates."
            % (total_calls, info["devices"], info["templates"])
        )
        emit(total=total_calls, devices=info["devices"])
    except Exception as ex:  # noqa: BLE001 - estimation is best-effort
        log("Could not estimate total API calls: %s" % ex)

    # 3) Collection stages.
    emit(status2="Stage 1: collecting data...", level2="info")
    stage1_zip = run_stage1(auth, log=log, endpoint_log=endpoint_log)
    emit(status2="Stage 1 complete. Stage 2: collecting data...", level2="info")

    stage2_zip = os.path.join(OUTPUT_DIR, "stage2_%s.zip" % stamp)
    stage2_zip = run_stage2(auth, stage2_zip, log=log, endpoint_log=endpoint_log)
    emit(status2="Stage 2 complete. Bundling...", level2="info")

    combined_path = os.path.join(OUTPUT_DIR, "sdwan_collection_%s.zip" % stamp)
    bundle(stage1_zip, stage2_zip, combined_path, log=log)
    emit(status2="Collection complete", level2="ok")

    return combined_path


def main():
    parser = argparse.ArgumentParser(
        description="Combined SD-WAN collector (single login)."
    )
    parser.add_argument("-a", "--address", help="SD-WAN Manager IP address or FQDN")
    parser.add_argument("--port", default="443", help="SD-WAN Manager port (default: 443)")
    parser.add_argument("-u", "--user", help="SD-WAN Manager username")
    parser.add_argument("-p", "--password", help="SD-WAN Manager password")
    args = parser.parse_args()

    address = args.address or input("Enter SD-WAN Manager IP or FQDN: ").strip()
    if args.port == "":
        port = input("Enter port [443]: ").strip() or "443"
    else:
        port = args.port
    user = args.user or input("Enter username: ").strip()
    password = args.password or getpass("Enter password: ")

    try:
        combined = run_collection(address, port, user, password)
    except Exception as ex:  # noqa: BLE001 - top level user feedback
        print("ERROR: %s" % ex)
        sys.exit(1)

    print("\nDone. Combined archive:\n  %s" % combined)


if __name__ == "__main__":
    main()
