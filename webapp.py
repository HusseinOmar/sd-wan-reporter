#!/usr/bin/env python3
"""
SD-WAN Combined Collector - Web App
===================================

A thin Flask front-end around combined.run_collection(). The user enters only
the SD-WAN Manager IP, port, username and password. A single background job
authenticates once, runs the Stage 1 and Stage 2 collections, bundles both into
one zip, and offers it for download.

Run:
    python webapp.py            # listens on http://0.0.0.0:5050
    python webapp.py --port 8080

Intended for an isolated lab environment (SSL verification is disabled).
"""
import argparse
import os
import threading
import uuid

from flask import (
    Flask,
    jsonify,
    render_template,
    request,
    send_file,
)

import combined

app = Flask(__name__)

# In-memory job registry: job_id -> dict(status, log[], result, error)
JOBS = {}
JOBS_LOCK = threading.Lock()


def _new_job():
    job_id = uuid.uuid4().hex
    with JOBS_LOCK:
        JOBS[job_id] = {
            "status": "running",  # running | done | error
            "log": [],            # high-level status messages
            "endpoints": [],      # de-duplicated API endpoint URLs used
            "_seen": set(),       # internal dedupe set for endpoints
            "calls": 0,           # total API calls made (not de-duplicated)
            "total": 0,           # estimated total API calls (for progress bar)
            "devices": None,      # device count from the workload estimate
            "result": None,       # absolute path to combined zip
            "error": None,
            # Phase status surfaced to the UI
            "status1": "",        # reachability / authentication status
            "level1": "info",     # info | ok | err
            "status2": "",        # collection stage status
            "level2": "info",
            "button": "Run collection",
            # Connection panel
            "connected": False,
            "address": None,
            "hostname": None,
            "version": None,
        }
    return job_id


def _job_log(job_id, message):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if job is not None:
            job["log"].append(message)


def _job_endpoint(job_id, url):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if job is None:
            return
        # Count every call for progress; keep a de-duplicated list for display.
        job["calls"] += 1
        if url in job["_seen"]:
            return
        job["_seen"].add(url)
        job["endpoints"].append(url)


def _job_event(job_id, ev):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if job is None:
            return
        for key in ("status1", "level1", "status2", "level2", "button",
                    "connected", "address", "hostname", "version",
                    "total", "devices"):
            if key in ev:
                job[key] = ev[key]


def _run_job(job_id, address, port, user, password):
    def log(msg):
        _job_log(job_id, str(msg))

    def endpoint_log(url):
        _job_endpoint(job_id, str(url))

    def event(ev):
        _job_event(job_id, ev)

    try:
        result = combined.run_collection(
            address, port, user, password, log=log, endpoint_log=endpoint_log, event=event
        )
        with JOBS_LOCK:
            JOBS[job_id]["result"] = result
            JOBS[job_id]["status"] = "done"
            JOBS[job_id]["button"] = "Run collection"
        log("Output saved locally: %s" % result)
        log("Please share this output file with the Cisco team.")
    except Exception as ex:  # noqa: BLE001 - surface error to UI
        with JOBS_LOCK:
            JOBS[job_id]["error"] = str(ex)
            JOBS[job_id]["status"] = "error"
            JOBS[job_id]["button"] = "Run collection"
        log("ERROR: %s" % ex)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/run", methods=["POST"])
def api_run():
    data = request.get_json(force=True, silent=True) or request.form
    address = (data.get("address") or "").strip()
    port = (data.get("port") or "").strip()
    user = (data.get("user") or "").strip()
    password = data.get("password") or ""

    if not address or not user or not password:
        return jsonify({"error": "address, user and password are required"}), 400

    job_id = _new_job()
    thread = threading.Thread(
        target=_run_job, args=(job_id, address, port, user, password), daemon=True
    )
    thread.start()
    return jsonify({"job_id": job_id})


@app.route("/api/status/<job_id>")
def api_status(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if job is None:
            return jsonify({"error": "unknown job"}), 404
        return jsonify(
            {
                "status": job["status"],
                "log": job["log"],
                "endpoints": job["endpoints"],
                "endpoint_count": len(job["endpoints"]),
                "calls": job["calls"],
                "total": job["total"],
                "devices": job["devices"],
                "error": job["error"],
                "status1": job["status1"],
                "level1": job["level1"],
                "status2": job["status2"],
                "level2": job["level2"],
                "button": job["button"],
                "connected": job["connected"],
                "address": job["address"],
                "hostname": job["hostname"],
                "version": job["version"],
                "download": "/api/download/%s" % job_id
                if job["status"] == "done"
                else None,
                "filename": os.path.basename(job["result"])
                if job["result"]
                else None,
                "saved_path": job["result"],
            }
        )


@app.route("/api/download/<job_id>")
def api_download(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        result = job["result"] if job else None
    if not result or not os.path.exists(result):
        return jsonify({"error": "result not available"}), 404
    return send_file(result, as_attachment=True, download_name=os.path.basename(result))


def main():
    parser = argparse.ArgumentParser(description="SD-WAN Combined Collector web app")
    parser.add_argument("--host", default="0.0.0.0", help="bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5050, help="bind port (default: 5050)")
    args = parser.parse_args()
    app.run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    main()
