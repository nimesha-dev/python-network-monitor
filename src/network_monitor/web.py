"""Local web dashboard for the Python Network Monitor.

Starts a small local HTTP server that serves an auto-refreshing HTML
dashboard with live tables, charts, filters, search and event details.
No terminal input is needed after startup and no third-party web
libraries are used.

Usage:

    python -m network_monitor.web
    python -m network_monitor.web --port 9000
    python -m network_monitor.web --no-browser
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
import threading
import time
import webbrowser
from collections import Counter, deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from network_monitor.collector import collect_snapshot
from network_monitor.config import Settings, prepare_directories
from network_monitor.detector import SecurityDetector
from network_monitor.monitor import calculate_speeds
from network_monitor.storage import Storage

HOST = "127.0.0.1"
DEFAULT_PORT = 8765
HISTORY_LIMIT = 90
SEVERITY_ORDER = ("HIGH", "MEDIUM", "LOW", "INFO")


class DashboardState:
    """Thread-safe shared state written by the monitor thread."""

    def __init__(self, settings: Settings, storage: Storage) -> None:
        self.settings = settings
        self.storage = storage
        self.detector = SecurityDetector(settings)
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.started_at = time.monotonic()
        self.snapshot: dict[str, Any] | None = None
        self.speeds: list[dict[str, Any]] = []
        self.history: deque[dict[str, Any]] = deque(maxlen=HISTORY_LIMIT)
        self.process_counts: list[dict[str, Any]] = []
        self.last_update: str | None = None
        self.samples = 0

    def monitor_loop(self) -> None:
        try:
            previous = collect_snapshot()
        except Exception:
            return
        # First snapshot is the baseline, not newly observed activity.
        self.detector.inspect_interfaces(previous["interfaces"])
        self.detector.inspect_connections(previous["connections"])
        self.detector.inspect_listeners(previous["listening_ports"])
        self.storage.save_snapshot(previous)
        self._publish(previous, [], previous.get("timestamp"))
        last_sample = time.monotonic()

        while not self.stop_event.is_set():
            time.sleep(max(0.5, float(self.settings.monitor_interval)))
            try:
                current = collect_snapshot()
            except Exception:
                continue
            now = time.monotonic()
            elapsed = max(0.001, now - last_sample)
            last_sample = now
            speeds = calculate_speeds(previous, current, elapsed)

            events = self.detector.inspect_interfaces(current["interfaces"])
            events.extend(self.detector.inspect_connections(
                current["connections"]))
            events.extend(self.detector.inspect_speeds(speeds))
            events.extend(self.detector.inspect_listeners(
                current["listening_ports"]))
            for event in events:
                self.storage.save_event(event)

            self.storage.save_snapshot(current)
            self._publish(current, speeds, current.get("timestamp"))
            previous = current

    def _publish(self, snapshot: dict[str, Any],
                 speeds: list[dict[str, Any]], timestamp: str | None) -> None:
        upload = sum(item.get("upload_bps", 0.0) for item in speeds
                     if item.get("name") != "lo")
        download = sum(item.get("download_bps", 0.0) for item in speeds
                       if item.get("name") != "lo")
        counts = Counter(
            str(item.get("process_name") or "Unknown")
            for item in snapshot.get("connections", [])
        )
        with self.lock:
            self.snapshot = snapshot
            self.speeds = speeds
            self.samples += 1
            self.last_update = timestamp or datetime.now(
                timezone.utc).isoformat()
            self.process_counts = [
                {"name": name, "count": count}
                for name, count in counts.most_common(8)
            ]
            if speeds:
                self.history.append({
                    "t": int(time.time()),
                    "up": round(upload, 2),
                    "down": round(download, 2),
                })

    def to_dict(self) -> dict[str, Any]:
        with self.lock:
            snapshot = self.snapshot or {}
            payload: dict[str, Any] = {
                "updated": self.last_update,
                "uptime_seconds": round(time.monotonic() - self.started_at, 1),
                "samples": self.samples,
                "interfaces": snapshot.get("interfaces", []),
                "statistics": snapshot.get("statistics", []),
                "connections": snapshot.get("connections", []),
                "listeners": snapshot.get("listening_ports", []),
                "speeds": self.speeds,
                "history": list(self.history),
                "process_counts": self.process_counts,
            }
        events = self.storage.recent_events(50)
        all_events = self.storage.recent_events(1000)
        severity_counts = {level: 0 for level in SEVERITY_ORDER}
        for event in all_events:
            level = event.get("severity", "INFO")
            severity_counts[level] = severity_counts.get(level, 0) + 1
        payload["events"] = events
        payload["severity_counts"] = severity_counts
        payload["event_total"] = len(all_events)
        return payload


def make_handler(state: DashboardState):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
            parsed = urlparse(self.path)
            path = parsed.path
            if path in ("/", "/index.html"):
                self._send(200, "text/html; charset=utf-8",
                           HTML_PAGE.encode("utf-8"))
            elif path == "/api/state":
                body = json.dumps(state.to_dict(), default=str).encode("utf-8")
                self._send(200, "application/json; charset=utf-8", body)
            elif path == "/api/export":
                fmt = parse_qs(parsed.query).get("format", ["json"])[0]
                self._export(fmt)
            elif path == "/favicon.ico":
                self._send(204, "image/png", b"")
            else:
                self._send(404, "text/plain; charset=utf-8", b"Not found")

        def _export(self, fmt: str) -> None:
            events = state.storage.recent_events(10000)
            if fmt == "csv":
                buffer = io.StringIO()
                fields = ["id", "timestamp", "severity", "category",
                          "source_ip", "destination_ip", "description",
                          "details"]
                writer = csv.DictWriter(buffer, fieldnames=fields)
                writer.writeheader()
                for event in events:
                    writer.writerow({key: event.get(key, "") for key in fields})
                body = buffer.getvalue().encode("utf-8")
                content_type = "text/csv; charset=utf-8"
                filename = "security_events.csv"
            else:
                body = json.dumps(events, indent=2, default=str).encode("utf-8")
                content_type = "application/json; charset=utf-8"
                filename = "security_events.json"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header(
                "Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _send(self, status: int, content_type: str, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            return

    return Handler


HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Python Network Monitor — Live Dashboard</title>
<style>
  :root {
    --bg: #0b1120; --card: #111a2e; --border: #1e2a44;
    --text: #e2e8f0; --muted: #8494b0; --accent: #22d3ee;
    --green: #22c55e; --blue: #38bdf8; --amber: #f59e0b; --red: #ef4444;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  html { scroll-behavior: smooth; }
  body {
    background: var(--bg); color: var(--text);
    font: 14px/1.45 "Segoe UI", system-ui, sans-serif;
    padding: 0 20px 24px; min-height: 100vh;
  }
  .topbar {
    position: sticky; top: 0; z-index: 50;
    background: rgba(11,17,32,.96); backdrop-filter: blur(6px);
    border-bottom: 1px solid var(--border);
    display: flex; flex-wrap: wrap; align-items: center; gap: 12px;
    padding: 12px 0; margin-bottom: 16px;
  }
  h1 { font-size: 18px; font-weight: 650; white-space: nowrap; }
  h1 span { color: var(--accent); }
  .tabs { display: flex; gap: 4px; flex-wrap: wrap; }
  .tabs a {
    color: var(--muted); text-decoration: none; font-size: 12.5px;
    padding: 6px 11px; border-radius: 7px; font-weight: 600;
  }
  .tabs a:hover { background: #16203a; color: var(--text); }
  .live {
    display: inline-flex; align-items: center; gap: 7px;
    background: #052e16; border: 1px solid #14532d; color: #4ade80;
    padding: 4px 11px; border-radius: 999px; font-size: 12px; font-weight: 600;
  }
  .live.paused { background: #451a03; border-color: #78350f; color: #fbbf24; }
  .live .dot { width: 8px; height: 8px; border-radius: 50%; background: currentColor; animation: pulse 1.6s infinite; }
  .live.paused .dot { animation: none; }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: .35; } }
  .top-actions { display: flex; gap: 8px; align-items: center; margin-left: auto; flex-wrap: wrap; }
  .meta { color: var(--muted); font-size: 12px; }
  .btn {
    background: #16203a; border: 1px solid var(--border); color: var(--text);
    font-size: 12px; font-weight: 600; padding: 6px 12px; border-radius: 7px;
    cursor: pointer; text-decoration: none; display: inline-block;
  }
  .btn:hover { border-color: var(--accent); color: var(--accent); }
  .btn.warn { color: #fbbf24; }
  .kpis {
    display: grid; gap: 12px;
    grid-template-columns: repeat(auto-fit, minmax(155px, 1fr));
    margin-bottom: 16px; scroll-margin-top: 70px;
  }
  .kpi {
    background: var(--card); border: 1px solid var(--border);
    border-radius: 10px; padding: 13px 15px; cursor: pointer;
    transition: border-color .15s, transform .15s;
  }
  .kpi:hover { border-color: var(--accent); transform: translateY(-2px); }
  .kpi .label { color: var(--muted); font-size: 11.5px; text-transform: uppercase; letter-spacing: .6px; }
  .kpi .value { font-size: 23px; font-weight: 650; margin-top: 4px; }
  .kpi .sub { color: var(--muted); font-size: 11.5px; margin-top: 2px; }
  .grid2 { display: grid; gap: 14px; grid-template-columns: 2fr 1fr; margin-bottom: 14px; scroll-margin-top: 70px; }
  .grid2b { display: grid; gap: 14px; grid-template-columns: 1fr 1fr; margin-bottom: 14px; scroll-margin-top: 70px; }
  @media (max-width: 980px) { .grid2, .grid2b { grid-template-columns: 1fr; } }
  .panel {
    background: var(--card); border: 1px solid var(--border);
    border-radius: 10px; padding: 14px 16px; overflow: hidden;
    scroll-margin-top: 70px;
  }
  .panel-head { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; margin-bottom: 12px; }
  .panel-head h2 {
    font-size: 12.5px; text-transform: uppercase; letter-spacing: .7px;
    color: var(--muted); font-weight: 600; margin-right: auto;
  }
  .count { color: var(--accent); font-weight: 700; }
  canvas { width: 100%; height: 210px; display: block; cursor: pointer; }
  .legend { display: flex; gap: 16px; font-size: 12px; color: var(--muted); margin-top: 6px; flex-wrap: wrap; }
  .legend i { display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 5px; }
  .chips { display: flex; gap: 6px; flex-wrap: wrap; }
  .chip {
    background: #0b1428; border: 1px solid var(--border); color: var(--muted);
    font-size: 11.5px; font-weight: 700; padding: 4px 10px; border-radius: 999px;
    cursor: pointer; letter-spacing: .3px;
  }
  .chip:hover { border-color: var(--accent); color: var(--accent); }
  .chip.active { background: #164e63; border-color: #22d3ee; color: #a5f3fc; }
  .chip.c-HIGH.active { background: #450a0a; border-color: #ef4444; color: #f87171; }
  .chip.c-MEDIUM.active { background: #451a03; border-color: #f59e0b; color: #fbbf24; }
  .chip.c-LOW.active { background: #082f49; border-color: #38bdf8; color: #7dd3fc; }
  .chip.c-INFO.active { background: #1e293b; border-color: #64748b; color: #cbd5e1; }
  .search {
    background: #0b1428; border: 1px solid var(--border); color: var(--text);
    font-size: 12.5px; padding: 6px 11px; border-radius: 7px; width: 190px;
    outline: none;
  }
  .search:focus { border-color: var(--accent); }
  .search::placeholder { color: #5b6b8c; }
  table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
  th {
    text-align: left; color: var(--muted); font-weight: 600;
    padding: 6px 8px; border-bottom: 1px solid var(--border);
    font-size: 11.5px; text-transform: uppercase; letter-spacing: .4px;
    cursor: pointer; user-select: none; white-space: nowrap;
  }
  th:hover { color: var(--accent); }
  th.sorted { color: var(--accent); }
  th.sorted::after { content: " ▾"; }
  th.sorted.asc::after { content: " ▴"; }
  td { padding: 6px 8px; border-bottom: 1px solid #16203a; vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  tbody tr:hover { background: #16203a; }
  tbody tr.clickable { cursor: pointer; }
  .mono { font-family: ui-monospace, "Cascadia Code", monospace; font-size: 12px; }
  .muted { color: var(--muted); }
  .badge {
    display: inline-block; padding: 2px 8px; border-radius: 999px;
    font-size: 10.5px; font-weight: 700; letter-spacing: .4px;
  }
  .b-HIGH { background: #450a0a; color: #f87171; }
  .b-MEDIUM { background: #451a03; color: #fbbf24; }
  .b-LOW { background: #082f49; color: #7dd3fc; }
  .b-INFO { background: #1e293b; color: #94a3b8; }
  .b-UP { background: #052e16; color: #4ade80; }
  .b-DOWN { background: #3f1d1d; color: #f87171; }
  .b-TCP { background: #0b2545; color: #7dd3fc; }
  .b-UDP { background: #052e16; color: #86efac; }
  @keyframes flash { 0% { background: #164e63; } 100% { background: transparent; } }
  tr.flash td { animation: flash 2.2s ease-out; }
  .bars { display: flex; flex-direction: column; gap: 9px; }
  .bar-row { display: grid; grid-template-columns: 110px 1fr 44px; gap: 10px; align-items: center; }
  .bar-label { color: var(--muted); font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .bar-track { background: #0b1428; border-radius: 5px; height: 14px; overflow: hidden; }
  .bar-fill { background: linear-gradient(90deg, #0891b2, #22d3ee); height: 100%; border-radius: 5px; min-width: 2px; }
  .bar-val { font-size: 12px; text-align: right; color: var(--text); }
  .scroll { max-height: 340px; overflow-y: auto; }
  .scroll::-webkit-scrollbar { width: 8px; }
  .scroll::-webkit-scrollbar-thumb { background: #243352; border-radius: 4px; }
  footer {
    margin-top: 16px; padding-top: 14px; border-top: 1px solid var(--border);
    color: var(--muted); font-size: 12.5px; display: flex; flex-wrap: wrap; gap: 18px;
  }
  footer code { background: #0b1428; padding: 2px 7px; border-radius: 5px; color: #a5f3fc; }
  .empty { color: var(--muted); text-align: center; padding: 18px 0; }
  .modal {
    position: fixed; inset: 0; z-index: 100; display: flex;
    align-items: center; justify-content: center;
    background: rgba(3,7,18,.75); padding: 20px;
  }
  .modal.hidden { display: none; }
  .modal-card {
    background: var(--card); border: 1px solid var(--border);
    border-radius: 12px; width: min(640px, 100%); max-height: 85vh;
    overflow: auto; padding: 18px 20px;
  }
  .modal-card h3 { font-size: 15px; margin-bottom: 4px; display: flex; gap: 10px; align-items: center; }
  .modal-card .close { float: right; cursor: pointer; color: var(--muted); font-size: 20px; line-height: 1; border: none; background: none; }
  .modal-card .close:hover { color: var(--text); }
  .kv { display: grid; grid-template-columns: 130px 1fr; gap: 5px 12px; margin: 14px 0; font-size: 13px; }
  .kv .k { color: var(--muted); }
  pre {
    background: #0b1428; border: 1px solid var(--border); border-radius: 8px;
    padding: 12px; font-size: 12px; overflow-x: auto; color: #a5f3fc;
    font-family: ui-monospace, "Cascadia Code", monospace;
  }
</style>
</head>
<body>

<div class="topbar">
  <h1>Python <span>Network Monitor</span></h1>
  <nav class="tabs">
    <a href="#overview">Overview</a>
    <a href="#traffic">Traffic</a>
    <a href="#connections">Connections</a>
    <a href="#events">Events</a>
  </nav>
  <span class="live" id="status"><span class="dot"></span> <span id="status-text">LIVE</span></span>
  <div class="top-actions">
    <span class="meta">Updated <b id="updated">—</b> · uptime <b id="uptime">—</b></span>
    <button class="btn warn" id="pauseBtn" title="Freeze the view to read data">Pause</button>
    <button class="btn" id="refreshBtn" title="Fetch latest data now">Refresh</button>
  </div>
</div>

<section class="kpis" id="overview">
  <div class="kpi" data-go="overview" title="Jump to overview">
    <div class="label">Interfaces up</div><div class="value" id="k-ifaces">—</div><div class="sub" id="k-ifaces-sub">—</div>
  </div>
  <div class="kpi" data-go="connections" title="Jump to connections">
    <div class="label">Connections</div><div class="value" id="k-conns">—</div><div class="sub" id="k-conns-sub">—</div>
  </div>
  <div class="kpi" data-go="connections" title="Jump to listeners">
    <div class="label">Listeners</div><div class="value" id="k-listen">—</div><div class="sub">TCP services</div>
  </div>
  <div class="kpi" data-go="traffic" title="Jump to traffic chart">
    <div class="label">Upload rate</div><div class="value" id="k-up" style="color:#4ade80">—</div><div class="sub">all interfaces /s</div>
  </div>
  <div class="kpi" data-go="traffic" title="Jump to traffic chart">
    <div class="label">Download rate</div><div class="value" id="k-down" style="color:#7dd3fc">—</div><div class="sub">all interfaces /s</div>
  </div>
  <div class="kpi" data-go="events" title="Jump to security events">
    <div class="label">Security events</div><div class="value" id="k-events">—</div><div class="sub" id="k-events-sub">stored in SQLite</div>
  </div>
</section>

<section class="grid2" id="traffic">
  <div class="panel">
    <div class="panel-head"><h2>Traffic rate history (live)</h2></div>
    <canvas id="rateChart"></canvas>
    <div class="legend">
      <span><i style="background:#22c55e"></i>Upload</span>
      <span><i style="background:#38bdf8"></i>Download</span>
      <span class="muted">samples every 2 s · loopback excluded</span>
    </div>
  </div>
  <div class="panel">
    <div class="panel-head"><h2>Events by severity</h2><span class="muted" style="font-size:11.5px">click a bar to filter</span></div>
    <canvas id="sevChart"></canvas>
    <div class="legend"><span class="muted">totals across stored events · click bar → events table</span></div>
  </div>
</section>

<section class="grid2b">
  <div class="panel">
    <div class="panel-head"><h2>Network interfaces</h2><span class="count" id="if-count"></span></div>
    <div class="scroll">
      <table>
        <thead><tr><th>Interface</th><th>Type</th><th>Status</th><th>IPv4</th><th>IPv6</th><th>Speed</th></tr></thead>
        <tbody id="t-ifaces"></tbody>
      </table>
    </div>
  </div>
  <div class="panel">
    <div class="panel-head"><h2>Top processes by connections</h2></div>
    <div class="bars" id="t-processes"></div>
  </div>
</section>

<section class="grid2b">
  <div class="panel" id="listeners-panel">
    <div class="panel-head"><h2>TCP listening services</h2><span class="count" id="l-count"></span></div>
    <div class="scroll">
      <table>
        <thead><tr><th>Address</th><th>Port</th><th>Process</th></tr></thead>
        <tbody id="t-listen"></tbody>
      </table>
    </div>
  </div>
  <div class="panel" id="connections">
    <div class="panel-head">
      <h2>Active connections <span class="count" id="conn-count"></span></h2>
      <div class="chips" id="conn-chips">
        <button class="chip active" data-conn="">All</button>
        <button class="chip" data-conn="TCP">TCP</button>
        <button class="chip" data-conn="UDP">UDP</button>
        <button class="chip" data-conn="ESTABLISHED">Established</button>
        <button class="chip" data-conn="LISTEN">Listen</button>
      </div>
      <input class="search" id="conn-search" placeholder="Search IP, port, process…">
    </div>
    <div class="scroll">
      <table>
        <thead><tr>
          <th data-sort-c="proto">Proto</th>
          <th data-sort-c="local">Local</th>
          <th data-sort-c="remote">Remote</th>
          <th data-sort-c="status">Status</th>
          <th data-sort-c="process">Process</th>
        </tr></thead>
        <tbody id="t-conns"></tbody>
      </table>
    </div>
  </div>
</section>

<section class="panel" id="events">
  <div class="panel-head">
    <h2>Recent security events <span class="count" id="ev-count"></span></h2>
    <div class="chips" id="ev-chips">
      <button class="chip active" data-sev="">All</button>
      <button class="chip c-HIGH" data-sev="HIGH">High</button>
      <button class="chip c-MEDIUM" data-sev="MEDIUM">Medium</button>
      <button class="chip c-LOW" data-sev="LOW">Low</button>
      <button class="chip c-INFO" data-sev="INFO">Info</button>
    </div>
    <input class="search" id="ev-search" placeholder="Search IP, rule, text…">
    <a class="btn" href="/api/export?format=csv" title="Download all stored events as CSV">CSV</a>
    <a class="btn" href="/api/export?format=json" title="Download all stored events as JSON">JSON</a>
  </div>
  <div class="scroll">
    <table>
      <thead><tr>
        <th data-sort-e="severity">Severity</th>
        <th data-sort-e="category">Category</th>
        <th data-sort-e="source">Source</th>
        <th data-sort-e="dest">Destination</th>
        <th data-sort-e="description">Description</th>
        <th data-sort-e="time">Time</th>
      </tr></thead>
      <tbody id="t-events"></tbody>
    </table>
  </div>
</section>

<footer>
  <span>Full app: <code>python -m network_monitor.main</code></span>
  <span>Feature tour: <code>python -m network_monitor.showcase</code></span>
  <span>Click any event row for full evidence · charts and tables auto-refresh 2 s</span>
  <span class="muted">Live view only — packet capture stays in the terminal app.</span>
</footer>

<div class="modal hidden" id="modal">
  <div class="modal-card">
    <button class="close" id="modalClose" title="Close (Esc)">×</button>
    <h3 id="modal-title">Event</h3>
    <div class="kv" id="modal-kv"></div>
    <div class="muted" style="font-size:12px;margin-bottom:6px">Evidence / details</div>
    <pre id="modal-pre">{}</pre>
    <div style="margin-top:12px;display:flex;gap:8px">
      <button class="btn" id="copyBtn">Copy evidence</button>
      <button class="btn" id="closeBtn2">Close</button>
    </div>
  </div>
</div>

<script>
"use strict";
const $ = (id) => document.getElementById(id);
const SEV_RANK = { HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };

let S = null;                 // last state from server
let paused = false;
let lastMaxId = 0;
let firstLoad = true;
let filters = { sev: "", conn: "", evQ: "", connQ: "" };
let sortE = { key: "id", dir: -1 };
let sortC = { key: null, dir: 1 };
let sevGeom = null;
let currentEvent = null;

function esc(value) {
  return String(value == null ? "" : value).replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}

function fmtBytes(b) {
  if (b == null || isNaN(b)) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = Number(b), i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  const digits = i === 0 || v >= 100 ? 0 : 1;
  return v.toFixed(digits) + " " + units[i];
}
function fmtRate(bps) { return fmtBytes(bps) + "/s"; }
function fmtTime(iso) {
  if (!iso) return "—";
  try { return new Date(iso).toLocaleTimeString(); } catch (e) { return iso; }
}
function badge(sev) {
  const s = esc(sev || "INFO");
  return '<span class="badge b-' + s + '">' + s + "</span>";
}

function fitCanvas(canvas) {
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth, h = canvas.clientHeight;
  canvas.width = Math.max(1, Math.round(w * dpr));
  canvas.height = Math.max(1, Math.round(h * dpr));
  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);
  return { ctx, w, h };
}

function drawRates(history) {
  const { ctx, w, h } = fitCanvas($("rateChart"));
  const pad = { l: 58, r: 10, t: 12, b: 22 };
  ctx.font = "11px system-ui";
  if (!history || history.length < 2) {
    ctx.fillStyle = "#8494b0";
    ctx.fillText("Collecting live samples…", pad.l, h / 2);
    return;
  }
  let max = 1;
  history.forEach((p) => { max = Math.max(max, p.up, p.down); });
  max *= 1.15;
  const plotW = w - pad.l - pad.r, plotH = h - pad.t - pad.b;
  const xAt = (i) => pad.l + (i * plotW) / (history.length - 1);
  const yAt = (v) => pad.t + plotH - (v / max) * plotH;

  ctx.strokeStyle = "#1e2a44";
  ctx.fillStyle = "#8494b0";
  ctx.lineWidth = 1;
  for (let g = 0; g <= 4; g++) {
    const y = pad.t + (plotH * g) / 4;
    ctx.beginPath(); ctx.moveTo(pad.l, y); ctx.lineTo(w - pad.r, y); ctx.stroke();
    ctx.fillText(fmtRate(max * (1 - g / 4)), 4, y + 4);
  }
  function series(key, color, fill) {
    ctx.beginPath();
    history.forEach((p, i) => {
      const x = xAt(i), y = yAt(p[key]);
      if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.stroke();
    ctx.lineTo(xAt(history.length - 1), pad.t + plotH);
    ctx.lineTo(xAt(0), pad.t + plotH);
    ctx.closePath();
    ctx.fillStyle = fill; ctx.fill();
  }
  series("up", "#22c55e", "rgba(34,197,94,0.12)");
  series("down", "#38bdf8", "rgba(56,189,248,0.12)");
  ctx.fillStyle = "#8494b0";
  const first = new Date(history[0].t * 1000).toLocaleTimeString();
  const last = new Date(history[history.length - 1].t * 1000).toLocaleTimeString();
  ctx.fillText(first, pad.l, h - 6);
  const tw = ctx.measureText(last).width;
  ctx.fillText(last, w - pad.r - tw, h - 6);
}

function drawSeverity(counts) {
  const { ctx, w, h } = fitCanvas($("sevChart"));
  const keys = ["HIGH", "MEDIUM", "LOW", "INFO"];
  const colors = { HIGH: "#ef4444", MEDIUM: "#f59e0b", LOW: "#38bdf8", INFO: "#64748b" };
  const values = keys.map((k) => (counts && counts[k]) || 0);
  const max = Math.max(1, ...values);
  const pad = { l: 10, r: 10, t: 16, b: 30 };
  const plotW = w - pad.l - pad.r, plotH = h - pad.t - pad.b;
  const gap = 18;
  const barW = (plotW - gap * (keys.length - 1)) / keys.length;
  sevGeom = { keys, pad, barW, gap, w, h, plotH };
  ctx.font = "11px system-ui";
  keys.forEach((k, i) => {
    const x = pad.l + i * (barW + gap);
    const bh = (values[i] / max) * plotH;
    const y = pad.t + plotH - bh;
    ctx.fillStyle = "#0b1428";
    ctx.fillRect(x, pad.t, barW, plotH);
    ctx.fillStyle = colors[k];
    ctx.globalAlpha = filters.sev && filters.sev !== k ? 0.35 : 1;
    ctx.fillRect(x, y, barW, bh);
    ctx.globalAlpha = 1;
    if (filters.sev === k) {
      ctx.strokeStyle = "#e2e8f0";
      ctx.strokeRect(x - 1, pad.t - 1, barW + 2, plotH + 2);
    }
    ctx.fillStyle = "#e2e8f0";
    const label = String(values[i]);
    const lw = ctx.measureText(label).width;
    ctx.fillText(label, x + (barW - lw) / 2, Math.max(pad.t + 12, y - 5));
    ctx.fillStyle = filters.sev === k ? "#e2e8f0" : "#8494b0";
    const kw = ctx.measureText(k).width;
    ctx.fillText(k, x + (barW - kw) / 2, h - 10);
  });
}

function syncChips() {
  document.querySelectorAll("#ev-chips .chip").forEach((c) =>
    c.classList.toggle("active", c.dataset.sev === filters.sev));
  document.querySelectorAll("#conn-chips .chip").forEach((c) =>
    c.classList.toggle("active", c.dataset.conn === filters.conn));
}

function matchConn(c) {
  if (filters.conn === "TCP" || filters.conn === "UDP") {
    if (c.protocol !== filters.conn) return false;
  } else if (filters.conn === "ESTABLISHED" || filters.conn === "LISTEN") {
    if (c.status !== filters.conn) return false;
  }
  if (filters.connQ) {
    const hay = [c.protocol, c.local_ip, c.local_port, c.remote_ip,
                 c.remote_port, c.status, c.process_name, c.pid]
      .join(" ").toLowerCase();
    if (!hay.includes(filters.connQ)) return false;
  }
  return true;
}

function matchEvent(e) {
  if (filters.sev && e.severity !== filters.sev) return false;
  if (filters.evQ) {
    const hay = [e.severity, e.category, e.source_ip, e.destination_ip,
                 e.description, e.timestamp].join(" ").toLowerCase();
    if (!hay.includes(filters.evQ)) return false;
  }
  return true;
}

function sortRows(rows, sort, acc) {
  if (!sort.key) return rows;
  const a = acc[sort.key];
  if (!a) return rows;
  return rows.slice().sort((x, y) => {
    const vx = a(x), vy = a(y);
    if (typeof vx === "number" && typeof vy === "number") {
      return (vx - vy) * sort.dir;
    }
    return String(vx == null ? "" : vx).localeCompare(
      String(vy == null ? "" : vy)) * sort.dir;
  });
}

function renderConns() {
  const conns = (S.connections || []).filter(matchConn);
  const sorted = sortRows(conns, sortC, {
    proto: (c) => c.protocol,
    local: (c) => String(c.local_ip) + ":" + String(c.local_port),
    remote: (c) => String(c.remote_ip) + ":" + String(c.remote_port),
    status: (c) => c.status,
    process: (c) => String(c.process_name || ""),
  });
  $("conn-count").textContent = "(" + sorted.length + "/" +
    (S.connections || []).length + ")";
  $("t-conns").innerHTML = sorted.length ? sorted.slice(0, 40).map((c) =>
    "<tr><td>" + badge(c.protocol) + "</td>" +
    '<td class="mono">' + esc(c.local_ip) + ":" + esc(c.local_port) + "</td>" +
    '<td class="mono">' + esc(c.remote_ip) + ":" + esc(c.remote_port) + "</td>" +
    "<td>" + esc(c.status) + "</td>" +
    "<td>" + esc(c.process_name || "—") +
    (c.pid ? ' <span class="muted">#' + esc(c.pid) + "</span>" : "") +
    "</td></tr>"
  ).join("") : '<tr><td colspan="5" class="empty">No connections match the current filter.</td></tr>';
}

function renderEvents() {
  const events = (S.events || []).filter(matchEvent);
  const sorted = sortRows(events, sortE, {
    severity: (e) => SEV_RANK[e.severity] || 0,
    category: (e) => e.category || "",
    source: (e) => e.source_ip || "",
    dest: (e) => e.destination_ip || "",
    description: (e) => e.description || "",
    time: (e) => e.timestamp || "",
    id: (e) => e.id || 0,
  });
  $("ev-count").textContent = "(" + sorted.length + "/" +
    (S.events || []).length + ")";
  const maxId = Math.max(0, ...(S.events || []).map((e) => e.id || 0));
  const fresh = new Set();
  if (!firstLoad && maxId > lastMaxId) {
    (S.events || []).forEach((e) => {
      if ((e.id || 0) > lastMaxId && (e.severity === "HIGH" || e.severity === "MEDIUM")) {
        fresh.add(e.id);
      }
    });
  }
  if (!firstLoad) lastMaxId = Math.max(lastMaxId, maxId);
  if (firstLoad) { lastMaxId = maxId; firstLoad = false; }

  $("t-events").innerHTML = sorted.length ? sorted.slice(0, 40).map((e) =>
    '<tr class="clickable' + (fresh.has(e.id) ? " flash" : "") +
    '" data-id="' + esc(e.id) + '" title="Click for full evidence">' +
    "<td>" + badge(e.severity) + "</td>" +
    "<td>" + esc(e.category) + "</td>" +
    '<td class="mono">' + esc(e.source_ip || "—") + "</td>" +
    '<td class="mono">' + esc(e.destination_ip || "—") + "</td>" +
    "<td>" + esc(e.description) + "</td>" +
    '<td class="mono muted">' + esc(fmtTime(e.timestamp)) + "</td></tr>"
  ).join("") : '<tr><td colspan="6" class="empty">No events match the current filter.</td></tr>';
}

function openEvent(id) {
  const e = (S.events || []).find((x) => x.id === id);
  if (!e) return;
  currentEvent = e;
  $("modal-title").innerHTML = badge(e.severity) + " " + esc(e.category);
  $("modal-kv").innerHTML =
    '<div class="k">Event ID</div><div>' + esc(e.id) + "</div>" +
    '<div class="k">Timestamp</div><div class="mono">' + esc(e.timestamp) + "</div>" +
    '<div class="k">Source</div><div class="mono">' + esc(e.source_ip || "—") + "</div>" +
    '<div class="k">Destination</div><div class="mono">' + esc(e.destination_ip || "—") + "</div>" +
    '<div class="k">Description</div><div>' + esc(e.description) + "</div>";
  let details = e.details;
  try { details = JSON.stringify(JSON.parse(details), null, 2); } catch (err) {}
  $("modal-pre").textContent = details || "{}";
  $("modal").classList.remove("hidden");
}

function closeModal() { $("modal").classList.add("hidden"); currentEvent = null; }

function render(state) {
  S = state;
  $("updated").textContent = fmtTime(state.updated);
  $("uptime").textContent = Math.round(state.uptime_seconds || 0) + "s";

  const ifaces = state.interfaces || [];
  const up = ifaces.filter((i) => i.status === "UP").length;
  $("k-ifaces").textContent = up + " / " + ifaces.length;
  $("k-ifaces-sub").textContent = [...new Set(ifaces.map((i) => i.type))].join(", ") || "—";
  $("if-count").textContent = ifaces.length;

  const conns = state.connections || [];
  const tcp = conns.filter((c) => c.protocol === "TCP").length;
  const est = conns.filter((c) => c.status === "ESTABLISHED").length;
  $("k-conns").textContent = conns.length;
  $("k-conns-sub").textContent = "TCP " + tcp + " · UDP " + (conns.length - tcp) + " · established " + est;
  $("k-listen").textContent = (state.listeners || []).length;

  let upTotal = 0, downTotal = 0;
  (state.speeds || []).forEach((s) => {
    if (s.name !== "lo") { upTotal += s.upload_bps || 0; downTotal += s.download_bps || 0; }
  });
  $("k-up").textContent = fmtRate(upTotal);
  $("k-down").textContent = fmtRate(downTotal);

  $("k-events").textContent = state.event_total || 0;
  const sc = state.severity_counts || {};
  $("k-events-sub").innerHTML =
    '<span style="color:#f87171">H ' + (sc.HIGH || 0) + "</span> · " +
    '<span style="color:#fbbf24">M ' + (sc.MEDIUM || 0) + "</span> · " +
    '<span style="color:#94a3b8">I ' + (sc.INFO || 0) + "</span>";

  document.querySelectorAll("#ev-chips .chip[data-sev]").forEach((chip) => {
    const sev = chip.dataset.sev;
    if (sev) {
      const n = sc[sev] || 0;
      chip.textContent = chip.textContent.replace(/ \(\d+\)$/, "") + " (" + n + ")";
    }
  });

  $("t-ifaces").innerHTML = ifaces.length ? ifaces.map((i) =>
    "<tr><td>" + esc(i.name) + "</td><td>" + esc(i.type) + "</td>" +
    '<td><span class="badge b-' + esc(i.status) + '">' + esc(i.status) + "</span></td>" +
    '<td class="mono">' + esc((i.ipv4 || []).join(", ") || "—") + "</td>" +
    '<td class="mono">' + esc((i.ipv6 || []).slice(0, 2).join(", ") || "—") +
    (i.ipv6 && i.ipv6.length > 2 ? " …" : "") + "</td>" +
    "<td>" + (i.speed != null ? esc(i.speed) + " Mbps" : "—") + "</td></tr>"
  ).join("") : '<tr><td colspan="6" class="empty">Collecting…</td></tr>';

  const procs = state.process_counts || [];
  const pmax = Math.max(1, ...procs.map((p) => p.count));
  $("t-processes").innerHTML = procs.length ? procs.map((p) =>
    '<div class="bar-row"><span class="bar-label" title="' + esc(p.name) + '">' + esc(p.name) + "</span>" +
    '<div class="bar-track"><div class="bar-fill" style="width:' + Math.round((p.count / pmax) * 100) + '%"></div></div>' +
    '<span class="bar-val">' + p.count + "</span></div>"
  ).join("") : '<div class="empty">Collecting…</div>';

  const listeners = (state.listeners || []).filter((l) => l.protocol === "TCP" || !l.protocol);
  $("l-count").textContent = listeners.length;
  $("t-listen").innerHTML = listeners.length ? listeners.slice(0, 20).map((l) =>
    '<tr><td class="mono">' + esc(l.local_ip) + '</td><td class="mono">' +
    esc(l.local_port) + "</td><td>" + esc(l.process_name || "—") + "</td></tr>"
  ).join("") : '<tr><td colspan="3" class="empty">None</td></tr>';

  renderConns();
  renderEvents();
  syncChips();
  drawRates(state.history);
  drawSeverity(state.severity_counts);
}

async function refresh() {
  if (paused) return;
  try {
    const res = await fetch("/api/state", { cache: "no-store" });
    if (!res.ok) throw new Error("HTTP " + res.status);
    render(await res.json());
  } catch (err) {
    $("status-text").textContent = "RECONNECTING";
  }
}

document.addEventListener("click", (ev) => {
  const chipSev = ev.target.closest("#ev-chips .chip");
  if (chipSev) {
    filters.sev = chipSev.dataset.sev;
    renderEvents(); syncChips(); drawSeverity(S ? S.severity_counts : {});
    return;
  }
  const chipConn = ev.target.closest("#conn-chips .chip");
  if (chipConn) {
    filters.conn = chipConn.dataset.conn;
    renderConns(); syncChips();
    return;
  }
  const row = ev.target.closest("#t-events tr[data-id]");
  if (row) { openEvent(Number(row.dataset.id)); return; }
  const kpi = ev.target.closest(".kpi[data-go]");
  if (kpi) {
    const target = $(kpi.dataset.go);
    if (target) target.scrollIntoView({ behavior: "smooth", block: "start" });
    return;
  }
  const thE = ev.target.closest("th[data-sort-e]");
  if (thE) {
    const key = thE.dataset.sortE;
    sortE = { key, dir: sortE.key === key ? -sortE.dir : (key === "id" || key === "time" ? -1 : 1) };
    document.querySelectorAll("th[data-sort-e]").forEach((t) =>
      t.classList.remove("sorted", "asc"));
    thE.classList.add("sorted");
    if (sortE.dir === 1) thE.classList.add("asc");
    renderEvents();
    return;
  }
  const thC = ev.target.closest("th[data-sort-c]");
  if (thC) {
    const key = thC.dataset.sortC;
    sortC = { key, dir: sortC.key === key ? -sortC.dir : 1 };
    document.querySelectorAll("th[data-sort-c]").forEach((t) =>
      t.classList.remove("sorted", "asc"));
    thC.classList.add("sorted");
    if (sortC.dir === 1) thC.classList.add("asc");
    renderConns();
    return;
  }
});

$("ev-search").addEventListener("input", (e) => {
  filters.evQ = e.target.value.trim().toLowerCase();
  renderEvents();
});
$("conn-search").addEventListener("input", (e) => {
  filters.connQ = e.target.value.trim().toLowerCase();
  renderConns();
});

$("sevChart").addEventListener("click", (ev) => {
  if (!sevGeom) return;
  const rect = $("sevChart").getBoundingClientRect();
  const x = ev.clientX - rect.left;
  const { keys, pad, barW, gap } = sevGeom;
  keys.forEach((k, i) => {
    const bx = pad.l + i * (barW + gap);
    if (x >= bx && x <= bx + barW) {
      filters.sev = filters.sev === k ? "" : k;
      renderEvents(); syncChips(); drawSeverity(S ? S.severity_counts : {});
      $("events").scrollIntoView({ behavior: "smooth", block: "start" });
    }
  });
});

$("pauseBtn").addEventListener("click", () => {
  paused = !paused;
  $("pauseBtn").textContent = paused ? "Resume" : "Pause";
  $("status").classList.toggle("paused", paused);
  $("status-text").textContent = paused ? "PAUSED" : "LIVE";
  if (!paused) refresh();
});
$("refreshBtn").addEventListener("click", () => {
  const wasPaused = paused;
  paused = false;
  refresh().finally(() => { paused = wasPaused; });
});

$("modalClose").addEventListener("click", closeModal);
$("closeBtn2").addEventListener("click", closeModal);
$("modal").addEventListener("click", (e) => { if (e.target === $("modal")) closeModal(); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeModal(); });
$("copyBtn").addEventListener("click", async () => {
  if (!currentEvent) return;
  let text = currentEvent.details || "";
  try { text = JSON.stringify(JSON.parse(text), null, 2); } catch (err) {}
  try {
    await navigator.clipboard.writeText(text);
    $("copyBtn").textContent = "Copied!";
    setTimeout(() => { $("copyBtn").textContent = "Copy evidence"; }, 1500);
  } catch (err) {
    $("copyBtn").textContent = "Copy failed";
    setTimeout(() => { $("copyBtn").textContent = "Copy evidence"; }, 1500);
  }
});

window.addEventListener("resize", () => {
  if (!S) return;
  drawRates(S.history);
  drawSeverity(S.severity_counts);
});

refresh();
setInterval(refresh, 2000);
</script>
</body>
</html>
"""


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Local web dashboard for the Python Network Monitor")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"HTTP port (default {DEFAULT_PORT})")
    parser.add_argument("--no-browser", action="store_true",
                        help="do not open the browser automatically")
    args = parser.parse_args()

    prepare_directories()
    settings = Settings.load()
    storage = Storage()
    state = DashboardState(settings, storage)

    thread = threading.Thread(target=state.monitor_loop, daemon=True,
                              name="web-monitor")
    thread.start()

    handler = make_handler(state)
    try:
        httpd = ThreadingHTTPServer((HOST, args.port), handler)
    except OSError as error:
        print(f"Cannot bind {HOST}:{args.port} ({error}). "
              f"Try: python -m network_monitor.web --port {args.port + 1}")
        sys.exit(1)

    url = f"http://{HOST}:{args.port}/"
    print("Python Network Monitor — web dashboard")
    print(f"  URL:      {url}")
    print(f"  Samples:  every {settings.monitor_interval}s "
          "(background, no input needed)")
    print("  Stop:     Ctrl+C")
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
    finally:
        state.stop_event.set()
        httpd.server_close()


if __name__ == "__main__":
    main()
