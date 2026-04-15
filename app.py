#!/usr/bin/env python3
from __future__ import annotations

import cgi
import concurrent.futures as cf
import csv
import html
import http.client
import io
import os
import socket
import ssl
import time
import traceback
from datetime import datetime
from socketserver import ThreadingMixIn
from typing import Any
from urllib.parse import urlparse
from wsgiref.simple_server import WSGIServer, WSGIRequestHandler, make_server


APP_TITLE = "ESB Network Test Connection"
DEFAULT_TIMEOUT = 3.0
DEFAULT_PROTOCOL = "tcp"
DEFAULT_PORTS = {
    "tcp": 80,
    "http": 80,
    "https": 443,
}
RECENT_TESTS: list[dict[str, Any]] = []
MAX_RECENT_TESTS = 5


class ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True


def esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def clamp_recent_tests(item: dict[str, Any]) -> None:
    RECENT_TESTS.insert(0, item)
    del RECENT_TESTS[MAX_RECENT_TESTS:]


def read_form(environ: dict[str, Any]) -> tuple[dict[str, list[str]], dict[str, list[cgi.FieldStorage]]]:
    if environ.get("REQUEST_METHOD", "GET").upper() != "POST":
        return {}, {}

    try:
        form = cgi.FieldStorage(fp=environ["wsgi.input"], environ=environ, keep_blank_values=True)
    except Exception as exc:
        raise ValueError(f"Gagal membaca form upload: {exc}") from exc

    fields: dict[str, list[str]] = {}
    files: dict[str, list[cgi.FieldStorage]] = {}

    if form.list:
        for item in form.list:
            if not item.name:
                continue
            if item.filename:
                files.setdefault(item.name, []).append(item)
            else:
                fields.setdefault(item.name, []).append((item.value or "").strip())

    return fields, files


def default_port(protocol: str) -> int:
    return DEFAULT_PORTS.get(protocol, 80)


def default_path(protocol: str) -> str:
    return "/" if protocol in {"http", "https"} else ""


def first_value(fields: dict[str, list[str]], name: str, default: str = "") -> str:
    values = fields.get(name)
    if not values:
        return default
    return values[0]


def first_file(files: dict[str, list[cgi.FieldStorage]], name: str) -> cgi.FieldStorage | None:
    values = files.get(name)
    if not values:
        return None
    return values[0]


def parse_rows(fields: dict[str, list[str]]) -> list[dict[str, str]]:
    targets = fields.get("target", [])
    ports = fields.get("port", [])
    statuses = fields.get("status", [])
    row_count = max(len(targets), len(ports), len(statuses), 1)
    rows: list[dict[str, str]] = []

    for index in range(row_count):
        rows.append(
            {
                "target": targets[index] if index < len(targets) else "",
                "port": ports[index] if index < len(ports) else "",
                "status": statuses[index] if index < len(statuses) else "disconnect",
            }
        )

    return rows


def parse_csv_rows(content: str) -> list[dict[str, str]]:
    reader = csv.reader(io.StringIO(content), delimiter=",")
    rows: list[dict[str, str]] = []

    for line_no, row in enumerate(reader, start=1):
        cells = [cell.strip() for cell in row]
        if not cells or not any(cells):
            continue
        if len(cells) < 2:
            raise ValueError(f"CSV baris {line_no} harus punya format `target,port`.")

        target, port = cells[0], cells[1]
        if line_no == 1 and target.lower() == "target" and port.lower() == "port":
            continue
        rows.append({"target": target, "port": port, "status": "disconnect"})

    if not rows:
        raise ValueError("CSV tidak berisi data yang bisa diimpor.")

    return rows


def parse_target(raw_target: str, protocol_choice: str, port_value: str, path_value: str) -> dict[str, Any]:
    target = raw_target.strip()
    if not target:
        raise ValueError("Target wajib diisi. Contoh: `example.com` atau `https://example.com`.")

    has_scheme = "://" in target
    parsed = urlparse(target if has_scheme else f"//{target}", scheme="")

    host = parsed.hostname or ""
    if not host:
        raise ValueError("Target tidak valid. Masukkan host, IP, atau URL yang benar.")

    protocol = (parsed.scheme or protocol_choice or DEFAULT_PROTOCOL).lower()
    if protocol not in {"tcp", "http", "https"}:
        raise ValueError("Protocol harus `tcp`, `http`, atau `https`.")

    port_text = port_value.strip()
    if port_text:
        try:
            port = int(port_text)
        except ValueError as exc:
            raise ValueError("Port harus berupa angka.") from exc
    else:
        port = parsed.port or default_port(protocol)

    if not 1 <= port <= 65535:
        raise ValueError("Port harus berada di rentang 1 sampai 65535.")

    path = path_value.strip() or default_path(protocol)
    if parsed.path and parsed.path not in {"", "/"}:
        path = parsed.path
    if parsed.query:
        path = f"{path}?{parsed.query}" if path else f"/?{parsed.query}"

    return {
        "target": target,
        "host": host,
        "protocol": protocol,
        "port": port,
        "path": path,
        "url_detected": has_scheme,
    }


def resolve_addresses(host: str, port: int) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"DNS lookup gagal untuk `{host}`: {exc}") from exc

    addresses: list[str] = []
    for info in infos:
        sockaddr = info[4]
        address = sockaddr[0]
        if address not in addresses:
            addresses.append(address)
    return addresses


def format_socket_address(value: Any) -> str:
    if isinstance(value, tuple) and len(value) >= 2:
        return f"{value[0]}:{value[1]}"
    return str(value)


def test_tcp_connection(host: str, port: int, timeout: float) -> dict[str, Any]:
    try:
        resolved = resolve_addresses(host, port)
    except ValueError as exc:
        return {
            "status": "disconnect",
            "severity": "danger",
            "summary": str(exc),
            "resolved": [],
            "elapsed_ms": 0.0,
            "error": "dns",
        }

    start = time.perf_counter()

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            peer = format_socket_address(sock.getpeername())
            local = format_socket_address(sock.getsockname())
        elapsed_ms = (time.perf_counter() - start) * 1000

        return {
            "status": "connected",
            "severity": "success",
            "summary": "TCP handshake berhasil.",
            "resolved": resolved,
            "peer": peer,
            "local": local,
            "elapsed_ms": elapsed_ms,
        }
    except socket.timeout:
        elapsed_ms = (time.perf_counter() - start) * 1000
        return {
            "status": "disconnect",
            "severity": "danger",
            "summary": f"Timeout setelah {timeout:.1f} detik.",
            "resolved": resolved,
            "elapsed_ms": elapsed_ms,
            "error": "timeout",
        }
    except (ConnectionRefusedError, OSError) as exc:
        elapsed_ms = (time.perf_counter() - start) * 1000
        return {
            "status": "disconnect",
            "severity": "danger",
            "summary": f"Koneksi ditolak atau tidak bisa dijangkau: {exc}",
            "resolved": resolved,
            "elapsed_ms": elapsed_ms,
            "error": "disconnect",
        }


def http_connection(host: str, port: int, timeout: float, path: str, secure: bool) -> dict[str, Any]:
    methods = ("HEAD", "GET")
    last_error: Exception | None = None
    status = None
    reason = ""
    method_used = ""
    bytes_read = 0

    for method in methods:
        connection: http.client.HTTPConnection | http.client.HTTPSConnection | None = None
        try:
            if secure:
                context = ssl.create_default_context()
                connection = http.client.HTTPSConnection(host, port=port, timeout=timeout, context=context)
            else:
                connection = http.client.HTTPConnection(host, port=port, timeout=timeout)

            start = time.perf_counter()
            connection.request(
                method,
                path or "/",
                headers={
                    "User-Agent": "Network-Test-Connection/1.0",
                    "Accept": "*/*",
                },
            )
            response = connection.getresponse()
            body = response.read(256)
            elapsed_ms = (time.perf_counter() - start) * 1000

            status = response.status
            reason = response.reason
            method_used = method
            bytes_read = len(body)

            if status in {405, 501} and method == "HEAD":
                continue

            severity = "success" if status < 400 else "warning"
            summary = f"HTTP {status} {reason}".strip()
            if status >= 400:
                summary = f"Endpoint reachable, but server returned {summary}."
            else:
                summary = f"HTTP request completed with {summary}."

            return {
                "status": "connected",
                "severity": severity,
                "summary": summary,
                "http_status": status,
                "http_reason": reason,
                "method_used": method_used,
                "bytes_read": bytes_read,
                "elapsed_ms": elapsed_ms,
            }
        except Exception as exc:
            last_error = exc
        finally:
            if connection is not None:
                connection.close()

    raise ValueError(f"HTTP check gagal: {last_error}") from last_error


def run_single_check(target: str, port_value: str, timeout_value: str) -> tuple[dict[str, Any] | None, str | None]:
    try:
        parsed = parse_target(target, "tcp", port_value, "")
        try:
            timeout = float(timeout_value or DEFAULT_TIMEOUT)
        except ValueError as exc:
            raise ValueError("Timeout harus berupa angka.") from exc

        if timeout <= 0:
            raise ValueError("Timeout harus lebih besar dari 0.")

        check = test_tcp_connection(parsed["host"], parsed["port"], timeout)

        result = {
            **check,
            "host": parsed["host"],
            "port": parsed["port"],
            "protocol": "TCP",
            "path": "",
            "target": parsed["target"],
            "url_detected": parsed["url_detected"],
            "timeout": timeout,
            "total_ms": check["elapsed_ms"],
            "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        return result, None
    except ValueError as exc:
        return None, str(exc)


def run_batch_checks(rows: list[dict[str, str]], timeout_value: str) -> tuple[list[dict[str, str]], dict[str, Any], str | None]:
    try:
        timeout = float(timeout_value or DEFAULT_TIMEOUT)
    except ValueError as exc:
        raise ValueError("Timeout harus berupa angka.") from exc

    if timeout <= 0:
        raise ValueError("Timeout harus lebih besar dari 0.")

    results: list[tuple[int, dict[str, Any] | None, str | None]] = []

    def worker(index: int, row: dict[str, str]) -> tuple[int, dict[str, Any] | None, str | None]:
        target = row.get("target", "").strip()
        port = row.get("port", "").strip()
        if not target or not port:
            return index, None, None
        result, error = run_single_check(target, port, timeout_value)
        return index, result, error

    max_workers = min(20, max(1, len(rows)))
    with cf.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(worker, index, row) for index, row in enumerate(rows)]
        for future in cf.as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda item: item[0])

    connected_count = 0
    disconnect_count = 0
    tested_count = 0
    summary_error: str | None = None
    updated_rows = [dict(row) for row in rows]

    for index, result, error in results:
        if result:
            tested_count += 1
            updated_rows[index]["status"] = result["status"]
            if result["status"] == "connected":
                connected_count += 1
                clamp_recent_tests(
                    {
                        "target": f"{result['host']}:{result['port']}",
                        "protocol": result["protocol"],
                        "status": result["status"],
                        "elapsed_ms": result["total_ms"],
                        "checked_at": result["checked_at"],
                    }
                )
            else:
                disconnect_count += 1
        else:
            if updated_rows[index].get("target") or updated_rows[index].get("port"):
                disconnect_count += 1
                updated_rows[index]["status"] = "disconnect"
            if error and not summary_error:
                summary_error = error

    if tested_count == 0:
        severity = "warning"
        status = "disconnect"
    elif disconnect_count == 0:
        severity = "success"
        status = "connected"
    elif connected_count == 0:
        severity = "danger"
        status = "disconnect"
    else:
        severity = "warning"
        status = "partial"

    summary = {
        "kind": "batch",
        "status": status,
        "severity": severity,
        "title": "Test All selesai",
        "summary": f"{tested_count} target diuji. {connected_count} connected, {disconnect_count} disconnect.",
        "total": len(rows),
        "tested": tested_count,
        "connected": connected_count,
        "disconnect": disconnect_count,
        "timeout": timeout,
        "elapsed_ms": 0.0,
        "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "protocol": "BATCH",
        "host": "-",
        "port": "-",
        "resolved": [],
    }

    return updated_rows, summary, summary_error


def render_input(name: str, value: str, label: str, placeholder: str = "", input_type: str = "text", hint: str = "") -> str:
    hint_html = f'<div class="hint">{esc(hint)}</div>' if hint else ""
    return f"""
      <div class="field">
        <label for="{esc(name)}">{esc(label)}</label>
        <input id="{esc(name)}" name="{esc(name)}" type="{esc(input_type)}" value="{esc(value)}" placeholder="{esc(placeholder)}" />
        {hint_html}
      </div>
    """


def render_select(name: str, value: str, label: str, options: list[tuple[str, str]], hint: str = "") -> str:
    option_html = []
    for option_value, option_label in options:
        selected = " selected" if value == option_value else ""
        option_html.append(f'<option value="{esc(option_value)}"{selected}>{esc(option_label)}</option>')

    hint_html = f'<div class="hint">{esc(hint)}</div>' if hint else ""
    return f"""
      <div class="field">
        <label for="{esc(name)}">{esc(label)}</label>
        <select id="{esc(name)}" name="{esc(name)}">
          {''.join(option_html)}
        </select>
        {hint_html}
      </div>
    """


def render_result(result: dict[str, Any] | None, error: str | None) -> str:
    if error:
        return f"""
          <section class="card result-card">
            <span class="badge danger">Validation error</span>
            <div class="result-title">
              <div>
                <h2>Input belum valid</h2>
                <p>{esc(error)}</p>
              </div>
            </div>
          </section>
        """

    if not result:
        return """
          <section class="card result-card">
            <span class="badge success">Ready</span>
            <div class="result-title">
              <div>
                <h2>Siap menguji koneksi</h2>
                <p>Masukkan beberapa IP / DNS dan Port, lalu klik tombol Test di baris yang ingin dicek.</p>
              </div>
            </div>
          </section>
        """

    if result.get("kind") == "batch":
        badge_class = result.get("severity", "warning")
        if badge_class == "success":
            badge_label = "Connected"
        elif badge_class == "warning":
            badge_label = "Partial"
        else:
            badge_label = "Disconnect"
        metrics = [
            ("Total", str(result.get("total", 0))),
            ("Tested", str(result.get("tested", 0))),
            ("Connected", str(result.get("connected", 0))),
            ("Disconnect", str(result.get("disconnect", 0))),
        ]
        metric_html = "".join(
            f"""
              <div class="metric">
                <span>{esc(label)}</span>
                <strong>{esc(value)}</strong>
              </div>
            """
            for label, value in metrics
        )

        return f"""
          <section class="card result-card">
            <span class="badge {esc(badge_class)}">{esc(result.get('title', 'Batch result'))}</span>
            <div class="result-title">
              <div>
                <h2>{esc(result.get('summary', 'Batch test complete.'))}</h2>
                <p>Ringkasan hasil untuk semua row yang terisi.</p>
              </div>
            </div>
            <div class="metrics">
              {metric_html}
            </div>
          </section>
        """

    badge_class = result["severity"]
    badge_label = "Connected" if badge_class == "success" else "Disconnect"
    if result["status"] != "connected":
        badge_label = "Disconnect"
        badge_class = "danger"

    resolved = ", ".join(result.get("resolved", [])) or "-"
    method_used = result.get("method_used", "-")
    http_status = result.get("http_status")
    http_reason = result.get("http_reason", "-")
    host = result.get("host", "-")
    port = result.get("port", "-")
    protocol = result.get("protocol", "TCP")
    checked_at = result.get("checked_at", "-")
    timeout_value = result.get("timeout", DEFAULT_TIMEOUT)

    if result["status"] != "connected":
        if result.get("error") == "timeout":
            status_line = f"TCP ke {host}:{port} timeout setelah {result.get('timeout', DEFAULT_TIMEOUT):.1f} detik."
        else:
            status_line = f"TCP ke {host}:{port} disconnect."
    elif protocol == "TCP":
        status_line = f"TCP ke {host}:{port} berhasil dalam {result['elapsed_ms']:.1f} ms."
    else:
        status_line = (
            f"HTTP {method_used} ke {host}:{port}{result.get('path', '')} "
            f"selesai dalam {result['elapsed_ms']:.1f} ms."
        )

    details = [
        ("Target", f"{host}:{port}"),
        ("Protocol", protocol),
        ("DNS", resolved),
        ("Checked at", checked_at),
    ]

    if protocol != "TCP":
        details.extend(
            [
                ("HTTP status", f"{http_status} {http_reason}".strip()),
                ("HTTP method", method_used),
                ("Body sample", f"{result.get('bytes_read', 0)} bytes"),
            ]
        )
    else:
        details.extend(
            [
                ("Local socket", result.get("local", "-")),
                ("Peer socket", result.get("peer", "-")),
            ]
        )

    detail_html = "".join(
        f"""
          <div class="detail">
            <span>{esc(label)}</span>
            <strong>{esc(value)}</strong>
          </div>
        """
        for label, value in details
    )

    return f"""
      <section class="card result-card">
        <span class="badge {esc(badge_class)}">{esc(badge_label)}</span>
        <div class="result-title">
          <div>
            <h2>{esc(status_line)}</h2>
            <p>{esc(result['summary'])}</p>
          </div>
        </div>
        <div class="metrics">
          <div class="metric">
            <span>Latency</span>
            <strong>{result.get('total_ms', result.get('elapsed_ms', 0.0)):.1f} ms</strong>
          </div>
          <div class="metric">
            <span>Timeout</span>
            <strong>{esc(timeout_value)} s</strong>
          </div>
          <div class="metric">
            <span>Mode</span>
            <strong>{esc(protocol)}</strong>
          </div>
        </div>
        <div class="detail-list">
          {detail_html}
        </div>
        {'<div class="error-box">' + esc(result.get("error", "")) + '</div>' if result.get("status") == "failed" and result.get("error") else ""}
      </section>
    """


def render_history() -> str:
    if not RECENT_TESTS:
        return """
          <section class="card history">
            <div class="section-head">
              <div>
                <span class="badge warning">History</span>
                <h2>Belum ada riwayat</h2>
              </div>
            </div>
            <p class="section-copy">
              Hasil tes terakhir akan muncul di sini agar mudah membandingkan target yang sudah dicoba.
            </p>
          </section>
        """

    rows_html = "".join(
        f"""
          <tr>
            <td>{esc(item['target'])}</td>
            <td>{esc(item['protocol'])}</td>
            <td><span class="mini-badge {esc('ok' if item['status'] == 'connected' else 'danger')}">{esc('Connected' if item['status'] == 'connected' else 'Disconnect')}</span></td>
            <td>{item['elapsed_ms']:.1f} ms</td>
            <td>{esc(item['checked_at'])}</td>
          </tr>
        """
        for item in RECENT_TESTS
    )

    return f"""
      <section class="card history">
        <div class="section-head">
          <div>
            <span class="badge warning">History</span>
            <h2>Tes terbaru</h2>
          </div>
        </div>
        <div class="table-wrap">
          <table class="data-table">
            <thead>
              <tr>
                <th>Target</th>
                <th>Protocol</th>
                <th>Status</th>
                <th>Latency</th>
                <th>Checked at</th>
              </tr>
            </thead>
            <tbody>
              {rows_html}
            </tbody>
          </table>
        </div>
      </section>
    """


def render_toast(toast: dict[str, str] | None) -> str:
    if not toast:
        return ""

    return f"""
      <div class="toast toast-{esc(toast.get('kind', 'danger'))}" id="toast" role="status" aria-live="polite">
        <strong>{esc(toast.get('title', 'Notice'))}</strong>
        <span>{esc(toast.get('message', ''))}</span>
      </div>
    """


def summarize_rows(rows: list[dict[str, str]]) -> dict[str, int]:
    meaningful_rows = [row for row in rows if (row.get("target") or row.get("port"))]
    total = len(meaningful_rows)
    connected = sum(1 for row in meaningful_rows if row.get("status") == "connected")
    disconnect = max(total - connected, 0)
    return {
        "total": total,
        "connected": connected,
        "disconnect": disconnect,
    }


def render_summary_cards(summary: dict[str, int]) -> str:
    return f"""
      <div class="summary-grid">
        <div class="summary-card">
          <span>Total</span>
          <strong id="summary-total">{summary['total']}</strong>
        </div>
        <div class="summary-card">
          <span>Connected</span>
          <strong id="summary-connected">{summary['connected']}</strong>
        </div>
        <div class="summary-card">
          <span>Disconnect</span>
          <strong id="summary-disconnect">{summary['disconnect']}</strong>
        </div>
      </div>
    """


def render_rows_table(rows: list[dict[str, str]]) -> str:
    if not rows:
        rows = [{"target": "", "port": "", "status": "disconnect"}]

    row_html = []
    for index, row in enumerate(rows):
        status = row.get("status", "disconnect")
        is_connected = status == "connected"
        pill_class = "ok" if is_connected else "danger"
        pill_label = "Connected" if is_connected else "Disconnect"
        row_html.append(
            f"""
              <tr data-status="{esc(status)}">
                <td>
                  <input
                    class="inline-input"
                    name="target"
                    type="text"
                    value="{esc(row.get('target', ''))}"
                    placeholder="192.168.1.10 or example.local"
                  />
                </td>
                <td>
                  <input
                    class="inline-input"
                    name="port"
                    type="number"
                    value="{esc(row.get('port', ''))}"
                    placeholder="80"
                  />
                </td>
                <td>
                  <span class="status-pill {pill_class}">{pill_label}</span>
                  <input type="hidden" name="status" value="{esc(status)}" />
                </td>
                <td>
                  <div class="row-actions">
                    <button class="test-button row-test-button" type="submit" name="action" value="test:{index}" aria-label="Run test" title="Run test">
                      <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                        <path d="M8.5 5.5v13l10-6.5-10-6.5z"></path>
                      </svg>
                    </button>
                    <button class="delete-button row-delete-button" type="button" aria-label="Delete row" title="Delete row">
                      <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                        <path d="M9 3.75h6a1.25 1.25 0 0 1 1.25 1.25V6h3a.75.75 0 0 1 0 1.5h-1.06l-.7 10.02A2.25 2.25 0 0 1 15.25 19.5h-6.5a2.25 2.25 0 0 1-2.24-2.02L5.82 7.5H4.75a.75.75 0 0 1 0-1.5h3V5A1.25 1.25 0 0 1 9 3.75zm0 1.5V6h6V5.25H9zm-1.67 2.25.66 9.88c.03.41.37.73.78.73h6.48c.41 0 .75-.32.78-.73l.66-9.88H7.33zM10 9.5a.75.75 0 0 1 .75.75v4.5a.75.75 0 0 1-1.5 0v-4.5A.75.75 0 0 1 10 9.5zm4 0a.75.75 0 0 1 .75.75v4.5a.75.75 0 0 1-1.5 0v-4.5A.75.75 0 0 1 14 9.5z"></path>
                      </svg>
                    </button>
                  </div>
                </td>
              </tr>
            """
        )

    return "".join(row_html)


def render_page(
    rows: list[dict[str, str]],
    timeout: str,
    result: dict[str, Any] | None,
    error: str | None,
    toast: dict[str, str] | None = None,
) -> str:
    timeout = timeout or str(DEFAULT_TIMEOUT)
    summary = summarize_rows(rows)

    result_html = render_result(result, error)
    history_html = render_history()
    toast_html = render_toast(toast)
    summary_html = render_summary_cards(summary)

    return f"""<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{esc(APP_TITLE)}</title>
  <style>
    :root {{
      --bg: #050b14;
      --bg-soft: #0b1524;
      --panel: rgba(10, 18, 31, 0.82);
      --line: rgba(170, 194, 230, 0.14);
      --text: #edf4ff;
      --muted: #9cb0cb;
      --accent: #5eead4;
      --accent-2: #f59e0b;
      --success: #34d399;
      --warning: #fbbf24;
      --danger: #fb7185;
    }}

    * {{
      box-sizing: border-box;
    }}

    body {{
      margin: 0;
      min-height: 100vh;
      color: var(--text);
      background:
        radial-gradient(circle at top left, rgba(94, 234, 212, 0.16), transparent 28%),
        radial-gradient(circle at top right, rgba(245, 158, 11, 0.16), transparent 24%),
        linear-gradient(180deg, #07111d 0%, #081523 50%, var(--bg) 100%);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}

    body::before {{
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      background-image:
        linear-gradient(rgba(255, 255, 255, 0.04) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255, 255, 255, 0.04) 1px, transparent 1px);
      background-size: 42px 42px;
      mask-image: linear-gradient(180deg, rgba(0, 0, 0, 0.5), transparent 80%);
    }}

    .container {{
      position: relative;
      z-index: 1;
      max-width: 1200px;
      margin: 0 auto;
      padding: 32px 18px 44px;
    }}

    .topbar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
      margin-bottom: 18px;
    }}

    .brand {{
      display: inline-flex;
      align-items: center;
      gap: 10px;
      padding: 8px 12px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: rgba(255, 255, 255, 0.03);
      color: #d8ecff;
      font-size: 12px;
      letter-spacing: 0.14em;
      text-transform: uppercase;
    }}

    .brand-mark {{
      width: 10px;
      height: 10px;
      border-radius: 999px;
      background: linear-gradient(135deg, var(--accent), var(--accent-2));
      box-shadow: 0 0 0 4px rgba(94, 234, 212, 0.12);
    }}

    .hero {{
      display: grid;
      grid-template-columns: 1fr;
      gap: 20px;
      align-items: stretch;
    }}

    .toast {{
      position: fixed;
      top: 20px;
      right: 20px;
      z-index: 30;
      min-width: 280px;
      max-width: 360px;
      padding: 14px 16px;
      border-radius: 16px;
      border: 1px solid rgba(255, 255, 255, 0.12);
      background: rgba(10, 18, 31, 0.96);
      box-shadow: 0 18px 42px rgba(0, 0, 0, 0.35);
      backdrop-filter: blur(16px);
      display: grid;
      gap: 4px;
      animation: toast-in 0.22s ease-out;
    }}

    .toast strong {{
      font-size: 0.92rem;
      letter-spacing: 0.02em;
    }}

    .toast span {{
      color: var(--muted);
      font-size: 0.88rem;
      line-height: 1.4;
    }}

    .toast-success {{
      border-color: rgba(52, 211, 153, 0.25);
      box-shadow: 0 18px 42px rgba(52, 211, 153, 0.12);
    }}

    .toast-danger {{
      border-color: rgba(251, 113, 133, 0.28);
      box-shadow: 0 18px 42px rgba(251, 113, 133, 0.12);
    }}

    @keyframes toast-in {{
      from {{
        opacity: 0;
        transform: translateY(-8px);
      }}
      to {{
        opacity: 1;
        transform: translateY(0);
      }}
    }}

    .card {{
      border: 1px solid var(--line);
      border-radius: 24px;
      background: var(--panel);
      box-shadow: 0 26px 70px rgba(0, 0, 0, 0.28);
      backdrop-filter: blur(18px);
    }}

    .hero-copy {{
      padding: 30px;
    }}

    .kicker {{
      display: inline-flex;
      align-items: center;
      gap: 10px;
      padding: 8px 12px;
      border-radius: 999px;
      background: rgba(94, 234, 212, 0.1);
      color: #bffdf4;
      font-size: 12px;
      letter-spacing: 0.12em;
      text-transform: uppercase;
    }}

    h1 {{
      margin: 16px 0 12px;
      max-width: 12ch;
      font-size: clamp(2.2rem, 4.6vw, 4.2rem);
      line-height: 0.98;
    }}

    .lead {{
      max-width: 60ch;
      margin: 0;
      color: var(--muted);
      line-height: 1.7;
      font-size: 1.02rem;
    }}

    .bullets {{
      display: grid;
      gap: 10px;
      margin-top: 26px;
    }}

    .bullet {{
      display: flex;
      gap: 12px;
      align-items: flex-start;
      color: #dce8f8;
      line-height: 1.5;
      font-size: 0.95rem;
    }}

    .dot {{
      width: 10px;
      height: 10px;
      margin-top: 0.35rem;
      border-radius: 999px;
      background: linear-gradient(135deg, var(--accent), var(--accent-2));
      box-shadow: 0 0 0 4px rgba(94, 234, 212, 0.12);
      flex: 0 0 auto;
    }}

    .stat-grid {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
      margin-top: 26px;
    }}

    .stat {{
      padding: 14px;
      border: 1px solid var(--line);
      border-radius: 18px;
      background: rgba(255, 255, 255, 0.03);
    }}

    .stat strong {{
      display: block;
      font-size: 1.02rem;
      margin-bottom: 4px;
    }}

    .stat span {{
      color: var(--muted);
      font-size: 0.85rem;
    }}

    .form-card {{
      padding: 24px;
    }}

    .summary-grid {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
      margin-bottom: 14px;
    }}

    .summary-card {{
      padding: 14px 16px;
      border-radius: 16px;
      border: 1px solid rgba(255, 255, 255, 0.08);
      background: rgba(255, 255, 255, 0.03);
      display: grid;
      gap: 6px;
    }}

    .summary-card span {{
      color: var(--muted);
      font-size: 0.82rem;
      letter-spacing: 0.06em;
      text-transform: uppercase;
    }}

    .summary-card strong {{
      font-size: 1.4rem;
      line-height: 1;
    }}

    .toolbar {{
      display: flex;
      justify-content: space-between;
      gap: 14px;
      align-items: center;
      margin-bottom: 14px;
      flex-wrap: wrap;
    }}

    .toolbar-left {{
      display: flex;
      gap: 12px;
      align-items: center;
      flex-wrap: wrap;
    }}

    .timeout-setting {{
      display: inline-flex;
      align-items: center;
      gap: 10px;
      color: var(--muted);
      font-size: 0.9rem;
      font-weight: 600;
    }}

    .timeout-setting span {{
      white-space: nowrap;
    }}

    .timeout-input {{
      width: 120px;
      padding: 11px 12px;
    }}

    .toolbar-right {{
      display: flex;
      gap: 10px;
      align-items: center;
      flex-wrap: wrap;
    }}

    .file-input {{
      max-width: 260px;
      padding: 11px 12px;
    }}

    .ghost-button {{
      border: 1px solid rgba(154, 176, 209, 0.2);
      background: rgba(255, 255, 255, 0.04);
      color: var(--text);
      border-radius: 12px;
      padding: 12px 14px;
      font-weight: 700;
      cursor: pointer;
    }}

    .ghost-button:hover {{
      border-color: rgba(94, 234, 212, 0.45);
    }}

    .batch-button {{
      border: 0;
      border-radius: 12px;
      padding: 12px 14px;
      font-weight: 800;
      color: #04111a;
      background: linear-gradient(135deg, #a7f3d0, var(--accent));
      cursor: pointer;
    }}

    .batch-button:hover {{
      transform: translateY(-1px);
    }}

    .filter-setting {{
      display: inline-flex;
      align-items: center;
      gap: 10px;
      color: var(--muted);
      font-size: 0.9rem;
      font-weight: 600;
    }}

    .filter-setting span {{
      white-space: nowrap;
    }}

    .filter-select {{
      min-width: 150px;
      padding: 11px 12px;
    }}

    .reset-button {{
      border: 1px solid rgba(251, 113, 133, 0.28);
      background: rgba(251, 113, 133, 0.08);
      color: #fecdd3;
      border-radius: 12px;
      padding: 12px 14px;
      font-weight: 700;
      cursor: pointer;
    }}

    .reset-button:hover {{
      background: rgba(251, 113, 133, 0.14);
    }}

    .import-button {{
      border: 0;
      border-radius: 12px;
      padding: 12px 14px;
      font-weight: 800;
      color: #04111a;
      background: linear-gradient(135deg, var(--accent), #8ef3e3 48%, var(--accent-2));
      cursor: pointer;
    }}

    .import-button:hover {{
      transform: translateY(-1px);
    }}

    .section-head {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: flex-start;
      margin-bottom: 16px;
    }}

    .section-head h2 {{
      margin: 12px 0 0;
      font-size: 1.4rem;
    }}

    .section-copy {{
      margin: 0;
      color: var(--muted);
      line-height: 1.7;
    }}

    .table-wrap {{
      overflow-x: auto;
      border-radius: 18px;
      border: 1px solid rgba(255, 255, 255, 0.08);
      background: rgba(8, 15, 26, 0.6);
    }}

    .data-table {{
      width: 100%;
      border-collapse: collapse;
      min-width: 680px;
    }}

    .data-table th {{
      text-align: left;
      font-size: 0.82rem;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--muted);
      padding: 14px 16px;
      background: rgba(255, 255, 255, 0.03);
      border-bottom: 1px solid rgba(255, 255, 255, 0.06);
    }}

    .data-table td {{
      padding: 14px 16px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.06);
      vertical-align: middle;
    }}

    .data-table tr:last-child td {{
      border-bottom: 0;
    }}

    .inline-input {{
      width: 100%;
      border: 1px solid rgba(154, 176, 209, 0.18);
      border-radius: 12px;
      background: rgba(8, 15, 26, 0.92);
      color: var(--text);
      padding: 12px 14px;
      font-size: 0.98rem;
      outline: none;
    }}

    .inline-input:focus {{
      border-color: rgba(94, 234, 212, 0.58);
      box-shadow: 0 0 0 4px rgba(94, 234, 212, 0.12);
    }}

    .test-button {{
      width: 100%;
      border: 0;
      border-radius: 12px;
      padding: 12px 16px;
      font-weight: 800;
      color: #04111a;
      background: linear-gradient(135deg, var(--accent), #8ef3e3 48%, var(--accent-2));
      box-shadow: 0 14px 30px rgba(94, 234, 212, 0.18);
      cursor: pointer;
    }}

    .test-button:hover {{
      transform: translateY(-1px);
    }}

    .helper-row {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: center;
      margin-top: 14px;
      color: var(--muted);
      font-size: 0.88rem;
      line-height: 1.5;
    }}

    .helper-row strong {{
      color: var(--text);
    }}

    .status-pill {{
      display: inline-flex;
      justify-content: center;
      align-items: center;
      min-width: 118px;
      padding: 11px 14px;
      border-radius: 12px;
      font-size: 0.8rem;
      font-weight: 800;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      border: 1px solid transparent;
    }}

    .status-pill.ok {{
      color: #a7f3d0;
      background: rgba(52, 211, 153, 0.12);
      border-color: rgba(52, 211, 153, 0.25);
    }}

    .status-pill.danger {{
      color: #fecdd3;
      background: rgba(251, 113, 133, 0.12);
      border-color: rgba(251, 113, 133, 0.25);
    }}

    .row-test-button {{
      width: 42px;
      height: 42px;
      padding: 0;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      flex: 0 0 auto;
      font-size: 0;
    }}

    .row-actions {{
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }}

    .delete-button {{
      border: 1px solid rgba(251, 113, 133, 0.28);
      background: rgba(251, 113, 133, 0.08);
      color: #fecdd3;
      border-radius: 12px;
      width: 42px;
      height: 42px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-weight: 700;
      cursor: pointer;
      flex: 0 0 auto;
    }}

    .delete-button:hover {{
      background: rgba(251, 113, 133, 0.14);
    }}

    .delete-button svg {{
      width: 18px;
      height: 18px;
      fill: currentColor;
      display: block;
    }}

    .row-test-button svg {{
      width: 18px;
      height: 18px;
      fill: currentColor;
      display: block;
    }}

    .results {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
      margin-top: 20px;
    }}

    .result-card, .history {{
      padding: 24px;
    }}

    .badge {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 8px 12px;
      border-radius: 999px;
      font-size: 0.8rem;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }}

    .badge.success {{
      background: rgba(52, 211, 153, 0.12);
      color: #a7f3d0;
    }}

    .badge.warning {{
      background: rgba(251, 191, 36, 0.12);
      color: #fde68a;
    }}

    .badge.danger {{
      background: rgba(251, 113, 133, 0.12);
      color: #fecdd3;
    }}

    .result-title {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: flex-start;
      margin-top: 14px;
    }}

    .result-title h2 {{
      margin: 0;
      font-size: 1.4rem;
    }}

    .result-title p {{
      margin: 0.45rem 0 0;
      color: var(--muted);
      line-height: 1.6;
    }}

    .metrics {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
      margin-top: 18px;
    }}

    .metric {{
      padding: 14px;
      border-radius: 16px;
      border: 1px solid var(--line);
      background: rgba(255, 255, 255, 0.03);
    }}

    .metric span {{
      display: block;
      color: var(--muted);
      font-size: 0.8rem;
      margin-bottom: 8px;
    }}

    .metric strong {{
      font-size: 1rem;
      word-break: break-word;
    }}

    .detail-list {{
      display: grid;
      gap: 10px;
      margin-top: 18px;
    }}

    .detail {{
      display: flex;
      justify-content: space-between;
      gap: 16px;
      padding: 12px 14px;
      border: 1px solid rgba(255, 255, 255, 0.06);
      border-radius: 14px;
      background: rgba(255, 255, 255, 0.03);
    }}

    .detail span {{
      color: var(--muted);
    }}

    .detail strong {{
      text-align: right;
      word-break: break-word;
    }}

    .error-box {{
      margin-top: 16px;
      padding: 14px 16px;
      border-radius: 16px;
      border: 1px solid rgba(251, 113, 133, 0.28);
      background: rgba(251, 113, 133, 0.08);
      color: #ffd7dd;
      white-space: pre-wrap;
      line-height: 1.5;
    }}

    .mini-badge {{
      display: inline-flex;
      align-items: center;
      padding: 6px 10px;
      border-radius: 999px;
      font-size: 0.78rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }}

    .mini-badge.ok {{
      background: rgba(52, 211, 153, 0.12);
      color: #a7f3d0;
    }}

    .mini-badge.danger {{
      background: rgba(251, 113, 133, 0.12);
      color: #fecdd3;
    }}

    .footer {{
      margin-top: 18px;
      color: var(--muted);
      font-size: 0.86rem;
      text-align: center;
    }}

    @media (max-width: 960px) {{
      .hero, .results {{
        grid-template-columns: 1fr;
      }}

      .summary-grid {{
        grid-template-columns: 1fr;
      }}

      .stat-grid, .metrics {{
        grid-template-columns: 1fr;
      }}

      .topbar {{
        align-items: flex-start;
        flex-direction: column;
      }}

      h1 {{
        max-width: none;
      }}
    }}
  </style>
</head>
<body>
  <div class="container">
    {toast_html}
    <div class="topbar">
      <div class="brand"><span class="brand-mark"></span>{esc(APP_TITLE)}</div>
      <div class="secondary">Browser UI for TCP, HTTP, and HTTPS checks</div>
    </div>

    <section class="card form-card">
        <div class="section-head">
          <div>
            <span class="badge success">Input</span>
            <h2>Test IP / DNS</h2>
          </div>
        </div>

      {summary_html}

      <form method="post" enctype="multipart/form-data" id="connection-form">
        <div class="toolbar">
          <div class="toolbar-left">
            <input class="inline-input file-input" type="file" name="csv_file" accept=".csv,text/csv" />
            <button class="import-button" type="submit" name="action" value="import_csv">Import CSV</button>
            <label class="timeout-setting">
              <span>Timeout (detik)</span>
              <input class="inline-input timeout-input" name="timeout" type="number" step="0.1" min="0.1" value="{esc(timeout)}" />
            </label>
          </div>
          <div class="toolbar-right">
            <label class="filter-setting">
              <span>Filter</span>
              <select class="inline-input filter-select" id="status-filter">
                <option value="all">All</option>
                <option value="connected">Connected</option>
                <option value="disconnect">Disconnect</option>
              </select>
            </label>
            <button class="batch-button" type="submit" name="action" value="test_all">Test All</button>
            <button class="ghost-button" type="button" id="add-row-button">Add Row</button>
            <button class="reset-button" type="button" id="reset-rows-button">Reset</button>
          </div>
        </div>

        <div class="table-wrap">
          <table class="data-table">
            <thead>
              <tr>
                <th>IP / DNS</th>
                <th>Port</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody id="rows-body">
              {render_rows_table(rows)}
            </tbody>
          </table>
        </div>

        <div class="helper-row">
          <span>CSV format: <strong>target,port</strong></span>
          <span>Timeout saat ini: <strong>{esc(timeout)} detik</strong></span>
        </div>
      </form>
    </section>

    <section class="results">
      {result_html}
      {history_html}
    </section>

    <div class="footer">
      Created by <a href="https://budiart.my.id" target="_blank">BudiArt</a>
    </div>
    <script>
      (() => {{
        const tbody = document.getElementById("rows-body");
        const addButton = document.getElementById("add-row-button");
        const resetButton = document.getElementById("reset-rows-button");
        const filterSelect = document.getElementById("status-filter");
        const totalEl = document.getElementById("summary-total");
        const connectedEl = document.getElementById("summary-connected");
        const disconnectEl = document.getElementById("summary-disconnect");
        const toast = document.getElementById("toast");

        if (!tbody || !addButton || !resetButton || !filterSelect || !totalEl || !connectedEl || !disconnectEl) {{
          if (toast) {{
            window.setTimeout(() => {{
              toast.remove();
            }}, 5000);
          }}
          return;
        }}

        function buildRow(index) {{
          const tr = document.createElement("tr");
          tr.dataset.status = "disconnect";
          tr.innerHTML = `
            <td>
              <input
                class="inline-input"
                name="target"
                type="text"
                value=""
                placeholder="192.168.1.10 or example.local"
              />
            </td>
            <td>
              <input
                class="inline-input"
                name="port"
                type="number"
                value=""
                placeholder="80"
              />
            </td>
            <td>
              <span class="status-pill danger">Disconnect</span>
              <input type="hidden" name="status" value="disconnect" />
            </td>
            <td>
              <div class="row-actions">
                <button class="test-button row-test-button" type="submit" name="action" value="test:${{index}}" aria-label="Run test" title="Run test">
                  <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                    <path d="M8.5 5.5v13l10-6.5-10-6.5z"></path>
                  </svg>
                </button>
                <button class="delete-button row-delete-button" type="button" aria-label="Delete row" title="Delete row">
                  <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                    <path d="M9 3.75h6a1.25 1.25 0 0 1 1.25 1.25V6h3a.75.75 0 0 1 0 1.5h-1.06l-.7 10.02A2.25 2.25 0 0 1 15.25 19.5h-6.5a2.25 2.25 0 0 1-2.24-2.02L5.82 7.5H4.75a.75.75 0 0 1 0-1.5h3V5A1.25 1.25 0 0 1 9 3.75zm0 1.5V6h6V5.25H9zm-1.67 2.25.66 9.88c.03.41.37.73.78.73h6.48c.41 0 .75-.32.78-.73l.66-9.88H7.33zM10 9.5a.75.75 0 0 1 .75.75v4.5a.75.75 0 0 1-1.5 0v-4.5A.75.75 0 0 1 10 9.5zm4 0a.75.75 0 0 1 .75.75v4.5a.75.75 0 0 1-1.5 0v-4.5A.75.75 0 0 1 14 9.5z"></path>
                  </svg>
                </button>
              </div>
            </td>
          `;
          return tr;
        }}

        function isMeaningfulRow(row) {{
          const targetInput = row.querySelector('input[name="target"]');
          const portInput = row.querySelector('input[name="port"]');
          const target = targetInput ? targetInput.value.trim() : "";
          const port = portInput ? portInput.value.trim() : "";
          return Boolean(target || port);
        }}

        function refreshSummary() {{
          let total = 0;
          let connected = 0;
          let disconnect = 0;

          tbody.querySelectorAll("tr").forEach((row) => {{
            if (!isMeaningfulRow(row)) {{
              return;
            }}
            total += 1;
            if ((row.dataset.status || "disconnect") === "connected") {{
              connected += 1;
            }} else {{
              disconnect += 1;
            }}
          }});

          totalEl.textContent = String(total);
          connectedEl.textContent = String(connected);
          disconnectEl.textContent = String(disconnect);
        }}

        function applyFilter() {{
          const mode = filterSelect.value;
          tbody.querySelectorAll("tr").forEach((row) => {{
            const status = row.dataset.status || "disconnect";
            const show = mode === "all" || status === mode;
            row.style.display = show ? "" : "none";
          }});
        }}

        function reindexRows() {{
          const rows = tbody.querySelectorAll("tr");
          rows.forEach((row, index) => {{
            const testButton = row.querySelector(".row-test-button");
            if (testButton) {{
              testButton.value = `test:${{index}}`;
            }}
          }});
        }}

        function ensureRowExists() {{
          if (!tbody.querySelector("tr")) {{
            tbody.appendChild(buildRow(0));
          }}
          reindexRows();
          refreshSummary();
          applyFilter();
        }}

        addButton.addEventListener("click", () => {{
          tbody.appendChild(buildRow(tbody.children.length));
          reindexRows();
          refreshSummary();
          applyFilter();
        }});

        resetButton.addEventListener("click", () => {{
          tbody.innerHTML = "";
          tbody.appendChild(buildRow(0));
          reindexRows();
          refreshSummary();
          applyFilter();
        }});

        filterSelect.addEventListener("change", () => {{
          applyFilter();
        }});

        tbody.addEventListener("click", (event) => {{
          const deleteButton = event.target.closest(".row-delete-button");
          if (!deleteButton) {{
            return;
          }}

          const row = deleteButton.closest("tr");
          if (row) {{
            row.remove();
            ensureRowExists();
          }}
        }});

        tbody.addEventListener("input", () => {{
          refreshSummary();
          applyFilter();
        }});

        reindexRows();
        refreshSummary();
        applyFilter();

        if (toast) {{
          window.setTimeout(() => {{
            toast.remove();
          }}, 5000);
        }}
      }})();
    </script>
  </div>
</body>
</html>
"""


def response(start_response: Any, status: str, content_type: str, body: str) -> list[bytes]:
    headers = [
        ("Content-Type", content_type),
        ("Content-Length", str(len(body.encode("utf-8")))),
        ("Cache-Control", "no-store"),
    ]
    start_response(status, headers)
    return [body.encode("utf-8")]


def application(environ: dict[str, Any], start_response: Any) -> list[bytes]:
    path = environ.get("PATH_INFO", "/")
    method = environ.get("REQUEST_METHOD", "GET").upper()

    if path == "/health":
        return response(start_response, "200 OK", "text/plain; charset=utf-8", "ok\n")

    if path != "/":
        return response(start_response, "404 Not Found", "text/plain; charset=utf-8", "Not found\n")

    if method == "POST":
        try:
            fields, files = read_form(environ)
            action = first_value(fields, "action")
            rows = parse_rows(fields)
            timeout_value = first_value(fields, "timeout", str(DEFAULT_TIMEOUT))
            result: dict[str, Any] | None = None
            error: str | None = None
            toast: dict[str, str] | None = None

            if action == "import_csv":
                csv_upload = first_file(files, "csv_file")
                if csv_upload is not None and getattr(csv_upload, "file", None) is not None:
                    raw_content = csv_upload.file.read()
                    if isinstance(raw_content, bytes):
                        raw_text = raw_content.decode("utf-8-sig", errors="replace")
                    else:
                        raw_text = str(raw_content)
                    try:
                        imported_rows = parse_csv_rows(raw_text)
                        has_manual_rows = any((row.get("target") or row.get("port")) for row in rows)
                        rows = rows + imported_rows if has_manual_rows else imported_rows
                    except ValueError as exc:
                        error = str(exc)
                else:
                    error = "Silakan pilih file CSV dengan format `target,port`."
            elif action == "test_all":
                try:
                    rows, result, batch_error = run_batch_checks(rows, timeout_value)
                    error = None
                    message = result["summary"]
                    if batch_error:
                        message = f"{result['summary']} {batch_error}"
                    toast_title = "Connected" if result["status"] == "connected" else "Partial" if result["status"] == "partial" else "Disconnect"
                    toast = {
                        "kind": "success" if result["disconnect"] == 0 else "danger",
                        "title": toast_title,
                        "message": message,
                    }
                except ValueError as exc:
                    error = str(exc)
                    toast = {"kind": "danger", "title": "Error", "message": error}
            elif action.startswith("test:"):
                try:
                    row_index = int(action.split(":", 1)[1])
                except ValueError:
                    row_index = -1

                if not 0 <= row_index < len(rows):
                    error = "Baris yang dipilih tidak ditemukan."
                    toast = {"kind": "danger", "title": "Disconnect", "message": error}
                else:
                    selected = rows[row_index]
                    result, error = run_single_check(selected.get("target", ""), selected.get("port", ""), timeout_value)
                    if result:
                        rows[row_index]["status"] = result["status"]
                        toast_title = "Connected" if result["status"] == "connected" else "Disconnect"
                        toast_kind = "success" if result["status"] == "connected" else "danger"
                        toast_message = f"{result.get('host', '-')}:{result.get('port', '-')} berhasil terhubung."
                        if result.get("error") == "timeout":
                            toast_message = f"{result.get('host', '-')}:{result.get('port', '-')} timeout setelah {result.get('timeout', DEFAULT_TIMEOUT):.1f} detik."
                        elif result["status"] != "connected":
                            toast_message = f"{result.get('host', '-')}:{result.get('port', '-')} tidak terhubung."
                        toast = {"kind": toast_kind, "title": toast_title, "message": toast_message}
                        if result["status"] == "connected":
                            clamp_recent_tests(
                                {
                                    "target": f"{result['host']}:{result['port']}",
                                    "protocol": result["protocol"],
                                    "status": result["status"],
                                    "elapsed_ms": result["total_ms"],
                                    "checked_at": result["checked_at"],
                                }
                            )
                    else:
                        rows[row_index]["status"] = "disconnect"
                        toast = {"kind": "danger", "title": "Disconnect", "message": error or "Koneksi gagal."}

            page = render_page(rows, timeout_value, result, error, toast)
            return response(start_response, "200 OK", "text/html; charset=utf-8", page)
        except Exception as exc:
            traceback.print_exc()
            page = render_page(
                [{"target": "", "port": "", "status": "disconnect"}],
                str(DEFAULT_TIMEOUT),
                None,
                f"Terjadi error saat memproses request: {exc}",
                {"kind": "danger", "title": "Error", "message": f"Terjadi error saat memproses request: {exc}"},
            )
            return response(start_response, "200 OK", "text/html; charset=utf-8", page)

    page = render_page([{"target": "", "port": "", "status": "disconnect"}], str(DEFAULT_TIMEOUT), None, None, None)
    return response(start_response, "200 OK", "text/html; charset=utf-8", page)


def main() -> None:
    host = os.environ.get("HOST", "0.0.0.0")
    try:
        port = int(os.environ.get("PORT", "8000"))
    except ValueError:
        port = 8000

    with make_server(host, port, application, server_class=ThreadingWSGIServer, handler_class=WSGIRequestHandler) as httpd:
        print(f"Serving on http://{host}:{port}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down...")


if __name__ == "__main__":
    main()
