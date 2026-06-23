"""
PacketDesk - Windows executable-ready Python network diagnostics app.

Features:
- Tabbed monitoring with one target per tab
- Overview tab with summary of all target tabs
- Periodic ping sets against every traceroute hop
- Automatic traceroute before first ping and optionally every N ping sets
- Hop table with loss, min/max/current/average latency, jitter, samples
- PingPlotter-like per-hop latency distribution plot
- Bottom timeline chart with latency line and red packet-loss spikes

Build into a Windows EXE with build_windows.bat.
"""

from __future__ import annotations

import collections
import concurrent.futures
import csv
import dataclasses
import html
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
from typing import Deque, Dict, List, Optional, Tuple
from urllib.parse import urlparse

try:
    from PySide6 import QtCore, QtGui, QtWidgets
    import pyqtgraph as pg
except Exception as exc:  # pragma: no cover - only used for friendly startup failures
    print("Missing dependency:", exc)
    print("Install with: pip install -r requirements.txt")
    raise


APP_NAME = "PacketDesk"
MAX_HISTORY_PER_HOP = 5000
PING_TIMEOUT_MS = 1500
TRACEROUTE_TIMEOUT_MS = 1500
MAX_HOPS = 30
RDNS_TIMEOUT_SECONDS = 0.4
RDNS_SUCCESS_TTL_SECONDS = 3600.0
RDNS_FAILURE_TTL_SECONDS = 120.0
RDNS_MAX_WORKERS = 8
TARGET_HISTORY_LIMIT = 15
LOG_DIR_NAME = "logs"
TARGET_HISTORY_FILE = "target_history.json"
COMMON_TARGETS = [
    "8.8.8.8",
    "1.1.1.1",
    "9.9.9.9",
    "208.67.222.222",
    "google.com",
    "cloudflare.com",
]

def _resource_path(*parts: str) -> str:
    base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, *parts)


def _app_data_dir() -> str:
    # Store/MSIX installs are read-only under WindowsApps, so runtime files must go to user-writable storage.
    candidates = [
        QtCore.QStandardPaths.writableLocation(QtCore.QStandardPaths.AppDataLocation),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), APP_NAME),
        os.path.join(os.path.expanduser("~"), f".{APP_NAME.lower()}"),
    ]
    for path in candidates:
        if not path:
            continue
        try:
            os.makedirs(path, exist_ok=True)
            return path
        except Exception:
            continue
    fallback = os.path.join(tempfile.gettempdir(), APP_NAME)
    os.makedirs(fallback, exist_ok=True)
    return fallback


class ReverseDNSResolver:
    def __init__(self) -> None:
        self._cache: Dict[str, Tuple[str, float]] = {}
        self._lock = threading.Lock()
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=RDNS_MAX_WORKERS)

    def _get_cached(self, ip: str) -> Optional[str]:
        now = time.time()
        with self._lock:
            cached = self._cache.get(ip)
            if cached and cached[1] > now:
                return cached[0]
        return None

    def _set_cache(self, ip: str, name: str, success: bool) -> None:
        ttl = RDNS_SUCCESS_TTL_SECONDS if success else RDNS_FAILURE_TTL_SECONDS
        with self._lock:
            self._cache[ip] = (name, time.time() + ttl)

    def resolve_many(self, ips: List[str]) -> Dict[str, str]:
        results: Dict[str, str] = {}
        to_lookup: List[str] = []

        for ip in ips:
            cached = self._get_cached(ip)
            if cached is not None:
                results[ip] = cached
            else:
                to_lookup.append(ip)

        if not to_lookup:
            return results

        futures = {self._executor.submit(socket.gethostbyaddr, ip): ip for ip in to_lookup}
        done, not_done = concurrent.futures.wait(futures.keys(), timeout=RDNS_TIMEOUT_SECONDS)

        for future in done:
            ip = futures[future]
            try:
                host, _aliases, _addrs = future.result()
                name = host or ip
                success = name != ip
            except Exception:
                name = ip
                success = False
            results[ip] = name
            self._set_cache(ip, name, success)

        for future in not_done:
            ip = futures[future]
            future.cancel()
            results[ip] = ip
            self._set_cache(ip, ip, False)

        return results


RDNS_RESOLVER = ReverseDNSResolver()


class RunCsvLogger:
    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(self.file_path, "w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(
                [
                    "timestamp",
                    "target",
                    "set_number",
                    "hop",
                    "ip",
                    "name",
                    "latency_ms",
                    "lost",
                    "sent",
                    "received",
                    "loss_percent",
                    "avg_ms",
                    "min_ms",
                    "max_ms",
                    "jitter_ms",
                ]
            )

    def write_set(self, target: str, set_number: int, rows: List[Dict[str, object]], timestamp: float) -> None:
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
        out_rows = []
        for row in rows:
            latency = row.get("last_ms")
            out_rows.append(
                [
                    stamp,
                    target,
                    set_number,
                    int(row.get("hop", 0)),
                    str(row.get("ip", "")),
                    str(row.get("name", "")),
                    "" if latency is None else float(latency),
                    1 if latency is None else 0,
                    int(row.get("sent", 0)),
                    int(row.get("received", 0)),
                    float(row.get("loss_percent", 0.0)),
                    "" if row.get("avg_ms") is None else float(row.get("avg_ms", 0.0)),
                    "" if row.get("min_ms") is None else float(row.get("min_ms", 0.0)),
                    "" if row.get("max_ms") is None else float(row.get("max_ms", 0.0)),
                    "" if row.get("jitter_ms") is None else float(row.get("jitter_ms", 0.0)),
                ]
            )

        with self._lock:
            with open(self.file_path, "a", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)
                writer.writerows(out_rows)


# ----------------------------- data model -----------------------------


@dataclasses.dataclass
class HopStats:
    hop: int
    ip: str
    name: str = ""
    sent: int = 0
    received: int = 0
    last_ms: Optional[float] = None
    min_ms: Optional[float] = None
    max_ms: Optional[float] = None
    total_ms: float = 0.0
    last_received_ms: Optional[float] = None
    jitter_total: float = 0.0
    jitter_samples: int = 0

    def add_sample(self, latency_ms: Optional[float]) -> None:
        self.sent += 1
        self.last_ms = latency_ms
        if latency_ms is None:
            return

        self.received += 1
        self.total_ms += latency_ms
        self.min_ms = latency_ms if self.min_ms is None else min(self.min_ms, latency_ms)
        self.max_ms = latency_ms if self.max_ms is None else max(self.max_ms, latency_ms)

        if self.last_received_ms is not None:
            self.jitter_total += abs(latency_ms - self.last_received_ms)
            self.jitter_samples += 1
        self.last_received_ms = latency_ms

    @property
    def loss_percent(self) -> float:
        if self.sent <= 0:
            return 0.0
        return ((self.sent - self.received) / self.sent) * 100.0

    @property
    def avg_ms(self) -> Optional[float]:
        if self.received <= 0:
            return None
        return self.total_ms / self.received

    @property
    def jitter_ms(self) -> Optional[float]:
        if self.jitter_samples <= 0:
            return None
        return self.jitter_total / self.jitter_samples

    def as_row(self) -> Dict[str, object]:
        return {
            "hop": self.hop,
            "ip": self.ip,
            "name": self.name or self.ip,
            "sent": self.sent,
            "received": self.received,
            "samples": self.sent,
            "loss_percent": self.loss_percent,
            "last_ms": self.last_ms,
            "min_ms": self.min_ms,
            "avg_ms": self.avg_ms,
            "max_ms": self.max_ms,
            "jitter_ms": self.jitter_ms,
        }


@dataclasses.dataclass
class HopSample:
    set_number: int
    timestamp: float
    latency_ms: Optional[float]


# ----------------------------- target helpers -----------------------------


def normalize_target(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("Enter a target host or IP address.")

    if "://" in value:
        parsed = urlparse(value)
        value = parsed.hostname or value
    else:
        value = value.split("/")[0]

    value = value.strip("[] ")
    if not value:
        raise ValueError("Enter a target host or IP address.")

    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass

    if len(value) > 253 or not re.match(r"^[A-Za-z0-9._-]+$", value):
        raise ValueError("Target must be a hostname, domain, or IP address.")
    return value


def fmt_ms(value: Optional[float]) -> str:
    if value is None:
        return "—"
    if value < 1:
        return "<1"
    return f"{value:.0f}"


def fmt_percent(value: float) -> str:
    return f"{value:.1f}%"


# ----------------------------- platform commands -----------------------------


_TIME_PATTERNS = [
    re.compile(r"time[=<]\s*(\d+(?:\.\d+)?)\s*ms", re.I),
    re.compile(r"Average\s*=\s*(\d+)ms", re.I),
]


def ping_once(host: str, timeout_ms: int = PING_TIMEOUT_MS) -> Optional[float]:
    system = platform.system().lower()
    if "windows" in system:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host]
    elif "darwin" in system:
        cmd = ["ping", "-c", "1", "-W", str(timeout_ms), host]
    else:
        timeout_seconds = max(1, int(round(timeout_ms / 1000)))
        cmd = ["ping", "-c", "1", "-W", str(timeout_seconds), host]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(2.0, timeout_ms / 1000.0 + 1.5),
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )
    except Exception:
        return None

    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    if "timed out" in output.lower() or "100% loss" in output.lower() or "unreachable" in output.lower():
        return None

    for pattern in _TIME_PATTERNS:
        match = pattern.search(output)
        if match:
            try:
                return float(match.group(1))
            except ValueError:
                return None
    return None


def _parse_tracert_line(line: str) -> Optional[Tuple[int, str, str]]:
    stripped = line.strip()
    if not stripped:
        return None

    match = re.match(r"^(\d+)\s+(.+)$", stripped)
    if not match:
        return None
    hop = int(match.group(1))
    rest = match.group(2)

    if "Request timed out" in rest:
        return hop, "*", "Request timed out"

    bracket_ip = re.search(r"\[([0-9A-Fa-f:.]+)\]", rest)
    if bracket_ip:
        ip = bracket_ip.group(1)
        name_part = rest[: bracket_ip.start()].strip()
        name_part = re.sub(r"(?:<\d+|\d+)\s*ms", " ", name_part, flags=re.I).strip()
        name = name_part.split()[-1] if name_part.split() else ip
        return hop, ip, name

    tokens = rest.split()
    for token in reversed(tokens):
        candidate = token.strip("[]")
        try:
            ipaddress.ip_address(candidate)
            return hop, candidate, candidate
        except ValueError:
            continue

    paren_ip = re.search(r"\(([0-9A-Fa-f:.]+)\)", rest)
    if paren_ip:
        ip = paren_ip.group(1)
        name = rest[: paren_ip.start()].strip().split()[-1] if rest[: paren_ip.start()].strip() else ip
        return hop, ip, name

    return None


def traceroute(target: str, max_hops: int = MAX_HOPS, timeout_ms: int = TRACEROUTE_TIMEOUT_MS) -> List[Tuple[int, str, str]]:
    system = platform.system().lower()
    commands: List[List[str]] = []
    if "windows" in system:
        commands.append(["tracert", "-d", "-h", str(max_hops), "-w", str(timeout_ms), target])
    else:
        commands.append(["traceroute", "-n", "-m", str(max_hops), "-w", str(max(1, int(timeout_ms / 1000))), target])
        commands.append(["tracepath", "-n", target])

    for cmd in commands:
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=max(10.0, max_hops * (timeout_ms / 1000.0) * 0.75),
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
            output = (proc.stdout or "") + "\n" + (proc.stderr or "")
            hops: List[Tuple[int, str, str]] = []
            seen_hops = set()
            for line in output.splitlines():
                parsed = _parse_tracert_line(line)
                if not parsed:
                    continue
                hop, ip, name = parsed
                if hop in seen_hops:
                    continue
                seen_hops.add(hop)
                hops.append((hop, ip, name))
            if hops:
                return hops
        except Exception:
            continue

    try:
        resolved = socket.gethostbyname(target)
    except Exception:
        resolved = target
    return [(1, resolved, target if resolved != target else resolved)]


# ----------------------------- worker thread -----------------------------


class MonitorWorker(QtCore.QObject):
    status = QtCore.Signal(str)
    trace_changed = QtCore.Signal(list)
    stats_changed = QtCore.Signal(list, dict)
    set_completed = QtCore.Signal(int, float)
    finished = QtCore.Signal()
    error = QtCore.Signal(str)

    def __init__(
        self,
        target: str,
        interval_seconds: float,
        retrace_every_sets: int,
        resolve_names: bool = True,
        log_file_path: Optional[str] = None,
    ) -> None:
        super().__init__()
        self.target = target
        self.interval_seconds = interval_seconds
        self.retrace_every_sets = retrace_every_sets
        self.resolve_names = resolve_names
        self._logger = RunCsvLogger(log_file_path) if log_file_path else None
        self._stop = threading.Event()
        self._set_number = 0
        self._hop_stats: Dict[int, HopStats] = {}
        self._history: Dict[int, Deque[HopSample]] = collections.defaultdict(lambda: collections.deque(maxlen=MAX_HISTORY_PER_HOP))
        self._current_hops: List[Tuple[int, str, str]] = []

    @QtCore.Slot()
    def run(self) -> None:
        try:
            self.status.emit(f"Resolving {self.target}...")
            trace = traceroute(self.target, max_hops=MAX_HOPS, timeout_ms=TRACEROUTE_TIMEOUT_MS)
            self._current_hops = [(hop, ip, name) for hop, ip, name in trace]
            trace_payload = [{"hop": hop, "ip": ip, "name": name} for hop, ip, name in trace]
            self.trace_changed.emit(trace_payload)

            for hop, ip, name in trace:
                self._hop_stats[hop] = HopStats(hop=hop, ip=ip, name=name)

            while not self._stop.is_set():
                self._set_number += 1
                timestamp = time.time()
                rows: List[Dict[str, object]] = []

                if self._set_number == 1 or (self.retrace_every_sets > 0 and self._set_number % self.retrace_every_sets == 0):
                    refreshed = traceroute(self.target, max_hops=MAX_HOPS, timeout_ms=TRACEROUTE_TIMEOUT_MS)
                    if refreshed:
                        self._current_hops = [(hop, ip, name) for hop, ip, name in refreshed]
                        self.trace_changed.emit([{"hop": hop, "ip": ip, "name": name} for hop, ip, name in refreshed])

                for hop, ip, name in self._current_hops:
                    latency_ms = None if ip == "*" else ping_once(ip, timeout_ms=PING_TIMEOUT_MS)
                    stats = self._hop_stats.setdefault(hop, HopStats(hop=hop, ip=ip, name=name))
                    stats.ip = ip
                    stats.name = name
                    stats.add_sample(latency_ms)
                    self._history[hop].append(HopSample(set_number=self._set_number, timestamp=timestamp, latency_ms=latency_ms))

                    rows.append(stats.as_row())

                histories = {
                    hop: [dataclasses.asdict(sample) for sample in samples]
                    for hop, samples in self._history.items()
                }

                ordered_rows = [row for row in rows if int(row["hop"]) in {hop for hop, _, _ in self._current_hops}]
                ordered_rows.sort(key=lambda row: int(row["hop"]))
                if self._logger is not None and ordered_rows:
                    self._logger.write_set(self.target, self._set_number, ordered_rows, timestamp)
                self.stats_changed.emit(ordered_rows, histories)
                self.set_completed.emit(self._set_number, timestamp)

                if self._stop.wait(self.interval_seconds):
                    break

            self.status.emit("Stopping...")
        except Exception as exc:
            self.error.emit(str(exc))
        finally:
            self.finished.emit()

    def stop(self) -> None:
        self._stop.set()


class HopTable(QtWidgets.QTableWidget):
    selected_hop_changed = QtCore.Signal(int)

    HEADERS = [
        "Hop",
        "IP",
        "Name",
        "Cur",
        "Avg",
        "Min",
        "Max",
        "Jitter",
        "Loss",
        "Sent",
        "Recv",
    ]

    def __init__(self) -> None:
        super().__init__(0, len(self.HEADERS))
        self.setHorizontalHeaderLabels(self.HEADERS)
        self.verticalHeader().setVisible(False)
        self.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.setAlternatingRowColors(True)
        self.horizontalHeader().setStretchLastSection(False)
        self.horizontalHeader().setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
        self.horizontalHeader().setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)
        self.horizontalHeader().setSectionResizeMode(2, QtWidgets.QHeaderView.Stretch)
        for col in range(3, len(self.HEADERS)):
            self.horizontalHeader().setSectionResizeMode(col, QtWidgets.QHeaderView.ResizeToContents)
        self.itemSelectionChanged.connect(self._selection_changed)

    def update_rows(self, rows: List[Dict[str, object]]) -> None:
        selected = self.current_hop()
        self.setRowCount(len(rows))
        for row_idx, row in enumerate(rows):
            values = [
                str(row["hop"]),
                str(row["ip"]),
                str(row["name"]),
                fmt_ms(row.get("last_ms")),
                fmt_ms(row.get("avg_ms")),
                fmt_ms(row.get("min_ms")),
                fmt_ms(row.get("max_ms")),
                fmt_ms(row.get("jitter_ms")),
                fmt_percent(float(row.get("loss_percent", 0.0))),
                str(row.get("sent", 0)),
                str(row.get("received", 0)),
            ]
            for col, value in enumerate(values):
                item = QtWidgets.QTableWidgetItem(value)
                item.setToolTip(value)
                if col == 0:
                    item.setData(QtCore.Qt.UserRole, int(row["hop"]))
                if col >= 3:
                    item.setTextAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
                if col == 8 and float(row.get("loss_percent", 0.0)) >= 25.0:
                    item.setBackground(QtGui.QColor(100, 20, 20))
                    item.setForeground(QtGui.QColor(255, 200, 200))
                self.setItem(row_idx, col, item)

        if selected is not None:
            for row_idx in range(self.rowCount()):
                item = self.item(row_idx, 0)
                if item and item.data(QtCore.Qt.UserRole) == selected:
                    self.selectRow(row_idx)
                    break
        elif self.rowCount() > 0 and self.currentRow() < 0:
            self.selectRow(self.rowCount() - 1)

    def current_hop(self) -> Optional[int]:
        row = self.currentRow()
        if row < 0:
            return None
        item = self.item(row, 0)
        if not item:
            return None
        return int(item.data(QtCore.Qt.UserRole))

    def _selection_changed(self) -> None:
        hop = self.current_hop()
        if hop is not None:
            self.selected_hop_changed.emit(hop)


# ----------------------------- plots -----------------------------


class PathPlot(pg.PlotWidget):
    def __init__(self) -> None:
        super().__init__()
        self.setBackground("#040704")
        self.showGrid(x=True, y=True, alpha=0.2)
        self.setLabel("bottom", "Latency", units="ms", color="#66ff66")
        self.setLabel("left", "Hop", color="#66ff66")
        self.getPlotItem().invertY(True)
        for axis_name in ("left", "bottom"):
            axis = self.getAxis(axis_name)
            axis.setPen(pg.mkPen(QtGui.QColor(30, 120, 30), width=1))
            axis.setTextPen(pg.mkPen(QtGui.QColor(102, 255, 102), width=1))
        self._items: List[pg.GraphicsObject] = []
        self._bands: List[pg.GraphicsObject] = []
        self._init_bands()

    def _init_bands(self) -> None:
        plot = self.getPlotItem()
        for item in self._bands:
            plot.removeItem(item)
        self._bands.clear()
        bands = [
            (0, 200, QtGui.QColor(20, 70, 20, 110)),
            (200, 500, QtGui.QColor(60, 55, 10, 110)),
            (500, 2000, QtGui.QColor(90, 20, 20, 110)),
        ]
        for x, width, color in bands:
            rect = QtWidgets.QGraphicsRectItem(x, -1000, width, 3000)
            rect.setBrush(QtGui.QBrush(color))
            rect.setPen(QtGui.QPen(QtCore.Qt.NoPen))
            rect.setZValue(-100)
            plot.addItem(rect)
            self._bands.append(rect)

    def clear_dynamic(self) -> None:
        for item in self._items:
            self.getPlotItem().removeItem(item)
        self._items.clear()

    def update_rows(self, rows: List[Dict[str, object]]) -> None:
        self.clear_dynamic()
        if not rows:
            return

        max_x = 100.0
        hops: List[int] = []
        for row in rows:
            hop = int(row["hop"])
            hops.append(hop)
            loss = float(row.get("loss_percent", 0.0))
            min_ms = row.get("min_ms")
            max_ms = row.get("max_ms")
            avg_ms = row.get("avg_ms")
            last_ms = row.get("last_ms")
            if max_ms is not None:
                max_x = max(max_x, float(max_ms) * 1.25)

            if loss >= 100.0 and int(row.get("sent", 0)) > 0:
                loss_rect = QtWidgets.QGraphicsRectItem(0, hop - 0.42, max_x, 0.84)
                loss_rect.setBrush(QtGui.QBrush(QtGui.QColor(210, 40, 40, 120)))
                loss_rect.setPen(QtGui.QPen(QtCore.Qt.NoPen))
                loss_rect.setZValue(-10)
                self.getPlotItem().addItem(loss_rect)
                self._items.append(loss_rect)

            if min_ms is not None and max_ms is not None:
                line = pg.PlotDataItem(
                    [float(min_ms), float(max_ms)],
                    [hop, hop],
                    pen=pg.mkPen(QtGui.QColor(85, 180, 85), width=1),
                )
                self.addItem(line)
                self._items.append(line)

            if avg_ms is not None:
                avg = pg.ScatterPlotItem(
                    [float(avg_ms)],
                    [hop],
                    symbol="o",
                    size=8,
                    brush=pg.mkBrush(QtGui.QColor(110, 255, 110)),
                    pen=pg.mkPen(QtGui.QColor(30, 120, 30)),
                )
                self.addItem(avg)
                self._items.append(avg)

            if last_ms is not None:
                cur = pg.ScatterPlotItem(
                    [float(last_ms)],
                    [hop],
                    symbol="x",
                    size=9,
                    pen=pg.mkPen(QtGui.QColor(150, 255, 150), width=2),
                )
                self.addItem(cur)
                self._items.append(cur)

        self.setYRange(min(hops) - 0.75, max(hops) + 0.75, padding=0)
        self.setXRange(0, max(200.0, min(max_x, 2000.0)), padding=0.02)


class TimelinePlot(pg.PlotWidget):
    def __init__(self) -> None:
        super().__init__()
        self.setBackground("#040704")
        self.showGrid(x=True, y=True, alpha=0.2)
        self.setLabel("bottom", "Ping set", color="#66ff66")
        self.setLabel("left", "Latency", units="ms", color="#66ff66")
        for axis_name in ("left", "bottom"):
            axis = self.getAxis(axis_name)
            axis.setPen(pg.mkPen(QtGui.QColor(30, 120, 30), width=1))
            axis.setTextPen(pg.mkPen(QtGui.QColor(102, 255, 102), width=1))
        self._latency_item = pg.PlotDataItem([], [], pen=pg.mkPen(QtGui.QColor(95, 235, 95), width=1.4))
        self._avg_item = pg.PlotDataItem([], [], pen=pg.mkPen(QtGui.QColor(180, 255, 180), width=2.2))
        self._points_item = pg.ScatterPlotItem([], [], symbol="o", size=4, brush=pg.mkBrush(QtGui.QColor(120, 255, 120)))
        self._loss_item: Optional[pg.BarGraphItem] = None
        self.addItem(self._latency_item)
        self.addItem(self._avg_item)
        self.addItem(self._points_item)

    def set_selected_hop(self, hop: Optional[int]) -> None:
        if hop is None:
            self.setTitle("Final target timeline", color="#66ff66")
        else:
            self.setTitle(
                f"Final target hop {hop}: bright line is running average, red bars are packet loss",
                color="#66ff66",
            )

    def update_history(self, samples: List[Dict[str, object]]) -> None:
        if self._loss_item is not None:
            self.removeItem(self._loss_item)
            self._loss_item = None

        if not samples:
            self._latency_item.setData([], [])
            self._avg_item.setData([], [])
            self._points_item.setData([], [])
            return

        xs_latency: List[int] = []
        ys_latency: List[float] = []
        xs_avg: List[int] = []
        ys_avg: List[float] = []
        xs_loss: List[int] = []
        running_total = 0.0
        running_count = 0
        for sample in samples:
            set_number = int(sample["set_number"])
            latency = sample.get("latency_ms")
            if latency is None:
                xs_loss.append(set_number)
            else:
                latency_value = float(latency)
                xs_latency.append(set_number)
                ys_latency.append(latency_value)
                running_total += latency_value
                running_count += 1
                xs_avg.append(set_number)
                ys_avg.append(running_total / running_count)

        self._latency_item.setData(xs_latency, ys_latency)
        self._avg_item.setData(xs_avg, ys_avg)
        self._points_item.setData(xs_latency, ys_latency)

        max_latency = max(ys_latency) if ys_latency else 100.0
        y_spike = max(20.0, max_latency * 1.15)
        if xs_loss:
            self._loss_item = pg.BarGraphItem(
                x=xs_loss,
                height=[y_spike] * len(xs_loss),
                width=0.8,
                brush=pg.mkBrush(QtGui.QColor(235, 30, 30, 140)),
                pen=pg.mkPen(QtGui.QColor(235, 30, 30, 180)),
            )
            self.addItem(self._loss_item)

        min_x = max(1, int(samples[-1]["set_number"]) - 250)
        max_x = int(samples[-1]["set_number"]) + 3
        self.setXRange(min_x, max_x, padding=0)
        self.setYRange(0, max(50.0, y_spike * 1.1), padding=0.02)


# ----------------------------- tabs -----------------------------


class TargetTab(QtWidgets.QWidget):
    status_changed = QtCore.Signal(str)
    snapshot_changed = QtCore.Signal(dict)
    target_committed = QtCore.Signal(str)

    def __init__(self, tab_name: str, target_choices: List[str]) -> None:
        super().__init__()
        self.tab_name = tab_name
        self._target_choices = target_choices[:]
        self._worker_thread: Optional[QtCore.QThread] = None
        self._worker: Optional[MonitorWorker] = None
        self._rows: List[Dict[str, object]] = []
        self._selected_hop: Optional[int] = None
        self._timeline_hop: Optional[int] = None
        self._target_timeline_samples: List[Dict[str, object]] = []
        self._last_status = "Idle"
        self._last_target = ""
        self._last_log_path = ""

        self._build_ui()

    def _build_ui(self) -> None:
        root = QtWidgets.QVBoxLayout(self)
        root.setContentsMargins(6, 6, 6, 6)
        root.setSpacing(6)

        controls = QtWidgets.QHBoxLayout()
        controls.setSpacing(8)

        controls.addWidget(QtWidgets.QLabel("Target:"))
        self.target_combo = QtWidgets.QComboBox()
        self.target_combo.setEditable(True)
        self.target_combo.setMinimumWidth(260)
        self.update_target_choices(self._target_choices)
        if self.target_combo.lineEdit() is not None:
            self.target_combo.lineEdit().setPlaceholderText("example.com or 8.8.8.8")
            self.target_combo.lineEdit().returnPressed.connect(self.start_monitoring)
            self.target_combo.lineEdit().textChanged.connect(self._target_text_changed)
        controls.addWidget(self.target_combo)

        self.start_button = QtWidgets.QPushButton("Go")
        self.start_button.clicked.connect(self.start_monitoring)
        controls.addWidget(self.start_button)

        self.stop_button = QtWidgets.QPushButton("Stop")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_monitoring)
        controls.addWidget(self.stop_button)

        controls.addWidget(QtWidgets.QLabel("Ping every:"))
        self.interval_combo = QtWidgets.QComboBox()
        for label, seconds in [("1 sec", 1), ("2 sec", 2), ("5 sec", 5), ("10 sec", 10), ("30 sec", 30), ("60 sec", 60)]:
            self.interval_combo.addItem(label, seconds)
        self.interval_combo.setCurrentIndex(2)
        controls.addWidget(self.interval_combo)

        controls.addWidget(QtWidgets.QLabel("Retrace after:"))
        self.retrace_combo = QtWidgets.QComboBox()
        for label, sets in [("Never", 0), ("5 sets", 5), ("10 sets", 10), ("25 sets", 25), ("50 sets", 50), ("100 sets", 100)]:
            self.retrace_combo.addItem(label, sets)
        self.retrace_combo.setCurrentIndex(2)
        controls.addWidget(self.retrace_combo)

        self.rdns_checkbox = QtWidgets.QCheckBox("Reverse DNS")
        self.rdns_checkbox.setChecked(True)
        self.rdns_checkbox.setToolTip("Resolve hostnames for hop IPs with cache + timeout")
        controls.addWidget(self.rdns_checkbox)

        self.clear_button = QtWidgets.QPushButton("Clear")
        self.clear_button.clicked.connect(self.clear_data)
        controls.addWidget(self.clear_button)

        controls.addStretch(1)
        root.addLayout(controls)

        splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        top_splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)

        self.hop_table = HopTable()
        self.hop_table.selected_hop_changed.connect(self.on_selected_hop_changed)
        top_splitter.addWidget(self.hop_table)

        self.path_plot = PathPlot()
        top_splitter.addWidget(self.path_plot)
        top_splitter.setStretchFactor(0, 3)
        top_splitter.setStretchFactor(1, 2)

        bottom_panel = QtWidgets.QWidget()
        bottom_layout = QtWidgets.QVBoxLayout(bottom_panel)
        bottom_layout.setContentsMargins(6, 6, 6, 6)
        bottom_layout.setSpacing(4)

        self.timeline_status_label = QtWidgets.QLabel("Final target: —   Successful samples: 0   Running avg: — ms   Loss: —")
        bottom_layout.addWidget(self.timeline_status_label)

        self.timeline_plot = TimelinePlot()
        bottom_layout.addWidget(self.timeline_plot, 1)

        splitter.addWidget(top_splitter)
        splitter.addWidget(bottom_panel)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 1)
        root.addWidget(splitter, 1)

        self.summary_label = QtWidgets.QLabel("Selected hop —   Avg: — ms   Loss: —   Sets: 0")
        root.addWidget(self.summary_label)

    def _target_text_changed(self, text: str) -> None:
        if self._worker is None and text.strip():
            self._last_target = text.strip()
            self.snapshot_changed.emit(self.snapshot())

    def update_target_choices(self, choices: List[str]) -> None:
        current_text = self.target_combo.currentText().strip() if hasattr(self, "target_combo") else ""
        unique_choices: List[str] = []
        seen = set()
        for value in choices:
            normalized = value.strip()
            key = normalized.lower()
            if not key or key in seen:
                continue
            seen.add(key)
            unique_choices.append(normalized)

        self._target_choices = unique_choices
        if hasattr(self, "target_combo"):
            self.target_combo.blockSignals(True)
            self.target_combo.clear()
            self.target_combo.addItems(unique_choices)
            self.target_combo.setCurrentText(current_text)
            self.target_combo.blockSignals(False)

    def start_monitoring(self) -> None:
        if self._worker is not None:
            return
        try:
            target = normalize_target(self.target_combo.currentText())
        except ValueError as exc:
            QtWidgets.QMessageBox.warning(self, APP_NAME, str(exc))
            return

        self.clear_data()
        self.target_combo.setCurrentText(target)
        self._last_target = target
        self.target_committed.emit(target)

        interval = float(self.interval_combo.currentData())
        retrace = int(self.retrace_combo.currentData())
        primary_log_path = self._build_log_file_path(target)
        fallback_log_path = self._build_log_file_path(target, use_temp_fallback=True)
        self._last_log_path = primary_log_path

        self._worker = None
        startup_error: Optional[Exception] = None
        for candidate_path in (primary_log_path, fallback_log_path):
            try:
                self._worker = MonitorWorker(
                    target,
                    interval,
                    retrace,
                    resolve_names=self.rdns_checkbox.isChecked(),
                    log_file_path=candidate_path,
                )
                self._last_log_path = candidate_path
                break
            except Exception as exc:
                startup_error = exc
                self._worker = None

        if self._worker is None:
            self._worker_thread = None
            message = f"Unable to start monitor: {startup_error}"
            self._set_status(message)
            QtWidgets.QMessageBox.critical(self, APP_NAME, message)
            return

        self._worker_thread = QtCore.QThread(self)
        self._worker.moveToThread(self._worker_thread)
        self._worker_thread.started.connect(self._worker.run)
        self._worker.status.connect(self._set_status)
        self._worker.error.connect(self._on_error)
        self._worker.trace_changed.connect(self._on_trace_changed)
        self._worker.stats_changed.connect(self._on_stats_changed)
        self._worker.set_completed.connect(self._on_set_completed)
        self._worker.finished.connect(self._on_worker_finished)
        self._worker.finished.connect(self._worker_thread.quit)
        self._worker_thread.finished.connect(self._worker_thread.deleteLater)
        self._worker_thread.start()

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.target_combo.setEnabled(False)
        self.interval_combo.setEnabled(False)
        self.retrace_combo.setEnabled(False)
        self.rdns_checkbox.setEnabled(False)
        self._set_status(f"Starting... Logging to {self._last_log_path}")
        self.snapshot_changed.emit(self.snapshot())

    def stop_monitoring(self) -> None:
        if self._worker is not None:
            self._worker.stop()
            self._set_status("Stopping...")
        if self._worker_thread is not None:
            self._worker_thread.quit()
            self._worker_thread.wait(3000)

    def clear_data(self) -> None:
        self._rows = []
        self._selected_hop = None
        self._timeline_hop = None
        self._target_timeline_samples = []
        self.hop_table.setRowCount(0)
        self.path_plot.clear_dynamic()
        self.timeline_plot.set_selected_hop(None)
        self.timeline_plot.update_history([])
        self.timeline_status_label.setText("Final target: —   Successful samples: 0   Running avg: — ms   Loss: —")
        self.summary_label.setText("Selected hop —   Avg: — ms   Loss: —   Sets: 0")
        self.snapshot_changed.emit(self.snapshot())

    def snapshot(self) -> Dict[str, object]:
        avg = "—"
        loss = "—"
        sets = 0
        if self._rows:
            final_row = self._rows[-1]
            avg = fmt_ms(final_row.get("avg_ms"))
            loss = fmt_percent(float(final_row.get("loss_percent", 0.0)))
            sets = int(final_row.get("samples", 0))
        updated = "—"
        if self._target_timeline_samples:
            updated = time.strftime("%H:%M:%S", time.localtime(float(self._target_timeline_samples[-1]["timestamp"])))
        return {
            "tab_name": self.tab_name,
            "target": self._last_target or "(not set)",
            "status": self._last_status,
            "sets": sets,
            "avg": avg,
            "loss": loss,
            "updated": updated,
            "running": self._worker is not None,
            "summary": self.summary_label.text(),
            "log_file": self._last_log_path,
        }

    def _set_status(self, message: str) -> None:
        self._last_status = message
        self.status_changed.emit(message)
        self.snapshot_changed.emit(self.snapshot())

    def _on_error(self, message: str) -> None:
        self._set_status(message)
        QtWidgets.QMessageBox.critical(self, APP_NAME, message)

    def _on_trace_changed(self, trace: List[Dict[str, object]]) -> None:
        self._set_status(f"Route contains {len(trace)} hop(s).")

    def _on_stats_changed(self, rows: List[Dict[str, object]], _histories: Dict[int, List[Dict[str, object]]]) -> None:
        self._rows = rows
        self.hop_table.update_rows(rows)
        self.path_plot.update_rows(rows)

        self._timeline_hop = self._choose_final_target_hop(rows)
        self.timeline_plot.set_selected_hop(self._timeline_hop)
        self._append_final_target_sample(rows, self._timeline_hop)
        self.timeline_plot.update_history(self._target_timeline_samples)
        self._update_timeline_status(self._timeline_hop, self._target_timeline_samples)
        self._update_summary()
        self.snapshot_changed.emit(self.snapshot())

    def _on_set_completed(self, _set_number: int, _timestamp: float) -> None:
        self.snapshot_changed.emit(self.snapshot())

    def _on_worker_finished(self) -> None:
        self._worker = None
        self._worker_thread = None
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.target_combo.setEnabled(True)
        self.interval_combo.setEnabled(True)
        self.retrace_combo.setEnabled(True)
        self.rdns_checkbox.setEnabled(True)
        if self._last_status == "Stopping...":
            self._set_status("Stopped.")
        self.snapshot_changed.emit(self.snapshot())

    def _build_log_file_path(self, target: str, use_temp_fallback: bool = False) -> str:
        safe_target = re.sub(r"[^A-Za-z0-9_.-]+", "_", target).strip("_") or "target"
        stamp = time.strftime("%Y%m%d_%H%M%S")
        if use_temp_fallback:
            base_root = os.path.join(tempfile.gettempdir(), APP_NAME)
        else:
            base_root = _app_data_dir()
        base_dir = os.path.join(base_root, LOG_DIR_NAME)
        return os.path.join(base_dir, f"{safe_target}_{stamp}.csv")

    def _choose_final_target_hop(self, rows: List[Dict[str, object]]) -> Optional[int]:
        if not rows:
            return None
        for row in reversed(rows):
            if str(row.get("ip", "")) != "*":
                return int(row["hop"])
        return int(rows[-1]["hop"])

    def _append_final_target_sample(self, rows: List[Dict[str, object]], hop: Optional[int]) -> None:
        if hop is None:
            return
        final_row = None
        for row in rows:
            if int(row["hop"]) == hop:
                final_row = row
                break
        if final_row is None:
            return

        set_number = int(final_row.get("samples", 0))
        if set_number <= 0:
            return

        if self._target_timeline_samples and int(self._target_timeline_samples[-1]["set_number"]) == set_number:
            self._target_timeline_samples[-1]["latency_ms"] = final_row.get("last_ms")
            return

        self._target_timeline_samples.append(
            {
                "set_number": set_number,
                "timestamp": time.time(),
                "latency_ms": final_row.get("last_ms"),
            }
        )

    def _update_timeline_status(self, hop: Optional[int], samples: List[Dict[str, object]]) -> None:
        if hop is None:
            self.timeline_status_label.setText("Final target: —   Successful samples: 0   Running avg: — ms   Loss: —")
            return

        success_values = [
            float(sample["latency_ms"])
            for sample in samples
            if sample.get("latency_ms") is not None
        ]
        success_count = len(success_values)
        running_avg_text = "—" if not success_values else f"{(sum(success_values) / success_count):.1f}"

        loss_text = "—"
        for row in self._rows:
            if int(row["hop"]) == hop:
                loss_text = fmt_percent(float(row.get("loss_percent", 0.0)))
                break

        self.timeline_status_label.setText(
            f"Final target: hop {hop}   Successful samples: {success_count}   Running avg: {running_avg_text} ms   Loss: {loss_text}"
        )

    def _update_summary(self) -> None:
        if not self._rows:
            self.summary_label.setText("Selected hop —   Avg: — ms   Loss: —   Sets: 0")
            return

        selected_row = None
        if self._selected_hop is not None:
            for row in self._rows:
                if int(row["hop"]) == self._selected_hop:
                    selected_row = row
                    break
        if selected_row is None:
            selected_row = self._rows[-1]

        avg = fmt_ms(selected_row.get("avg_ms"))
        loss = fmt_percent(float(selected_row.get("loss_percent", 0.0)))
        samples = int(selected_row.get("samples", 0))
        self.summary_label.setText(f"Selected hop {selected_row['hop']}   Avg: {avg} ms   Loss: {loss}   Sets: {samples}")

    def on_selected_hop_changed(self, hop: int) -> None:
        self._selected_hop = hop
        self._update_summary()
        self.snapshot_changed.emit(self.snapshot())


# ----------------------------- tools tab -----------------------------


class DnsWorker(QtCore.QObject):
    output = QtCore.Signal(str)
    finished = QtCore.Signal()

    def __init__(
        self,
        target: str,
        record_type: str,
        filter_text: str = "",
        sort_desc: bool = False,
    ) -> None:
        super().__init__()
        self.target = target
        self.record_type = record_type
        self.filter_text = filter_text.strip().lower()
        self.sort_desc = sort_desc
        self._cancelled = threading.Event()

    def cancel(self) -> None:
        self._cancelled.set()

    @QtCore.Slot()
    def run(self) -> None:
        try:
            self._do_lookup()
        except Exception as exc:
            self.output.emit(f"Error: {exc}")
        finally:
            self.finished.emit()

    def _do_lookup(self) -> None:
        self.output.emit(f"=== DNS Lookup: {self.target}  [{self.record_type}] ===")
        self.output.emit("")

        if self._cancelled.is_set():
            self.output.emit("Cancelled.")
            return

        if self.record_type == "PTR":
            self._python_reverse_lookup()
        elif self.record_type in ("A", "AAAA"):
            self._python_forward_lookup()
            self._nslookup_query()
        else:
            self._nslookup_query()

    def _python_reverse_lookup(self) -> None:
        self.output.emit(f"Reverse DNS for: {self.target}")
        try:
            hostname, aliases, addresses = socket.gethostbyaddr(self.target)
            self.output.emit(f"  Hostname:   {hostname}")
            if aliases:
                self.output.emit(f"  Aliases:    {', '.join(aliases)}")
            if addresses:
                self.output.emit(f"  Addresses:  {', '.join(addresses)}")
        except Exception as exc:
            self.output.emit(f"  {exc}")
        self.output.emit("")
        self._nslookup_query()

    def _python_forward_lookup(self) -> None:
        family = socket.AF_INET if self.record_type == "A" else socket.AF_INET6
        self.output.emit(f"Python socket {self.record_type} lookup for: {self.target}")
        try:
            results = socket.getaddrinfo(self.target, None, family)
            seen: set = set()
            addrs: List[str] = []
            for result in results:
                addr = result[4][0]
                if addr not in seen:
                    seen.add(addr)
                    addrs.append(addr)

            if self.filter_text:
                addrs = [a for a in addrs if self.filter_text in a.lower()]
            addrs.sort(reverse=self.sort_desc)

            if addrs:
                for addr in addrs:
                    self.output.emit(f"  {addr}")
            else:
                self.output.emit("  (no results)")
        except Exception as exc:
            self.output.emit(f"  {exc}")
        self.output.emit("")

    def _extract_nslookup_records(self, output_text: str) -> List[str]:
        records: List[str] = []
        for line in output_text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            lower = stripped.lower()
            if (
                lower.startswith("server:")
                or lower.startswith("address:")
                or lower.startswith("addresses:")
                or lower.startswith("non-authoritative answer")
                or lower.startswith("authoritative answers")
                or lower.startswith("name:")
                or lower.startswith(">")
            ):
                continue
            records.append(stripped)

        seen: set = set()
        unique: List[str] = []
        for record in records:
            key = record.lower()
            if key in seen:
                continue
            seen.add(key)
            unique.append(record)
        return unique

    def _apply_record_filter_sort(self, records: List[str]) -> List[str]:
        if self.filter_text:
            records = [record for record in records if self.filter_text in record.lower()]
        records.sort(key=lambda value: value.lower(), reverse=self.sort_desc)
        return records

    def _nslookup_query(self) -> None:
        if self._cancelled.is_set():
            self.output.emit("Cancelled.")
            return
        self.output.emit(f"nslookup output (-type={self.record_type}):")
        cmd = ["nslookup", f"-type={self.record_type}", self.target]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10.0,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
            out = (proc.stdout or "").rstrip()
            err = (proc.stderr or "").rstrip()
            if out:
                parsed_records = self._extract_nslookup_records(out)
                filtered_records = self._apply_record_filter_sort(parsed_records)
                order_text = "descending" if self.sort_desc else "ascending"
                filter_text = self.filter_text if self.filter_text else "(none)"
                self.output.emit(f"  Filter: {filter_text}")
                self.output.emit(f"  Sort: {order_text}")
                if filtered_records:
                    self.output.emit("  Parsed records:")
                    for record in filtered_records:
                        self.output.emit(f"    {record}")
                self.output.emit("")
                self.output.emit(out)
            if err:
                self.output.emit(err)
            if not out and not err:
                self.output.emit("  (no output)")
        except FileNotFoundError:
            self.output.emit("  nslookup is not available on this system.")
        except subprocess.TimeoutExpired:
            self.output.emit("  Query timed out after 10 seconds.")
        except Exception as exc:
            self.output.emit(f"  {exc}")


DNS_PROPAGATION_RESOLVERS: List[Tuple[str, Optional[str]]] = [
    ("System DNS", None),
    ("Google 8.8.8.8", "8.8.8.8"),
    ("Cloudflare 1.1.1.1", "1.1.1.1"),
    ("Quad9 9.9.9.9", "9.9.9.9"),
    ("OpenDNS 208.67.222.222", "208.67.222.222"),
]


class DnsPropagationWorker(QtCore.QObject):
    output = QtCore.Signal(str)
    finished = QtCore.Signal()

    def __init__(self, target: str, record_type: str) -> None:
        super().__init__()
        self.target = target.strip()
        self.record_type = record_type.strip().upper() or "A"
        self._cancelled = threading.Event()

    def cancel(self) -> None:
        self._cancelled.set()

    @QtCore.Slot()
    def run(self) -> None:
        try:
            self._do_compare()
        except Exception as exc:
            self.output.emit(f"Error: {exc}")
        finally:
            self.finished.emit()

    def _parse_nslookup_records(self, output_text: str) -> List[str]:
        records: List[str] = []
        answer_started = False
        for line in output_text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            lower = stripped.lower()
            if lower.startswith("server:") or (lower.startswith("address:") and not answer_started):
                continue
            if lower.startswith("non-authoritative answer") or lower.startswith("authoritative answers"):
                answer_started = True
                continue
            if lower.startswith("name:"):
                answer_started = True
            if not answer_started:
                continue

            if lower.startswith("name:"):
                records.append(stripped.split(":", 1)[1].strip())
                continue
            if lower.startswith("canonical name:"):
                records.append(stripped.split(":", 1)[1].strip())
                continue
            if lower.startswith("aliases:"):
                aliases_text = stripped.split(":", 1)[1].strip()
                if aliases_text:
                    records.extend(part.strip() for part in aliases_text.split(",") if part.strip())
                continue
            if lower.startswith("address:") or lower.startswith("addresses:"):
                value_text = stripped.split(":", 1)[1].strip()
                if value_text:
                    for token in re.split(r"[\s,]+", value_text):
                        try:
                            ipaddress.ip_address(token)
                        except ValueError:
                            continue
                        records.append(token)

        seen: set = set()
        unique: List[str] = []
        for record in records:
            key = record.lower()
            if key not in seen:
                seen.add(key)
                unique.append(record)
        return unique

    def _query_resolver(self, resolver_name: str, server: Optional[str]) -> Tuple[str, List[str]]:
        cmd = ["nslookup", f"-type={self.record_type}", self.target]
        if server:
            cmd.append(server)
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10.0,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )
        out = (proc.stdout or "").strip()
        err = (proc.stderr or "").strip()
        if err and not out:
            return (resolver_name, [f"(error: {err})"])
        records = self._parse_nslookup_records(out)
        if not records and err:
            records = [f"(error: {err})"]
        return (resolver_name, records)

    def _do_compare(self) -> None:
        self.output.emit(f"=== DNS Propagation / Multi-DNS Resolver: {self.target} [{self.record_type}] ===")
        self.output.emit("Comparing responses from several resolvers.")
        self.output.emit("")

        rows: List[Tuple[str, List[str]]] = []
        for resolver_name, server in DNS_PROPAGATION_RESOLVERS:
            if self._cancelled.is_set():
                self.output.emit("Cancelled.")
                return
            try:
                rows.append(self._query_resolver(resolver_name, server))
            except subprocess.TimeoutExpired:
                rows.append((resolver_name, ["(timed out)"]))
            except FileNotFoundError:
                rows.append((resolver_name, ["(nslookup not found)"]))
            except Exception as exc:
                rows.append((resolver_name, [f"(error: {exc})"]))

        if not rows:
            self.output.emit("No resolver data returned.")
            return

        normalized_answers = [", ".join(records).strip().lower() for _resolver, records in rows if records]
        all_same = bool(normalized_answers) and len(set(normalized_answers)) == 1

        self.output.emit(f"All resolvers returned the same answer: {'YES' if all_same else 'NO'}")
        self.output.emit("")

        resolver_w = max(len("Resolver"), *(len(row[0]) for row in rows))
        answer_w = max(len("Answer"), *(len(", ".join(row[1])) for row in rows))
        match_w = len("Match")

        baseline = ", ".join(rows[0][1]).strip().lower() if rows and rows[0][1] else ""

        header = f"{'Resolver':<{resolver_w}}  {'Answer':<{answer_w}}  {'Match':<{match_w}}"
        self.output.emit(header)
        self.output.emit("-" * len(header))
        for resolver_name, records in rows:
            answer_text = ", ".join(records) if records else "(no answer)"
            match_text = "same" if baseline and answer_text.strip().lower() == baseline else "different"
            self.output.emit(f"{resolver_name:<{resolver_w}}  {answer_text:<{answer_w}}  {match_text:<{match_w}}")

        self.output.emit("")
        self.output.emit("Tip: if answers differ, DNS propagation or caching is still in flight.")


class WhoisWorker(QtCore.QObject):
    output = QtCore.Signal(str)
    finished = QtCore.Signal()

    def __init__(self, target: str) -> None:
        super().__init__()
        self.target = target
        self._cancelled = threading.Event()

    def cancel(self) -> None:
        self._cancelled.set()

    @QtCore.Slot()
    def run(self) -> None:
        try:
            self._do_lookup()
        except Exception as exc:
            self.output.emit(f"Error: {exc}")
        finally:
            self.finished.emit()

    def _do_lookup(self) -> None:
        self.output.emit(f"=== WHOIS Lookup: {self.target} ===")
        self.output.emit("")

        if self._cancelled.is_set():
            self.output.emit("Cancelled.")
            return

        try:
            import whois  # type: ignore[import]
        except ImportError:
            self.output.emit("python-whois is not installed.")
            self.output.emit("Install it with:  pip install python-whois")
            return

        try:
            result = whois.whois(self.target)
        except Exception as exc:
            self.output.emit(f"WHOIS query failed: {exc}")
            return

        if self._cancelled.is_set():
            self.output.emit("Cancelled.")
            return

        fields = [
            ("Domain Name",         "domain_name"),
            ("Registrar",            "registrar"),
            ("Registrar URL",        "registrar_url"),
            ("WHOIS Server",         "whois_server"),
            ("Updated Date",         "updated_date"),
            ("Creation Date",        "creation_date"),
            ("Expiration Date",      "expiration_date"),
            ("Name Servers",         "name_servers"),
            ("Status",               "status"),
            ("Emails",               "emails"),
            ("Org",                  "org"),
            ("Address",              "address"),
            ("City",                 "city"),
            ("State",                "state"),
            ("Zip Code",             "zipcode"),
            ("Country",              "country"),
            ("DNSSEC",               "dnssec"),
        ]

        any_printed = False
        for label, attr in fields:
            value = getattr(result, attr, None)
            if value is None:
                continue
            if isinstance(value, list):
                unique = []
                seen: set = set()
                for item in value:
                    s = str(item).strip()
                    if s and s.lower() not in seen:
                        seen.add(s.lower())
                        unique.append(s)
                if not unique:
                    continue
                self.output.emit(f"{label}:")
                for item in unique:
                    self.output.emit(f"  {item}")
            else:
                self.output.emit(f"{label}: {str(value).strip()}")
            any_printed = True

        if not any_printed:
            self.output.emit("No structured data returned.")
            self.output.emit("")
            self.output.emit("Raw text:")
            raw = getattr(result, "text", None) or str(result)
            self.output.emit(raw)


COMMON_PORTS: List[Tuple[int, str]] = [
    (21,   "FTP"),
    (22,   "SSH"),
    (25,   "SMTP"),
    (53,   "DNS"),
    (80,   "HTTP"),
    (110,  "POP3"),
    (143,  "IMAP"),
    (389,  "LDAP"),
    (443,  "HTTPS"),
    (445,  "SMB"),
    (587,  "SMTP Submission"),
    (993,  "IMAPS"),
    (995,  "POP3S"),
    (1433, "SQL Server"),
    (3306, "MySQL"),
    (3389, "RDP"),
    (5432, "PostgreSQL"),
    (8080, "HTTP Alt"),
]


class PortCheckWorker(QtCore.QObject):
    output = QtCore.Signal(str)
    finished = QtCore.Signal()

    CONNECT_TIMEOUT = 5.0

    def __init__(self, host: str, port: int) -> None:
        super().__init__()
        self.host = host
        self.port = port
        self._cancelled = threading.Event()

    def cancel(self) -> None:
        self._cancelled.set()

    @QtCore.Slot()
    def run(self) -> None:
        try:
            self._do_check()
        except Exception as exc:
            self.output.emit(f"Error: {exc}")
        finally:
            self.finished.emit()

    def _do_check(self) -> None:
        self.output.emit(f"=== Port Check: {self.host}:{self.port} ===")
        self.output.emit("")

        # Resolve hostname first
        self.output.emit(f"Resolving {self.host!r} ...")
        try:
            infos = socket.getaddrinfo(self.host, self.port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            self.output.emit(f"  DNS resolution failed: {exc}")
            return

        resolved_ip = infos[0][4][0]
        self.output.emit(f"  Resolved IP:  {resolved_ip}")
        self.output.emit("")

        if self._cancelled.is_set():
            self.output.emit("Cancelled.")
            return

        # Attempt TCP connect
        self.output.emit(f"Connecting to {resolved_ip}:{self.port} (timeout {self.CONNECT_TIMEOUT:.0f}s) ...")
        t_start = time.perf_counter()
        try:
            with socket.create_connection((self.host, self.port), timeout=self.CONNECT_TIMEOUT):
                elapsed_ms = (time.perf_counter() - t_start) * 1000
                self.output.emit(f"  Status:        OPEN")
                self.output.emit(f"  Connect time:  {elapsed_ms:.1f} ms")
        except ConnectionRefusedError:
            elapsed_ms = (time.perf_counter() - t_start) * 1000
            self.output.emit(f"  Status:        CLOSED (connection refused)")
            self.output.emit(f"  Response time: {elapsed_ms:.1f} ms")
        except socket.timeout:
            elapsed_ms = (time.perf_counter() - t_start) * 1000
            self.output.emit(f"  Status:        TIMEOUT (no response in {self.CONNECT_TIMEOUT:.0f}s)")
        except OSError as exc:
            elapsed_ms = (time.perf_counter() - t_start) * 1000
            self.output.emit(f"  Status:        ERROR — {exc}")
            self.output.emit(f"  Response time: {elapsed_ms:.1f} ms")


class HttpCheckWorker(QtCore.QObject):
    output = QtCore.Signal(str)
    finished = QtCore.Signal()

    TIMEOUT = 10.0

    def __init__(self, url: str) -> None:
        super().__init__()
        self.url = url
        self._cancelled = threading.Event()

    def cancel(self) -> None:
        self._cancelled.set()

    @QtCore.Slot()
    def run(self) -> None:
        try:
            self._do_check()
        except Exception as exc:
            self.output.emit(f"Error: {exc}")
        finally:
            self.finished.emit()

    def _do_check(self) -> None:
        import urllib.request
        import urllib.error
        import ssl
        import http.client

        url = self.url.strip()
        if not re.match(r"^https?://", url, re.I):
            url = "https://" + url

        self.output.emit(f"=== HTTP/HTTPS Check: {url} ===")
        self.output.emit("")

        redirect_chain: List[str] = []
        final_url = url
        status_code = 0
        reason = ""
        server_header = ""
        content_length = ""
        t_total_ms = 0.0
        error_msg = ""

        ctx = ssl.create_default_context()

        try:
            opener = urllib.request.build_opener(
                urllib.request.HTTPRedirectHandler()
            )
            # Track redirects by subclassing
            recorded_redirects: List[str] = []

            class _TrackingRedirectHandler(urllib.request.HTTPRedirectHandler):  # noqa: N801
                def redirect_request(self_inner, req, fp, code, msg, headers, newurl):  # noqa: N805
                    recorded_redirects.append(f"  {code}  {req.full_url}  →  {newurl}")
                    return super().redirect_request(req, fp, code, msg, headers, newurl)

            opener = urllib.request.build_opener(_TrackingRedirectHandler)
            req = urllib.request.Request(
                url,
                headers={"User-Agent": f"{APP_NAME}/1.0"},
            )

            if self._cancelled.is_set():
                self.output.emit("Cancelled.")
                return

            t_start = time.perf_counter()
            with opener.open(req, timeout=self.TIMEOUT) as resp:
                t_total_ms = (time.perf_counter() - t_start) * 1000
                status_code = resp.status
                reason = resp.reason or ""
                final_url = resp.url
                server_header = resp.headers.get("Server", "")
                cl = resp.headers.get("Content-Length", "")
                content_length = cl if cl else "(not provided)"
                redirect_chain = recorded_redirects

        except urllib.error.HTTPError as exc:
            t_total_ms = (time.perf_counter() - t_start) * 1000 if 't_start' in dir() else 0.0
            status_code = exc.code
            reason = exc.reason or ""
            final_url = exc.url or url
            server_header = exc.headers.get("Server", "") if exc.headers else ""
            redirect_chain = recorded_redirects if 'recorded_redirects' in dir() else []
        except urllib.error.URLError as exc:
            error_msg = str(exc.reason)
        except ssl.SSLError as exc:
            error_msg = f"TLS/SSL error: {exc}"
        except socket.timeout:
            error_msg = f"Connection timed out after {self.TIMEOUT:.0f}s"
        except Exception as exc:
            error_msg = str(exc)

        # --- Output results ---
        if redirect_chain:
            self.output.emit("Redirect chain:")
            for hop in redirect_chain:
                self.output.emit(hop)
            self.output.emit("")

        self.output.emit(f"Final URL:        {final_url}")

        if error_msg:
            self.output.emit(f"Status:           ERROR")
            self.output.emit(f"Error:            {error_msg}")
        else:
            self.output.emit(f"Status code:      {status_code}  {reason}")
            self.output.emit(f"Response time:    {t_total_ms:.1f} ms")
            if server_header:
                self.output.emit(f"Server:           {server_header}")
            self.output.emit(f"Content-Length:   {content_length}")

        # TLS cert expiry (HTTPS only)
        if self._cancelled.is_set():
            return
        parsed_url = final_url if final_url else url
        if parsed_url.lower().startswith("https://"):
            self.output.emit("")
            self._check_tls_expiry(parsed_url, ctx)

    def _check_tls_expiry(self, url: str, ctx: "ssl.SSLContext") -> None:  # type: ignore[name-defined]
        import ssl
        from urllib.parse import urlparse as _urlparse
        parsed = _urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or 443
        if not host:
            return
        try:
            with socket.create_connection((host, port), timeout=5.0) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as tls:
                    cert = tls.getpeercert()
            not_after = cert.get("notAfter", "") if cert else ""
            if not_after:
                import datetime
                expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                now = datetime.datetime.utcnow()
                days_left = (expiry - now).days
                flag = "  ⚠ EXPIRING SOON" if days_left < 30 else ""
                if days_left < 0:
                    flag = "  ✗ EXPIRED"
                self.output.emit(f"TLS cert expiry:  {expiry.strftime('%Y-%m-%d')}  ({days_left}d remaining){flag}")
            else:
                self.output.emit("TLS cert expiry:  (unable to read)")
        except Exception as exc:
            self.output.emit(f"TLS cert check:   {exc}")



class LocalNetInfoWorker(QtCore.QObject):
    output = QtCore.Signal(str)
    finished = QtCore.Signal()

    def __init__(self) -> None:
        super().__init__()
        self._cancelled = threading.Event()

    def cancel(self) -> None:
        self._cancelled.set()

    @QtCore.Slot()
    def run(self) -> None:
        try:
            self._collect()
        except Exception as exc:
            self.output.emit(f"Error: {exc}")
        finally:
            self.finished.emit()

    def _run_cmd(self, args: List[str], label: str) -> None:
        self.output.emit(f"--- {label} ---")
        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=15.0,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
            out = (proc.stdout or "").rstrip()
            err = (proc.stderr or "").rstrip()
            if out:
                self.output.emit(out)
            if err:
                self.output.emit(err)
            if not out and not err:
                self.output.emit("(no output)")
        except FileNotFoundError:
            self.output.emit(f"  Command not found: {args[0]}")
        except subprocess.TimeoutExpired:
            self.output.emit("  Timed out.")
        except Exception as exc:
            self.output.emit(f"  {exc}")
        self.output.emit("")

    def _collect(self) -> None:
        import urllib.request

        self.output.emit("=== Local Network Information ===")
        self.output.emit(f"Collected: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        self.output.emit("")

        self.output.emit("--- Hostname / Python socket info ---")
        try:
            hostname = socket.gethostname()
            self.output.emit(f"  Hostname:      {hostname}")
            try:
                fqdn = socket.getfqdn()
                if fqdn != hostname:
                    self.output.emit(f"  FQDN:          {fqdn}")
            except Exception:
                pass
            try:
                local_ip = socket.gethostbyname(hostname)
                self.output.emit(f"  Primary IP:    {local_ip}")
            except Exception:
                pass
        except Exception as exc:
            self.output.emit(f"  {exc}")
        self.output.emit("")

        if self._cancelled.is_set():
            self.output.emit("Cancelled.")
            return

        self.output.emit("--- Public IP address ---")
        for probe_url in [
            "https://api.ipify.org",
            "https://checkip.amazonaws.com",
            "https://icanhazip.com",
        ]:
            try:
                req = urllib.request.Request(
                    probe_url,
                    headers={"User-Agent": f"{APP_NAME}/1.0"},
                )
                with urllib.request.urlopen(req, timeout=5.0) as resp:
                    public_ip = resp.read().decode().strip()
                self.output.emit(f"  Public IP:     {public_ip}")
                self.output.emit(f"  (via {probe_url})")
                break
            except Exception:
                continue
        else:
            self.output.emit("  Could not determine public IP (no internet or all probes failed).")
        self.output.emit("")

        if self._cancelled.is_set():
            self.output.emit("Cancelled.")
            return

        is_windows = platform.system().lower() == "windows"
        if is_windows:
            self._run_cmd(["ipconfig", "/all"], "ipconfig /all")
            if self._cancelled.is_set():
                return
            self._run_cmd(["route", "print"], "route print  (routing table)")
            if self._cancelled.is_set():
                return
            self._run_cmd(
                ["netsh", "interface", "ip", "show", "config"],
                "netsh interface ip show config",
            )
        else:
            for cmd, label in [
                (["ip", "addr", "show"],      "ip addr show  (interfaces)"),
                (["ip", "route", "show"],     "ip route show  (routing table)"),
                (["ip", "neigh", "show"],     "ip neigh show  (ARP/neighbors)"),
                (["cat", "/etc/resolv.conf"], "/etc/resolv.conf  (DNS)"),
            ]:
                if self._cancelled.is_set():
                    return
                self._run_cmd(cmd, label)

class ArpTableWorker(QtCore.QObject):
    output = QtCore.Signal(str)
    finished = QtCore.Signal()

    def __init__(
        self,
        interface_filter: str = "",
        type_filter: str = "all",
        sort_by: str = "ip",
        descending: bool = False,
    ) -> None:
        super().__init__()
        self._cancelled = threading.Event()
        self.interface_filter = interface_filter.strip().lower()
        self.type_filter = type_filter.strip().lower()
        self.sort_by = sort_by.strip().lower()
        self.descending = descending

    def cancel(self) -> None:
        self._cancelled.set()

    @QtCore.Slot()
    def run(self) -> None:
        try:
            self._collect()
        except Exception as exc:
            self.output.emit(f"Error: {exc}")
        finally:
            self.finished.emit()

    def _collect(self) -> None:
        self.output.emit("=== ARP Table Viewer ===")
        self.output.emit(f"Collected: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        self.output.emit("")

        is_windows = platform.system().lower() == "windows"
        cmd = ["arp", "-a"]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=20.0,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
        except FileNotFoundError:
            self.output.emit("arp command not found on this system.")
            return
        except subprocess.TimeoutExpired:
            self.output.emit("arp -a timed out.")
            return

        raw = (proc.stdout or "").strip()
        err = (proc.stderr or "").strip()
        if not raw and err:
            self.output.emit(err)
            return
        if not raw:
            self.output.emit("No ARP entries returned.")
            return

        entries: List[Tuple[str, str, str, str]] = []
        if is_windows:
            current_iface = ""
            for line in raw.splitlines():
                if self._cancelled.is_set():
                    self.output.emit("Cancelled.")
                    return
                stripped = line.strip()
                if not stripped:
                    continue

                iface_match = re.match(r"^Interface:\s+([0-9a-fA-F:.%]+)", stripped, re.I)
                if iface_match:
                    current_iface = iface_match.group(1)
                    continue

                row_match = re.match(
                    r"^([0-9a-fA-F:.]+)\s+([0-9a-fA-F\-]{11,}|[0-9a-fA-F:]{11,})\s+(dynamic|static|invalid)$",
                    stripped,
                    re.I,
                )
                if row_match:
                    ip_addr = row_match.group(1)
                    mac_raw = row_match.group(2).lower().replace("-", ":")
                    arp_type = row_match.group(3).lower()
                    entries.append((ip_addr, mac_raw, current_iface or "(unknown)", arp_type))
        else:
            # Linux/macOS output is less uniform; attempt a best-effort parse.
            for line in raw.splitlines():
                if self._cancelled.is_set():
                    self.output.emit("Cancelled.")
                    return
                stripped = line.strip()
                if not stripped:
                    continue
                ip_match = re.search(r"\(([^)]+)\)", stripped)
                mac_match = re.search(r"\b(([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\b", stripped)
                iface_match = re.search(r"\bon\s+(\S+)\b", stripped)
                type_val = "dynamic"
                if "permanent" in stripped.lower() or "static" in stripped.lower():
                    type_val = "static"
                ip_addr = ip_match.group(1) if ip_match else ""
                mac_addr = mac_match.group(1).lower() if mac_match else "(incomplete)"
                iface = iface_match.group(1) if iface_match else "(unknown)"
                if ip_addr:
                    entries.append((ip_addr, mac_addr, iface, type_val))

        total_entries = len(entries)

        if self.interface_filter:
            entries = [
                entry for entry in entries
                if self.interface_filter in entry[2].lower()
            ]

        if self.type_filter in ("dynamic", "static", "invalid"):
            entries = [entry for entry in entries if entry[3].lower() == self.type_filter]

        if self.sort_by == "ip":
            def sort_key(entry: Tuple[str, str, str, str]) -> Tuple[int, object]:
                try:
                    return (0, ipaddress.ip_address(entry[0]))
                except ValueError:
                    return (1, entry[0].lower())
        elif self.sort_by == "mac":
            def sort_key(entry: Tuple[str, str, str, str]) -> object:
                return entry[1].lower()
        elif self.sort_by == "interface":
            def sort_key(entry: Tuple[str, str, str, str]) -> object:
                return entry[2].lower()
        elif self.sort_by == "type":
            def sort_key(entry: Tuple[str, str, str, str]) -> object:
                return entry[3].lower()
        else:
            def sort_key(entry: Tuple[str, str, str, str]) -> Tuple[int, object]:
                try:
                    return (0, ipaddress.ip_address(entry[0]))
                except ValueError:
                    return (1, entry[0].lower())

        entries.sort(key=sort_key, reverse=self.descending)

        order_text = "descending" if self.descending else "ascending"
        interface_text = self.interface_filter if self.interface_filter else "(all)"
        type_text = self.type_filter if self.type_filter else "all"
        self.output.emit(f"Filter interface: {interface_text}")
        self.output.emit(f"Filter type:      {type_text}")
        self.output.emit(f"Sort:             {self.sort_by} ({order_text})")
        self.output.emit(f"Entries:          {len(entries)} shown / {total_entries} total")
        self.output.emit("")

        if not entries:
            self.output.emit("No parseable ARP entries found.")
            self.output.emit("")
            self.output.emit("Raw output:")
            self.output.emit(raw)
            return

        ip_w = max(len("IP Address"), *(len(e[0]) for e in entries))
        mac_w = max(len("MAC Address"), *(len(e[1]) for e in entries))
        if_w = max(len("Interface"), *(len(e[2]) for e in entries))
        type_w = max(len("Type"), *(len(e[3]) for e in entries))

        header = f"{'IP Address':<{ip_w}}  {'MAC Address':<{mac_w}}  {'Interface':<{if_w}}  {'Type':<{type_w}}"
        self.output.emit(header)
        self.output.emit("-" * len(header))
        for ip_addr, mac_addr, iface, arp_type in entries:
            self.output.emit(
                f"{ip_addr:<{ip_w}}  {mac_addr:<{mac_w}}  {iface:<{if_w}}  {arp_type:<{type_w}}"
            )


class RouteTableWorker(QtCore.QObject):
    output = QtCore.Signal(str)
    finished = QtCore.Signal()

    def __init__(
        self,
        interface_filter: str = "",
        gateway_filter: str = "",
        sort_by: str = "destination",
        descending: bool = False,
    ) -> None:
        super().__init__()
        self._cancelled = threading.Event()
        self.interface_filter = interface_filter.strip().lower()
        self.gateway_filter = gateway_filter.strip().lower()
        self.sort_by = sort_by.strip().lower()
        self.descending = descending

    def cancel(self) -> None:
        self._cancelled.set()

    @QtCore.Slot()
    def run(self) -> None:
        try:
            self._collect()
        except Exception as exc:
            self.output.emit(f"Error: {exc}")
        finally:
            self.finished.emit()

    def _collect(self) -> None:
        self.output.emit("=== Route Table Viewer ===")
        self.output.emit(f"Collected: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        self.output.emit("")

        is_windows = platform.system().lower() == "windows"
        cmd = ["route", "print"] if is_windows else ["ip", "route", "show"]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=20.0,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
        except FileNotFoundError:
            self.output.emit(f"Command not found: {' '.join(cmd)}")
            return
        except subprocess.TimeoutExpired:
            self.output.emit(f"{' '.join(cmd)} timed out.")
            return

        raw = (proc.stdout or "").strip()
        err = (proc.stderr or "").strip()
        if not raw and err:
            self.output.emit(err)
            return
        if not raw:
            self.output.emit("No routing entries returned.")
            return

        entries: List[Tuple[str, str, str, str, str]] = []

        if is_windows:
            in_ipv4_table = False
            in_active_routes = False
            found_columns = False

            for line in raw.splitlines():
                if self._cancelled.is_set():
                    self.output.emit("Cancelled.")
                    return

                stripped = line.strip()
                if not stripped:
                    continue

                if re.match(r"^IPv4 Route Table$", stripped, re.I):
                    in_ipv4_table = True
                    in_active_routes = False
                    found_columns = False
                    continue

                if in_ipv4_table and re.match(r"^IPv6 Route Table$", stripped, re.I):
                    break

                if not in_ipv4_table:
                    continue

                if re.match(r"^Active Routes:$", stripped, re.I):
                    in_active_routes = True
                    found_columns = False
                    continue

                if in_active_routes and re.match(r"^Persistent Routes:$", stripped, re.I):
                    break

                if not in_active_routes:
                    continue

                if stripped.lower().startswith("network destination"):
                    found_columns = True
                    continue

                if not found_columns:
                    continue

                parts = stripped.split()
                if len(parts) < 5:
                    continue

                destination = parts[0]
                netmask = parts[1]
                gateway = parts[2]
                interface = parts[3]
                metric = parts[4]
                entries.append((destination, netmask, gateway, interface, metric))
        else:
            # Best-effort parser for `ip route show` output on non-Windows systems.
            for line in raw.splitlines():
                if self._cancelled.is_set():
                    self.output.emit("Cancelled.")
                    return

                stripped = line.strip()
                if not stripped:
                    continue
                parts = stripped.split()
                if not parts:
                    continue

                dest_token = parts[0]
                if dest_token == "default":
                    destination = "0.0.0.0"
                    netmask = "0.0.0.0"
                else:
                    try:
                        network = ipaddress.ip_network(dest_token, strict=False)
                        destination = str(network.network_address)
                        netmask = str(network.netmask)
                    except ValueError:
                        destination = dest_token
                        netmask = "(n/a)"

                gateway = "On-link"
                interface = "(unknown)"
                metric = "(n/a)"

                if "via" in parts:
                    via_idx = parts.index("via")
                    if via_idx + 1 < len(parts):
                        gateway = parts[via_idx + 1]

                if "dev" in parts:
                    dev_idx = parts.index("dev")
                    if dev_idx + 1 < len(parts):
                        interface = parts[dev_idx + 1]

                if "metric" in parts:
                    metric_idx = parts.index("metric")
                    if metric_idx + 1 < len(parts):
                        metric = parts[metric_idx + 1]

                entries.append((destination, netmask, gateway, interface, metric))

        if not entries:
            self.output.emit("No parseable route entries found.")
            self.output.emit("")
            self.output.emit("Raw output:")
            self.output.emit(raw)
            return

        total_entries = len(entries)
        if self.interface_filter:
            entries = [entry for entry in entries if self.interface_filter in entry[3].lower()]
        if self.gateway_filter:
            entries = [entry for entry in entries if self.gateway_filter in entry[2].lower()]

        if self.sort_by == "destination":
            def sort_key(entry: Tuple[str, str, str, str, str]) -> Tuple[int, object]:
                try:
                    return (0, ipaddress.ip_address(entry[0]))
                except ValueError:
                    return (1, entry[0].lower())
        elif self.sort_by == "netmask":
            def sort_key(entry: Tuple[str, str, str, str, str]) -> object:
                return entry[1].lower()
        elif self.sort_by == "gateway":
            def sort_key(entry: Tuple[str, str, str, str, str]) -> object:
                return entry[2].lower()
        elif self.sort_by == "interface":
            def sort_key(entry: Tuple[str, str, str, str, str]) -> object:
                return entry[3].lower()
        elif self.sort_by == "metric":
            def sort_key(entry: Tuple[str, str, str, str, str]) -> Tuple[int, object]:
                try:
                    return (0, int(entry[4]))
                except ValueError:
                    return (1, entry[4].lower())
        else:
            def sort_key(entry: Tuple[str, str, str, str, str]) -> Tuple[int, object]:
                try:
                    return (0, ipaddress.ip_address(entry[0]))
                except ValueError:
                    return (1, entry[0].lower())

        entries.sort(key=sort_key, reverse=self.descending)

        order_text = "descending" if self.descending else "ascending"
        iface_text = self.interface_filter if self.interface_filter else "(all)"
        gateway_text = self.gateway_filter if self.gateway_filter else "(all)"
        self.output.emit(f"Filter interface: {iface_text}")
        self.output.emit(f"Filter gateway:   {gateway_text}")
        self.output.emit(f"Sort:             {self.sort_by} ({order_text})")
        self.output.emit(f"Entries:          {len(entries)} shown / {total_entries} total")
        self.output.emit("")

        if not entries:
            self.output.emit("No route entries matched the current filters.")
            return

        dest_w = max(len("Destination"), *(len(e[0]) for e in entries))
        mask_w = max(len("Netmask"), *(len(e[1]) for e in entries))
        gw_w = max(len("Gateway"), *(len(e[2]) for e in entries))
        if_w = max(len("Interface"), *(len(e[3]) for e in entries))
        metric_w = max(len("Metric"), *(len(e[4]) for e in entries))

        header = (
            f"{'Destination':<{dest_w}}  {'Netmask':<{mask_w}}  {'Gateway':<{gw_w}}  "
            f"{'Interface':<{if_w}}  {'Metric':<{metric_w}}"
        )
        self.output.emit(header)
        self.output.emit("-" * len(header))

        for destination, netmask, gateway, interface, metric in entries:
            self.output.emit(
                f"{destination:<{dest_w}}  {netmask:<{mask_w}}  {gateway:<{gw_w}}  "
                f"{interface:<{if_w}}  {metric:<{metric_w}}"
            )


class ActiveConnectionsWorker(QtCore.QObject):
    output = QtCore.Signal(str)
    finished = QtCore.Signal()

    def __init__(
        self,
        state_filter: str = "all",
        port_filter: str = "",
        process_filter: str = "",
        sort_by: str = "local",
        descending: bool = False,
    ) -> None:
        super().__init__()
        self._cancelled = threading.Event()
        self.state_filter = state_filter.strip().lower()
        self.port_filter = port_filter.strip().lower()
        self.process_filter = process_filter.strip().lower()
        self.sort_by = sort_by.strip().lower()
        self.descending = descending

    def cancel(self) -> None:
        self._cancelled.set()

    @QtCore.Slot()
    def run(self) -> None:
        try:
            self._collect()
        except Exception as exc:
            self.output.emit(f"Error: {exc}")
        finally:
            self.finished.emit()

    def _load_process_map(self) -> Dict[str, str]:
        process_map: Dict[str, str] = {}
        try:
            proc = subprocess.run(
                ["tasklist", "/fo", "csv", "/nh"],
                capture_output=True,
                text=True,
                timeout=10.0,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
            out = proc.stdout or ""
            reader = csv.reader(out.splitlines())
            for row in reader:
                if len(row) < 2:
                    continue
                image_name = row[0].strip()
                pid = row[1].strip()
                if pid and image_name:
                    process_map[pid] = image_name
        except Exception:
            return process_map
        return process_map

    def _split_endpoint(self, endpoint: str) -> Tuple[str, str]:
        endpoint = endpoint.strip()
        if not endpoint:
            return ("", "")

        if endpoint.startswith("[") and "]" in endpoint:
            # IPv6 form: [addr]:port
            idx = endpoint.rfind("]")
            host = endpoint[1:idx]
            port = endpoint[idx + 2:] if endpoint[idx + 1:idx + 2] == ":" else ""
            return (host, port)

        if endpoint.count(":") >= 2:
            # Likely IPv6 without brackets; split on the last colon.
            host, _sep, port = endpoint.rpartition(":")
            return (host, port)

        host, _sep, port = endpoint.rpartition(":")
        if not host and endpoint:
            return (endpoint, "")
        return (host, port)

    def _collect(self) -> None:
        self.output.emit("=== Active Connections Viewer ===")
        self.output.emit(f"Collected: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        self.output.emit("")

        is_windows = platform.system().lower() == "windows"
        if is_windows:
            cmd = ["netstat", "-ano"]
        else:
            cmd = ["ss", "-tunp"]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=20.0,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
        except FileNotFoundError:
            self.output.emit(f"Command not found: {' '.join(cmd)}")
            return
        except subprocess.TimeoutExpired:
            self.output.emit(f"{' '.join(cmd)} timed out.")
            return

        raw = (proc.stdout or "").strip()
        err = (proc.stderr or "").strip()
        if not raw and err:
            self.output.emit(err)
            return
        if not raw:
            self.output.emit("No active connections returned.")
            return

        entries: List[Tuple[str, str, str, str, str, str]] = []
        # destination, remote, port, state, pid, process_name
        process_map = self._load_process_map() if is_windows else {}

        if is_windows:
            for line in raw.splitlines():
                if self._cancelled.is_set():
                    self.output.emit("Cancelled.")
                    return
                stripped = line.strip()
                if not stripped:
                    continue
                if stripped.lower().startswith("proto"):
                    continue
                if stripped.lower().startswith("active connections"):
                    continue

                parts = stripped.split()
                if len(parts) < 4:
                    continue

                proto = parts[0].upper()
                if proto not in ("TCP", "UDP"):
                    continue

                if proto == "TCP":
                    if len(parts) < 5:
                        continue
                    local = parts[1]
                    remote = parts[2]
                    state = parts[3]
                    pid = parts[4]
                else:
                    # UDP has no state column in netstat -ano output.
                    local = parts[1]
                    remote = parts[2] if len(parts) > 3 else "*:*"
                    state = "UDP"
                    pid = parts[-1]

                _local_host, local_port = self._split_endpoint(local)
                _remote_host, remote_port = self._split_endpoint(remote)
                display_port = local_port or remote_port or ""
                process_name = process_map.get(pid, "")
                entries.append((local, remote, display_port, state, pid, process_name))
        else:
            # Best-effort parser for `ss -tunp` output.
            for line in raw.splitlines():
                if self._cancelled.is_set():
                    self.output.emit("Cancelled.")
                    return
                stripped = line.strip()
                if not stripped:
                    continue
                if stripped.lower().startswith("netid"):
                    continue
                parts = stripped.split()
                if len(parts) < 5:
                    continue

                state = parts[0]
                local = parts[3]
                remote = parts[4]
                pid = ""
                process_name = ""
                proc_match = re.search(r"pid=(\d+)", stripped)
                if proc_match:
                    pid = proc_match.group(1)
                pname_match = re.search(r'"([^\"]+)"', stripped)
                if pname_match:
                    process_name = pname_match.group(1)
                _local_host, local_port = self._split_endpoint(local)
                _remote_host, remote_port = self._split_endpoint(remote)
                display_port = local_port or remote_port or ""
                entries.append((local, remote, display_port, state, pid, process_name))

        if not entries:
            self.output.emit("No parseable connection entries found.")
            self.output.emit("")
            self.output.emit("Raw output:")
            self.output.emit(raw)
            return

        total_entries = len(entries)

        if self.state_filter == "listening":
            entries = [entry for entry in entries if entry[3].lower() in ("listening", "listen")]
        elif self.state_filter == "established":
            entries = [entry for entry in entries if entry[3].lower() == "established"]

        if self.port_filter:
            entries = [
                entry for entry in entries
                if self.port_filter in entry[2].lower()
                or self.port_filter in entry[0].lower()
                or self.port_filter in entry[1].lower()
            ]

        if self.process_filter:
            entries = [
                entry for entry in entries
                if self.process_filter in entry[4].lower()
                or self.process_filter in entry[5].lower()
            ]

        if self.sort_by == "local":
            def sort_key(entry: Tuple[str, str, str, str, str, str]) -> object:
                return entry[0].lower()
        elif self.sort_by == "remote":
            def sort_key(entry: Tuple[str, str, str, str, str, str]) -> object:
                return entry[1].lower()
        elif self.sort_by == "port":
            def sort_key(entry: Tuple[str, str, str, str, str, str]) -> Tuple[int, object]:
                try:
                    return (0, int(entry[2]))
                except ValueError:
                    return (1, entry[2].lower())
        elif self.sort_by == "state":
            def sort_key(entry: Tuple[str, str, str, str, str, str]) -> object:
                return entry[3].lower()
        elif self.sort_by == "pid":
            def sort_key(entry: Tuple[str, str, str, str, str, str]) -> Tuple[int, object]:
                try:
                    return (0, int(entry[4]))
                except ValueError:
                    return (1, entry[4].lower())
        elif self.sort_by == "process":
            def sort_key(entry: Tuple[str, str, str, str, str, str]) -> object:
                return entry[5].lower()
        else:
            def sort_key(entry: Tuple[str, str, str, str, str, str]) -> object:
                return entry[0].lower()

        entries.sort(key=sort_key, reverse=self.descending)

        order_text = "descending" if self.descending else "ascending"
        state_text = self.state_filter if self.state_filter else "all"
        port_text = self.port_filter if self.port_filter else "(all)"
        process_text = self.process_filter if self.process_filter else "(all)"
        self.output.emit(f"Filter state:     {state_text}")
        self.output.emit(f"Filter port:      {port_text}")
        self.output.emit(f"Filter process:   {process_text}")
        self.output.emit(f"Sort:             {self.sort_by} ({order_text})")
        self.output.emit(f"Entries:          {len(entries)} shown / {total_entries} total")
        self.output.emit("")

        if not entries:
            self.output.emit("No active connections matched the current filters.")
            return

        local_w = max(len("Local Address"), *(len(e[0]) for e in entries))
        remote_w = max(len("Remote Address"), *(len(e[1]) for e in entries))
        port_w = max(len("Port"), *(len(e[2]) for e in entries))
        state_w = max(len("State"), *(len(e[3]) for e in entries))
        pid_w = max(len("PID"), *(len(e[4]) for e in entries))
        proc_w = max(len("Process"), *(len(e[5]) for e in entries))

        header = (
            f"{'Local Address':<{local_w}}  {'Remote Address':<{remote_w}}  {'Port':<{port_w}}  "
            f"{'State':<{state_w}}  {'PID':<{pid_w}}  {'Process':<{proc_w}}"
        )
        self.output.emit(header)
        self.output.emit("-" * len(header))

        for local, remote, port, state, pid, process in entries:
            self.output.emit(
                f"{local:<{local_w}}  {remote:<{remote_w}}  {port:<{port_w}}  "
                f"{state:<{state_w}}  {pid:<{pid_w}}  {process:<{proc_w}}"
            )


class BandwidthMonitorWorker(QtCore.QObject):
    output = QtCore.Signal(str)
    finished = QtCore.Signal()

    def __init__(
        self,
        adapter_filter: str = "",
        active_only: bool = False,
        interval_seconds: float = 1.0,
        sort_by: str = "recv_mbps",
        descending: bool = True,
    ) -> None:
        super().__init__()
        self._cancelled = threading.Event()
        self.adapter_filter = adapter_filter.strip().lower()
        self.active_only = active_only
        self.interval_seconds = max(0.5, interval_seconds)
        self.sort_by = sort_by.strip().lower()
        self.descending = descending

    def cancel(self) -> None:
        self._cancelled.set()

    @QtCore.Slot()
    def run(self) -> None:
        try:
            self._monitor_loop()
        except Exception as exc:
            self.output.emit(f"Error: {exc}")
        finally:
            self.finished.emit()

    def _query_windows_stats(self) -> List[Tuple[str, float, float, int, int, int, float]]:
        ps_cmd = (
            "Get-CimInstance Win32_PerfRawData_Tcpip_NetworkInterface | "
            "Select-Object Name,BytesSentPersec,BytesReceivedPersec,PacketsSentPersec,"
            "PacketsReceivedPersec,PacketsOutboundErrors,PacketsReceivedErrors,CurrentBandwidth | "
            "ConvertTo-Csv -NoTypeInformation"
        )

        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=15.0,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )

        out = (proc.stdout or "").strip()
        err = (proc.stderr or "").strip()
        if not out:
            if err:
                raise RuntimeError(err)
            raise RuntimeError("No adapter stats returned.")

        rows: List[Tuple[str, float, float, int, int, int, float]] = []
        reader = csv.DictReader(out.splitlines())
        for row in reader:
            name = (row.get("Name") or "").strip()
            if not name:
                continue

            try:
                bytes_sent_per_sec = float(row.get("BytesSentPersec") or 0.0)
            except ValueError:
                bytes_sent_per_sec = 0.0
            try:
                bytes_recv_per_sec = float(row.get("BytesReceivedPersec") or 0.0)
            except ValueError:
                bytes_recv_per_sec = 0.0
            try:
                pkts_sent_per_sec = int(float(row.get("PacketsSentPersec") or 0.0))
            except ValueError:
                pkts_sent_per_sec = 0
            try:
                pkts_recv_per_sec = int(float(row.get("PacketsReceivedPersec") or 0.0))
            except ValueError:
                pkts_recv_per_sec = 0

            try:
                out_err = int(float(row.get("PacketsOutboundErrors") or 0.0))
            except ValueError:
                out_err = 0
            try:
                in_err = int(float(row.get("PacketsReceivedErrors") or 0.0))
            except ValueError:
                in_err = 0
            errors = max(0, out_err) + max(0, in_err)

            try:
                current_bandwidth_bps = float(row.get("CurrentBandwidth") or 0.0)
            except ValueError:
                current_bandwidth_bps = 0.0

            sent_mbps = (bytes_sent_per_sec * 8.0) / 1_000_000.0
            recv_mbps = (bytes_recv_per_sec * 8.0) / 1_000_000.0
            speed_mbps = current_bandwidth_bps / 1_000_000.0

            rows.append((name, sent_mbps, recv_mbps, pkts_sent_per_sec, pkts_recv_per_sec, errors, speed_mbps))

        return rows

    def _monitor_loop(self) -> None:
        self.output.emit("=== Bandwidth / Interface Monitor ===")
        self.output.emit("Press Cancel to stop live monitoring.")
        self.output.emit("")

        if platform.system().lower() != "windows":
            self.output.emit("This implementation currently uses Windows adapter counters.")
            self.output.emit("On non-Windows systems, consider adding an `ip -s link` parser.")
            return

        sample_no = 1
        while not self._cancelled.is_set():
            try:
                entries = self._query_windows_stats()
            except Exception as exc:
                self.output.emit(f"Sample {sample_no}: {exc}")
                entries = []

            total_entries = len(entries)

            if self.adapter_filter:
                entries = [entry for entry in entries if self.adapter_filter in entry[0].lower()]

            if self.active_only:
                entries = [
                    entry for entry in entries
                    if entry[1] > 0.0 or entry[2] > 0.0 or entry[3] > 0 or entry[4] > 0
                ]

            if self.sort_by == "name":
                entries.sort(key=lambda entry: entry[0].lower(), reverse=self.descending)
            elif self.sort_by == "sent_mbps":
                entries.sort(key=lambda entry: entry[1], reverse=self.descending)
            elif self.sort_by == "recv_mbps":
                entries.sort(key=lambda entry: entry[2], reverse=self.descending)
            elif self.sort_by == "speed_mbps":
                entries.sort(key=lambda entry: entry[6], reverse=self.descending)
            elif self.sort_by == "errors":
                entries.sort(key=lambda entry: entry[5], reverse=self.descending)

            order_text = "descending" if self.descending else "ascending"
            self.output.emit(f"Sample {sample_no}  @  {time.strftime('%H:%M:%S')}")
            self.output.emit(
                f"Filter adapter: {self.adapter_filter or '(all)'}   Active only: {'yes' if self.active_only else 'no'}"
            )
            self.output.emit(
                f"Sort: {self.sort_by} ({order_text})   Entries: {len(entries)} shown / {total_entries} total"
            )

            if entries:
                name_w = max(len("Adapter"), *(len(e[0]) for e in entries))
                sent_w = len("Sent Mbps")
                recv_w = len("Recv Mbps")
                ps_w = len("Pkt Sent/s")
                pr_w = len("Pkt Recv/s")
                err_w = len("Errors")
                spd_w = len("Link Mbps")

                header = (
                    f"{'Adapter':<{name_w}}  {'Sent Mbps':>{sent_w}}  {'Recv Mbps':>{recv_w}}  "
                    f"{'Pkt Sent/s':>{ps_w}}  {'Pkt Recv/s':>{pr_w}}  {'Errors':>{err_w}}  {'Link Mbps':>{spd_w}}"
                )
                self.output.emit(header)
                self.output.emit("-" * len(header))

                for name, sent_mbps, recv_mbps, pkt_sent, pkt_recv, errors, speed_mbps in entries:
                    self.output.emit(
                        f"{name:<{name_w}}  {sent_mbps:>{sent_w}.3f}  {recv_mbps:>{recv_w}.3f}  "
                        f"{pkt_sent:>{ps_w}}  {pkt_recv:>{pr_w}}  {errors:>{err_w}}  {speed_mbps:>{spd_w}.1f}"
                    )
            else:
                self.output.emit("No adapters matched current filters.")

            self.output.emit("")
            sample_no += 1

            sleep_steps = max(1, int(self.interval_seconds * 10))
            for _ in range(sleep_steps):
                if self._cancelled.is_set():
                    self.output.emit("Cancelled.")
                    return
                time.sleep(0.1)


class SubnetCalculatorWorker(QtCore.QObject):
    output = QtCore.Signal(str)
    finished = QtCore.Signal()

    def __init__(self, value_text: str, mask_text: str = "") -> None:
        super().__init__()
        self.value_text = value_text.strip()
        self.mask_text = mask_text.strip()
        self._cancelled = threading.Event()

    def cancel(self) -> None:
        self._cancelled.set()

    @QtCore.Slot()
    def run(self) -> None:
        try:
            self._calculate()
        except Exception as exc:
            self.output.emit(f"Error: {exc}")
        finally:
            self.finished.emit()

    def _binary(self, value: int) -> str:
        return ".".join(f"{part:08b}" for part in value.to_bytes(4, byteorder="big"))

    def _format_ip(self, value: ipaddress._BaseAddress) -> str:  # type: ignore[attr-defined]
        return str(value)

    def _calculate(self) -> None:
        self.output.emit("=== Subnet Calculator ===")
        self.output.emit(f"Collected: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        self.output.emit("")

        if self._cancelled.is_set():
            self.output.emit("Cancelled.")
            return

        if not self.value_text:
            raise ValueError("Enter a CIDR such as 192.168.1.25/24 or an IP address with subnet mask.")

        cidr_text = self.value_text
        reverse_mode = False

        if self.mask_text:
            reverse_mode = True
            cidr_text = f"{self.value_text}/{self.mask_text}"
        elif "/" in self.value_text:
            reverse_mode = False
        else:
            raise ValueError("Enter a CIDR (192.168.1.25/24) or provide a subnet mask for reverse calculation.")

        try:
            interface = ipaddress.ip_interface(cidr_text)
        except ValueError as exc:
            raise ValueError(f"Invalid subnet input: {exc}") from exc

        network = interface.network
        ip_addr = interface.ip
        if network.version != 4:
            raise ValueError("IPv6 is not supported by this subnet calculator yet.")
        mask = network.netmask
        wildcard = network.hostmask
        broadcast = network.broadcast_address

        if network.version == 4:
            total_addresses = network.num_addresses
            usable_hosts = max(0, total_addresses - 2)
            if network.prefixlen >= 31:
                usable_hosts = total_addresses
            if usable_hosts == 0 and total_addresses > 0:
                usable_hosts = total_addresses
            first_usable = None
            last_usable = None
            if total_addresses >= 2 and network.prefixlen < 31:
                first_usable = network.network_address + 1
                last_usable = network.broadcast_address - 1
            elif network.prefixlen == 31:
                first_usable = network.network_address
                last_usable = network.broadcast_address
            elif network.prefixlen == 32:
                first_usable = network.network_address
                last_usable = network.network_address
        else:
            total_addresses = network.num_addresses
            usable_hosts = total_addresses
            first_usable = network.network_address
            last_usable = network.broadcast_address

        self.output.emit(f"Input mode:       {'Reverse IP + mask' if reverse_mode else 'CIDR'}")
        self.output.emit(f"Input value:      {self.value_text}")
        if reverse_mode:
            self.output.emit(f"Subnet mask:      {self.mask_text}")
        self.output.emit("")

        self.output.emit(f"IP address:       {ip_addr}")
        self.output.emit(f"Network address:  {network.network_address}")
        self.output.emit(f"Broadcast address: {broadcast}")
        if first_usable is not None and last_usable is not None:
            self.output.emit(f"Usable range:     {first_usable} - {last_usable}")
        else:
            self.output.emit("Usable range:     (not applicable)")
        self.output.emit(f"Subnet mask:      {mask}   /{network.prefixlen}")
        self.output.emit(f"Wildcard mask:    {wildcard}")
        self.output.emit(f"Usable hosts:     {usable_hosts}")
        self.output.emit("")

        self.output.emit("Binary view:")
        self.output.emit(f"  IP:             {self._binary(int(ip_addr))}")
        self.output.emit(f"  Network:        {self._binary(int(network.network_address))}")
        self.output.emit(f"  Broadcast:      {self._binary(int(broadcast))}")
        self.output.emit(f"  Netmask:        {self._binary(int(mask))}")
        self.output.emit(f"  Wildcard:       {self._binary(int(wildcard))}")

        if reverse_mode:
            self.output.emit("")
            self.output.emit(f"CIDR:             {network.network_address}/{network.prefixlen}")


class MtuTestWorker(QtCore.QObject):
    output = QtCore.Signal(str)
    finished = QtCore.Signal()

    def __init__(self, target: str, max_payload: int = 1472) -> None:
        super().__init__()
        self.target = target.strip()
        self.max_payload = max(0, min(int(max_payload), 1472))
        self._cancelled = threading.Event()

    def cancel(self) -> None:
        self._cancelled.set()

    @QtCore.Slot()
    def run(self) -> None:
        try:
            self._probe()
        except Exception as exc:
            self.output.emit(f"Error: {exc}")
        finally:
            self.finished.emit()

    def _ping_once(self, payload: int) -> Tuple[bool, str]:
        cmd = ["ping", "-4", "-n", "1", "-w", "1200", "-f", "-l", str(payload), self.target]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15.0,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )
        output = (proc.stdout or "") + (proc.stderr or "")
        lower = output.lower()
        success = proc.returncode == 0 and "reply from" in lower
        if not success and ("fragmented" in lower or "packet needs to be fragmented" in lower):
            return False, "fragmentation needed"
        if not success and "timed out" in lower:
            return False, "timed out"
        if not success and "could not find host" in lower:
            return False, "host not found"
        if success:
            return True, "success"
        return False, output.strip().splitlines()[-1].strip() if output.strip() else "failed"

    def _probe(self) -> None:
        self.output.emit(f"=== MTU / Fragmentation Test: {self.target} ===")
        self.output.emit("Using Windows ping with DF set: ping -4 -f -l <payload>")
        self.output.emit("")

        if not self.target:
            raise ValueError("Enter a target host or IP address.")

        low = 0
        high = self.max_payload
        largest_success = -1
        first_failure = None
        failure_reason = ""

        self.output.emit(f"Search range: 0 to {high} bytes payload")
        self.output.emit("")

        while low <= high:
            if self._cancelled.is_set():
                self.output.emit("Cancelled.")
                return
            mid = (low + high) // 2
            self.output.emit(f"Probing {mid} bytes ...")
            ok, reason = self._ping_once(mid)
            if ok:
                largest_success = mid
                low = mid + 1
                self.output.emit(f"  OK")
            else:
                first_failure = mid if first_failure is None else min(first_failure, mid)
                failure_reason = reason
                high = mid - 1
                self.output.emit(f"  FAIL ({reason})")

        self.output.emit("")
        if largest_success < 0:
            self.output.emit("Largest successful payload: none")
            self.output.emit("Estimated path MTU:        unavailable")
            self.output.emit(f"Failure point:             {first_failure if first_failure is not None else 'unknown'} bytes ({failure_reason})")
            return

        estimated_mtu = largest_success + 28
        self.output.emit(f"Largest successful payload: {largest_success} bytes")
        self.output.emit(f"Estimated path MTU:        {estimated_mtu} bytes")
        if first_failure is not None and first_failure > largest_success:
            self.output.emit(f"Failure point:             {first_failure} bytes ({failure_reason})")
        else:
            self.output.emit(f"Failure point:             {largest_success + 1} bytes (first size expected to fragment or fail)")

        self.output.emit("")
        self.output.emit("Tip: if the largest success is much lower than 1472, a VPN, tunnel, or PPPoE hop may be reducing MTU.")

class TlsInspectorWorker(QtCore.QObject):
    output = QtCore.Signal(str)
    finished = QtCore.Signal()

    TIMEOUT = 8.0

    def __init__(self, host: str, port: int) -> None:
        super().__init__()
        self.host = host
        self.port = port
        self._cancelled = threading.Event()

    def cancel(self) -> None:
        self._cancelled.set()

    def _decode_der_cert(self, der_cert: bytes) -> tuple[Dict[str, object], str]:
        """Decode a DER certificate into a dict shape similar to getpeercert()."""
        import ssl
        import tempfile
        import os

        if not der_cert:
            return {}, ""

        pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
        cert_info: Dict[str, object] = {}

        # _test_decode_cert is private but provides rich parsed cert details from PEM.
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".pem", encoding="utf-8") as tmp:
            tmp.write(pem_cert)
            tmp_path = tmp.name
        try:
            cert_info = ssl._ssl._test_decode_cert(tmp_path)  # type: ignore[attr-defined]
        except Exception:
            cert_info = {}
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

        return cert_info or {}, pem_cert

    def _match_hostname_from_cert(self, cert: Dict[str, object], host: str) -> Tuple[bool, str]:
        """Best-effort hostname/IP match using SAN first, then CN fallback."""
        host_l = (host or "").strip().lower()
        if not host_l:
            return False, "empty target host"

        def _dns_match(pattern: str, value: str) -> bool:
            p = (pattern or "").strip().lower()
            v = (value or "").strip().lower()
            if not p or not v:
                return False
            if p == v:
                return True
            if p.startswith("*."):
                suffix = p[1:]  # includes leading dot
                # Only match a single label wildcard (e.g. *.example.com -> a.example.com)
                return v.endswith(suffix) and v.count(".") == p.count(".")
            return False

        san_entries = cert.get("subjectAltName", ()) or ()
        dns_sans = [str(v) for t, v in san_entries if str(t).upper() == "DNS"]
        ip_sans = [str(v) for t, v in san_entries if str(t).upper() == "IP ADDRESS"]

        host_ip: Optional[ipaddress._BaseAddress]
        try:
            host_ip = ipaddress.ip_address(host_l)
        except ValueError:
            host_ip = None

        if host_ip is not None:
            for ip_san in ip_sans:
                try:
                    if host_ip == ipaddress.ip_address(ip_san.strip()):
                        return True, f"matched IP SAN: {ip_san}"
                except ValueError:
                    continue
            if ip_sans:
                return False, f"target IP {host} not present in IP SANs"
            return False, "target is an IP but certificate has no IP SAN entries"

        for dns_san in dns_sans:
            if _dns_match(dns_san, host_l):
                return True, f"matched DNS SAN: {dns_san}"
        if dns_sans:
            return False, f"host {host} not present in DNS SANs"

        # CN fallback only when SANs are absent.
        cn = ""
        for rdn in cert.get("subject", ()) or ():
            for k, v in rdn:
                if k == "commonName":
                    cn = str(v)
                    break
            if cn:
                break

        if cn and _dns_match(cn, host_l):
            return True, f"matched Common Name: {cn}"
        if cn:
            return False, f"host {host} does not match Common Name {cn}"
        return False, "certificate has no SAN and no Common Name"

    @QtCore.Slot()
    def run(self) -> None:
        try:
            self._do_inspect()
        except Exception as exc:
            self.output.emit(f"Error: {exc}")
        finally:
            self.finished.emit()

    def _do_inspect(self) -> None:
        import ssl
        import datetime

        self.output.emit(f"=== TLS/SSL Certificate Inspector: {self.host}:{self.port} ===")
        self.output.emit("")

        # Resolve first
        self.output.emit(f"Resolving {self.host!r} ...")
        try:
            infos = socket.getaddrinfo(self.host, self.port, type=socket.SOCK_STREAM)
            resolved_ip = infos[0][4][0]
            self.output.emit(f"  Resolved IP:  {resolved_ip}")
        except socket.gaierror as exc:
            self.output.emit(f"  DNS resolution failed: {exc}")
            return
        self.output.emit("")

        if self._cancelled.is_set():
            self.output.emit("Cancelled.")
            return

        ctx = ssl.create_default_context()
        cert: Dict[str, object] = {}
        cert_pem = ""
        tls_version = ""
        cipher_name = ""
        cipher_bits = ""
        verification_ok = True
        verify_code: Optional[int] = None
        verify_message = ""

        self.output.emit(f"Connecting (TLS) to {self.host}:{self.port} ...")
        try:
            with socket.create_connection((self.host, self.port), timeout=self.TIMEOUT) as raw:
                with ctx.wrap_socket(raw, server_hostname=self.host) as tls:
                    cert = tls.getpeercert() or {}
                    cert_der = tls.getpeercert(binary_form=True)
                    if cert_der:
                        decoded, pem = self._decode_der_cert(cert_der)
                        if decoded:
                            cert = decoded
                        cert_pem = pem
                    tls_version = tls.version() or ""
                    cipher_info = tls.cipher()          # (name, proto, bits)
                    if cipher_info:
                        cipher_name = cipher_info[0] or ""
                        cipher_bits = str(cipher_info[2]) if cipher_info[2] else ""
        except ssl.SSLCertVerificationError as exc:
            verification_ok = False
            verify_code = getattr(exc, "verify_code", None)
            verify_message = getattr(exc, "verify_message", "") or str(exc)
            self.output.emit(f"  TLS verification failed: {exc}")
            if verify_code is not None:
                self.output.emit(f"  Verification code: {verify_code}")
            if verify_message:
                self.output.emit(f"  Verification reason: {verify_message}")
            self.output.emit("  (Attempting without verification to retrieve certificate info...)")
            self.output.emit("")
            ctx_noverify = ssl.create_default_context()
            ctx_noverify.check_hostname = False
            ctx_noverify.verify_mode = ssl.CERT_NONE
            try:
                with socket.create_connection((self.host, self.port), timeout=self.TIMEOUT) as raw:
                    with ctx_noverify.wrap_socket(raw, server_hostname=self.host) as tls:
                        cert_der = tls.getpeercert(binary_form=True)
                        cert, cert_pem = self._decode_der_cert(cert_der)
                        tls_version = tls.version() or ""
                        cipher_info = tls.cipher()
                        if cipher_info:
                            cipher_name = cipher_info[0] or ""
                            cipher_bits = str(cipher_info[2]) if cipher_info[2] else ""
            except Exception as exc2:
                self.output.emit(f"  Could not retrieve certificate: {exc2}")
                return
        except socket.timeout:
            self.output.emit(f"  Connection timed out after {self.TIMEOUT:.0f}s")
            return
        except OSError as exc:
            self.output.emit(f"  Connection error: {exc}")
            return

        if not cert:
            self.output.emit("  No certificate data returned.")
            if cert_pem:
                self.output.emit("")
                self.output.emit("Raw PEM certificate:")
                self.output.emit(cert_pem)
            return

        self.output.emit("")

        # --- Connection info ---
        self.output.emit(f"TLS version:      {tls_version}")
        bits_label = f"  ({cipher_bits}-bit)" if cipher_bits else ""
        self.output.emit(f"Cipher suite:     {cipher_name}{bits_label}")
        if verification_ok:
            self.output.emit("Certificate verify: PASS")
        else:
            self.output.emit("Certificate verify: FAIL")
            if verify_code is not None:
                self.output.emit(f"  Verify code:    {verify_code}")
            if verify_message:
                self.output.emit(f"  Verify reason:  {verify_message}")
        self.output.emit("")

        # --- Subject ---
        subject_parts = [v for rdn in cert.get("subject", ()) for _, v in rdn]
        subject_rdns = {k: v for rdn in cert.get("subject", ()) for k, v in rdn}
        self.output.emit(f"Subject:          {', '.join(subject_parts)}")
        if "commonName" in subject_rdns:
            self.output.emit(f"  Common Name:  {subject_rdns['commonName']}")
        if "organizationName" in subject_rdns:
            self.output.emit(f"  Org:          {subject_rdns['organizationName']}")
        if "countryName" in subject_rdns:
            self.output.emit(f"  Country:      {subject_rdns['countryName']}")
        self.output.emit("")

        # --- Issuer ---
        issuer_rdns = {k: v for rdn in cert.get("issuer", ()) for k, v in rdn}
        issuer_parts = [v for rdn in cert.get("issuer", ()) for _, v in rdn]
        self.output.emit(f"Issuer:           {', '.join(issuer_parts)}")
        if "organizationName" in issuer_rdns:
            self.output.emit(f"  Org:          {issuer_rdns['organizationName']}")
        if "commonName" in issuer_rdns:
            self.output.emit(f"  Common Name:  {issuer_rdns['commonName']}")
        self.output.emit("")

        # --- Validity ---
        not_before_str = cert.get("notBefore", "")
        not_after_str  = cert.get("notAfter", "")
        fmt = "%b %d %H:%M:%S %Y %Z"
        not_before: Optional[datetime.datetime] = None
        not_after: Optional[datetime.datetime] = None
        now = datetime.datetime.utcnow()
        try:
            not_before = datetime.datetime.strptime(not_before_str, fmt)
            not_after  = datetime.datetime.strptime(not_after_str, fmt)
            days_left = (not_after - now).days
            flag = ""
            if days_left < 0:
                flag = "  ✗ EXPIRED"
            elif days_left < 30:
                flag = "  ⚠ EXPIRING SOON"
            self.output.emit(f"Valid from:       {not_before.strftime('%Y-%m-%d %H:%M UTC')}")
            self.output.emit(f"Valid until:      {not_after.strftime('%Y-%m-%d %H:%M UTC')}  ({days_left}d remaining){flag}")
        except Exception:
            self.output.emit(f"Valid from:       {not_before_str}")
            self.output.emit(f"Valid until:      {not_after_str}")
        self.output.emit("")

        # --- SANs ---
        sans = cert.get("subjectAltName", ())
        if sans:
            self.output.emit("Subject Alt Names (SAN):")
            for san_type, san_val in sans:
                self.output.emit(f"  {san_type}: {san_val}")
        else:
            self.output.emit("Subject Alt Names: (none)")

        # --- Diagnostics ---
        self.output.emit("")
        self.output.emit("Diagnostics:")

        # Hostname coverage check gives a concrete reason for many validation failures.
        host_ok, host_reason = self._match_hostname_from_cert(cert, self.host)
        host_status = "PASS" if host_ok else "FAIL"
        self.output.emit(f"  Hostname check: {host_status} ({host_reason})")

        subject_pairs = sorted((k, v) for rdn in cert.get("subject", ()) for k, v in rdn)
        issuer_pairs = sorted((k, v) for rdn in cert.get("issuer", ()) for k, v in rdn)
        if subject_pairs and issuer_pairs and subject_pairs == issuer_pairs:
            self.output.emit("  Chain hint: certificate appears self-signed (subject == issuer)")

        if not sans:
            self.output.emit("  SAN check: no SAN entries present; modern clients generally require SAN")

        if not_before and now < not_before:
            self.output.emit("  Time validity: certificate is not yet valid")
        elif not_after and now > not_after:
            self.output.emit("  Time validity: certificate is expired")
        elif not_before and not_after:
            self.output.emit("  Time validity: certificate is currently within validity window")
        else:
            self.output.emit("  Time validity: unable to parse notBefore/notAfter fields")

        if not verification_ok and cert_pem:
            self.output.emit("")
            self.output.emit("Raw PEM certificate (verification failed):")
            self.output.emit(cert_pem)


class ToolsTab(QtWidgets.QWidget):
    def __init__(self) -> None:
        super().__init__()
        self._worker: Optional[QtCore.QObject] = None
        self._worker_thread: Optional[QtCore.QThread] = None
        self._build_ui()

    def _build_ui(self) -> None:
        root = QtWidgets.QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        controls = QtWidgets.QHBoxLayout()
        controls.setSpacing(8)

        controls.addWidget(QtWidgets.QLabel("Tool:"))
        self.tool_combo = QtWidgets.QComboBox()
        self.tool_combo.addItem("DNS Lookup")
        self.tool_combo.addItem("DNS Propagation")
        self.tool_combo.addItem("WHOIS Lookup")
        self.tool_combo.addItem("Port Check")
        self.tool_combo.addItem("HTTP Check")
        self.tool_combo.addItem("TLS Inspector")
        self.tool_combo.addItem("Local Network Info")
        self.tool_combo.addItem("ARP Table Viewer")
        self.tool_combo.addItem("Route Table Viewer")
        self.tool_combo.addItem("Active Connections")
        self.tool_combo.addItem("Bandwidth Monitor")
        self.tool_combo.addItem("Subnet Calculator")
        self.tool_combo.addItem("MTU / Fragmentation Test")
        self.tool_combo.currentIndexChanged.connect(self._on_tool_changed)
        controls.addWidget(self.tool_combo)

        self.target_label = QtWidgets.QLabel("Target:")
        controls.addWidget(self.target_label)
        self.target_edit = QtWidgets.QLineEdit()
        self.target_edit.setPlaceholderText("hostname or IP address")
        self.target_edit.setMinimumWidth(280)
        self.target_edit.returnPressed.connect(self._run_tool)
        controls.addWidget(self.target_edit)

        self.dns_type_label = QtWidgets.QLabel("Record type:")
        controls.addWidget(self.dns_type_label)
        self.dns_type_combo = QtWidgets.QComboBox()
        for rtype in ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR"]:
            self.dns_type_combo.addItem(rtype)
        controls.addWidget(self.dns_type_combo)

        self.dns_prop_type_label = QtWidgets.QLabel("Prop type:")
        controls.addWidget(self.dns_prop_type_label)
        self.dns_prop_type_combo = QtWidgets.QComboBox()
        for rtype in ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR"]:
            self.dns_prop_type_combo.addItem(rtype)
        controls.addWidget(self.dns_prop_type_combo)

        self.dns_filter_label = QtWidgets.QLabel("DNS filter:")
        controls.addWidget(self.dns_filter_label)
        self.dns_filter_edit = QtWidgets.QLineEdit()
        self.dns_filter_edit.setPlaceholderText("contains text (optional)")
        self.dns_filter_edit.setFixedWidth(170)
        self.dns_filter_edit.returnPressed.connect(self._run_tool)
        controls.addWidget(self.dns_filter_edit)

        self.dns_order_label = QtWidgets.QLabel("DNS sort:")
        controls.addWidget(self.dns_order_label)
        self.dns_order_combo = QtWidgets.QComboBox()
        self.dns_order_combo.addItem("Ascending", False)
        self.dns_order_combo.addItem("Descending", True)
        controls.addWidget(self.dns_order_combo)

        self.port_label = QtWidgets.QLabel("Port:")
        controls.addWidget(self.port_label)
        self.port_edit = QtWidgets.QLineEdit()
        self.port_edit.setPlaceholderText("443")
        self.port_edit.setFixedWidth(60)
        self.port_edit.returnPressed.connect(self._run_tool)
        controls.addWidget(self.port_edit)

        self.port_preset_label = QtWidgets.QLabel("Common:")
        controls.addWidget(self.port_preset_label)
        self.port_preset_combo = QtWidgets.QComboBox()
        self.port_preset_combo.addItem("— select —", 0)
        for port_num, port_name in COMMON_PORTS:
            self.port_preset_combo.addItem(f"{port_num}  {port_name}", port_num)
        self.port_preset_combo.currentIndexChanged.connect(self._on_port_preset_changed)
        controls.addWidget(self.port_preset_combo)

        self.arp_iface_label = QtWidgets.QLabel("Interface:")
        controls.addWidget(self.arp_iface_label)
        self.arp_iface_edit = QtWidgets.QLineEdit()
        self.arp_iface_edit.setPlaceholderText("contains text (optional)")
        self.arp_iface_edit.setFixedWidth(170)
        self.arp_iface_edit.returnPressed.connect(self._run_tool)
        controls.addWidget(self.arp_iface_edit)

        self.arp_type_label = QtWidgets.QLabel("ARP type:")
        controls.addWidget(self.arp_type_label)
        self.arp_type_combo = QtWidgets.QComboBox()
        self.arp_type_combo.addItem("All", "all")
        self.arp_type_combo.addItem("Dynamic", "dynamic")
        self.arp_type_combo.addItem("Static", "static")
        self.arp_type_combo.addItem("Invalid", "invalid")
        controls.addWidget(self.arp_type_combo)

        self.arp_sort_label = QtWidgets.QLabel("Sort by:")
        controls.addWidget(self.arp_sort_label)
        self.arp_sort_combo = QtWidgets.QComboBox()
        self.arp_sort_combo.addItem("IP Address", "ip")
        self.arp_sort_combo.addItem("MAC Address", "mac")
        self.arp_sort_combo.addItem("Interface", "interface")
        self.arp_sort_combo.addItem("Type", "type")
        controls.addWidget(self.arp_sort_combo)

        self.arp_order_combo = QtWidgets.QComboBox()
        self.arp_order_combo.addItem("Ascending", False)
        self.arp_order_combo.addItem("Descending", True)
        controls.addWidget(self.arp_order_combo)

        self.route_iface_label = QtWidgets.QLabel("Route iface:")
        controls.addWidget(self.route_iface_label)
        self.route_iface_edit = QtWidgets.QLineEdit()
        self.route_iface_edit.setPlaceholderText("contains text (optional)")
        self.route_iface_edit.setFixedWidth(160)
        self.route_iface_edit.returnPressed.connect(self._run_tool)
        controls.addWidget(self.route_iface_edit)

        self.route_gateway_label = QtWidgets.QLabel("Gateway:")
        controls.addWidget(self.route_gateway_label)
        self.route_gateway_edit = QtWidgets.QLineEdit()
        self.route_gateway_edit.setPlaceholderText("contains text (optional)")
        self.route_gateway_edit.setFixedWidth(160)
        self.route_gateway_edit.returnPressed.connect(self._run_tool)
        controls.addWidget(self.route_gateway_edit)

        self.route_sort_label = QtWidgets.QLabel("Route sort:")
        controls.addWidget(self.route_sort_label)
        self.route_sort_combo = QtWidgets.QComboBox()
        self.route_sort_combo.addItem("Destination", "destination")
        self.route_sort_combo.addItem("Netmask", "netmask")
        self.route_sort_combo.addItem("Gateway", "gateway")
        self.route_sort_combo.addItem("Interface", "interface")
        self.route_sort_combo.addItem("Metric", "metric")
        controls.addWidget(self.route_sort_combo)

        self.route_order_combo = QtWidgets.QComboBox()
        self.route_order_combo.addItem("Ascending", False)
        self.route_order_combo.addItem("Descending", True)
        controls.addWidget(self.route_order_combo)

        self.conn_state_label = QtWidgets.QLabel("Conn state:")
        controls.addWidget(self.conn_state_label)
        self.conn_state_combo = QtWidgets.QComboBox()
        self.conn_state_combo.addItem("All", "all")
        self.conn_state_combo.addItem("Listening", "listening")
        self.conn_state_combo.addItem("Established", "established")
        controls.addWidget(self.conn_state_combo)

        self.conn_port_label = QtWidgets.QLabel("Port search:")
        controls.addWidget(self.conn_port_label)
        self.conn_port_edit = QtWidgets.QLineEdit()
        self.conn_port_edit.setPlaceholderText("e.g. 443")
        self.conn_port_edit.setFixedWidth(110)
        self.conn_port_edit.returnPressed.connect(self._run_tool)
        controls.addWidget(self.conn_port_edit)

        self.conn_process_label = QtWidgets.QLabel("Process search:")
        controls.addWidget(self.conn_process_label)
        self.conn_process_edit = QtWidgets.QLineEdit()
        self.conn_process_edit.setPlaceholderText("pid or name")
        self.conn_process_edit.setFixedWidth(140)
        self.conn_process_edit.returnPressed.connect(self._run_tool)
        controls.addWidget(self.conn_process_edit)

        self.conn_sort_label = QtWidgets.QLabel("Conn sort:")
        controls.addWidget(self.conn_sort_label)
        self.conn_sort_combo = QtWidgets.QComboBox()
        self.conn_sort_combo.addItem("Local", "local")
        self.conn_sort_combo.addItem("Remote", "remote")
        self.conn_sort_combo.addItem("Port", "port")
        self.conn_sort_combo.addItem("State", "state")
        self.conn_sort_combo.addItem("PID", "pid")
        self.conn_sort_combo.addItem("Process", "process")
        controls.addWidget(self.conn_sort_combo)

        self.conn_order_combo = QtWidgets.QComboBox()
        self.conn_order_combo.addItem("Ascending", False)
        self.conn_order_combo.addItem("Descending", True)
        controls.addWidget(self.conn_order_combo)

        self.bw_adapter_label = QtWidgets.QLabel("Adapter:")
        controls.addWidget(self.bw_adapter_label)
        self.bw_adapter_edit = QtWidgets.QLineEdit()
        self.bw_adapter_edit.setPlaceholderText("contains text (optional)")
        self.bw_adapter_edit.setFixedWidth(160)
        self.bw_adapter_edit.returnPressed.connect(self._run_tool)
        controls.addWidget(self.bw_adapter_edit)

        self.bw_active_label = QtWidgets.QLabel("Mode:")
        controls.addWidget(self.bw_active_label)
        self.bw_active_combo = QtWidgets.QComboBox()
        self.bw_active_combo.addItem("All adapters", False)
        self.bw_active_combo.addItem("Active only", True)
        controls.addWidget(self.bw_active_combo)

        self.bw_interval_label = QtWidgets.QLabel("Interval(s):")
        controls.addWidget(self.bw_interval_label)
        self.bw_interval_edit = QtWidgets.QLineEdit("1.0")
        self.bw_interval_edit.setFixedWidth(55)
        self.bw_interval_edit.returnPressed.connect(self._run_tool)
        controls.addWidget(self.bw_interval_edit)

        self.bw_sort_label = QtWidgets.QLabel("BW sort:")
        controls.addWidget(self.bw_sort_label)
        self.bw_sort_combo = QtWidgets.QComboBox()
        self.bw_sort_combo.addItem("Recv Mbps", "recv_mbps")
        self.bw_sort_combo.addItem("Sent Mbps", "sent_mbps")
        self.bw_sort_combo.addItem("Adapter", "name")
        self.bw_sort_combo.addItem("Errors", "errors")
        self.bw_sort_combo.addItem("Link Mbps", "speed_mbps")
        controls.addWidget(self.bw_sort_combo)

        self.bw_order_combo = QtWidgets.QComboBox()
        self.bw_order_combo.addItem("Descending", True)
        self.bw_order_combo.addItem("Ascending", False)
        controls.addWidget(self.bw_order_combo)

        self.subnet_value_label = QtWidgets.QLabel("Subnet input:")
        controls.addWidget(self.subnet_value_label)
        self.subnet_value_edit = QtWidgets.QLineEdit()
        self.subnet_value_edit.setPlaceholderText("192.168.1.25/24 or 192.168.1.25")
        self.subnet_value_edit.setFixedWidth(220)
        self.subnet_value_edit.returnPressed.connect(self._run_tool)
        controls.addWidget(self.subnet_value_edit)

        self.subnet_mask_label = QtWidgets.QLabel("Mask:")
        controls.addWidget(self.subnet_mask_label)
        self.subnet_mask_edit = QtWidgets.QLineEdit()
        self.subnet_mask_edit.setPlaceholderText("255.255.255.0 (optional)")
        self.subnet_mask_edit.setFixedWidth(145)
        self.subnet_mask_edit.returnPressed.connect(self._run_tool)
        controls.addWidget(self.subnet_mask_edit)

        self.subnet_mode_label = QtWidgets.QLabel("Mode:")
        controls.addWidget(self.subnet_mode_label)
        self.subnet_mode_combo = QtWidgets.QComboBox()
        self.subnet_mode_combo.addItem("Auto / CIDR", "auto")
        self.subnet_mode_combo.addItem("Reverse (IP + mask)", "reverse")
        controls.addWidget(self.subnet_mode_combo)

        self.mtu_payload_label = QtWidgets.QLabel("Max payload:")
        controls.addWidget(self.mtu_payload_label)
        self.mtu_payload_edit = QtWidgets.QLineEdit("1472")
        self.mtu_payload_edit.setFixedWidth(65)
        self.mtu_payload_edit.setToolTip("Maximum payload size to test before stopping the binary search")
        self.mtu_payload_edit.returnPressed.connect(self._run_tool)
        controls.addWidget(self.mtu_payload_edit)

        self.go_button = QtWidgets.QPushButton("Go")
        self.go_button.clicked.connect(self._run_tool)
        controls.addWidget(self.go_button)

        self.cancel_button = QtWidgets.QPushButton("Cancel")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self._cancel_tool)
        controls.addWidget(self.cancel_button)

        self.clear_button = QtWidgets.QPushButton("Clear")
        self.clear_button.clicked.connect(self.results_text.clear if hasattr(self, 'results_text') else lambda: None)
        controls.addWidget(self.clear_button)

        self.copy_button = QtWidgets.QPushButton("Copy")
        self.copy_button.clicked.connect(self._copy_rendered_output)
        controls.addWidget(self.copy_button)

        self.save_button = QtWidgets.QPushButton("Save HTML")
        self.save_button.clicked.connect(self._save_rendered_output)
        controls.addWidget(self.save_button)

        controls.addStretch(1)
        root.addLayout(controls)

        self.results_text = QtWidgets.QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setAcceptRichText(True)
        self.results_text.setUndoRedoEnabled(False)
        self.results_text.setLineWrapMode(QtWidgets.QTextEdit.NoWrap)
        mono_font = QtGui.QFont("Cascadia Mono")
        if not mono_font.exactMatch():
            mono_font = QtGui.QFont("Consolas")
        mono_font.setPointSize(10)
        self.results_text.setFont(mono_font)
        self.results_text.setStyleSheet(
            """
            QTextEdit {
                background: #08110d;
                color: #d7e5d7;
                border: 1px solid #1d3b2a;
                border-radius: 10px;
                padding: 8px;
                selection-background-color: #2f7d53;
                selection-color: #f6fff5;
            }
            """
        )
        root.addWidget(self.results_text, 1)

        # Wire clear button now that results_text exists
        self.clear_button.clicked.disconnect()
        self.clear_button.clicked.connect(self.results_text.clear)

        # Set initial control visibility based on default tool selection
        self._on_tool_changed(0)
        self._render_in_table = False
        self._render_row_index = 0
        self._render_table_header_seen = False

    def _append_tool_output(self, text: str) -> None:
        if text is None:
            return

        line = str(text).rstrip("\n")
        if not line:
            self._render_in_table = False
            self._render_table_header_seen = False
            self.results_text.append("<div style='height:0.35em;'></div>")
            return

        escaped = html.escape(line)
        style = "white-space: pre; margin: 0; line-height: 1.35;"

        if line.startswith("==="):
            self._render_in_table = False
            self._render_table_header_seen = False
            self.results_text.append(
                "<div style='margin: 0.25em 0 0.45em 0; padding: 0.45em 0.7em; "
                "background: linear-gradient(90deg, rgba(64,160,110,0.22), rgba(14,26,20,0.0)); "
                "border-left: 3px solid #6ee7a6; border-radius: 8px; color: #dfffe8; "
                "font-weight: 700; font-size: 1.06em;'>" + escaped + "</div>"
            )
            return

        if line.startswith("---") or set(line) == {"-"}:
            self._render_in_table = True
            self._render_row_index = 0
            self._render_table_header_seen = True
            self.results_text.append(
                "<div style='margin: 0.15em 0; color: #355948; white-space: pre; font-weight: 600;'>"
                + escaped + "</div>"
            )
            return

        if line.startswith("Raw output:"):
            self._render_in_table = False
            self._render_table_header_seen = False
            self.results_text.append(
                "<div style='margin-top: 0.5em; color: #8fe3b0; font-weight: 700;'>" + escaped + "</div>"
            )
            return

        if line.startswith("Error:"):
            self._render_in_table = False
            self._render_table_header_seen = False
            self.results_text.append(
                "<div style='margin: 0.05em 0; color: #ff8f8f; font-weight: 700;'>" + escaped + "</div>"
            )
            return

        if line.startswith("Cancelled."):
            self._render_in_table = False
            self._render_table_header_seen = False
            self.results_text.append(
                "<div style='margin: 0.05em 0; color: #ffd37a; font-weight: 600;'>" + escaped + "</div>"
            )
            return

        if line.startswith("Filter") or line.startswith("Sort:") or line.startswith("Entries:") or line.startswith("Collected:"):
            self._render_in_table = False
            self._render_table_header_seen = False
            self.results_text.append(
                "<div style='margin: 0.05em 0; color: #9bc8ab; font-weight: 600;'>" + escaped + "</div>"
            )
            return

        if self._render_in_table and self._render_table_header_seen:
            if not line.startswith("-"):
                self._render_row_index += 1
                row_bg = "rgba(24, 44, 35, 0.92)" if self._render_row_index % 2 else "rgba(10, 22, 16, 0.92)"
                row_color = "#edfdf0" if self._render_row_index % 2 else "#d1e7d5"
                self.results_text.append(
                    "<div style='" + style + f" background: {row_bg}; color: {row_color}; "
                    "padding: 0.15em 0.45em; border-radius: 6px; margin: 0.02em 0;'>"
                    + escaped + "</div>"
                )
                return

        if "  " in line and not line.startswith(" "):
            self.results_text.append(
                "<div style='" + style + " color: #f0fff5; font-weight: 700; padding: 0.05em 0;'>" + escaped + "</div>"
            )
            return

        if line.startswith(" "):
            self.results_text.append(
                "<div style='" + style + " color: #d7e5d7; padding: 0.04em 0;'>" + escaped + "</div>"
            )
            return

        self.results_text.append(
            "<div style='" + style + " color: #d7e5d7; padding: 0.04em 0;'>" + escaped + "</div>"
        )

    def _copy_rendered_output(self) -> None:
        clipboard = QtWidgets.QApplication.clipboard()
        clipboard.setHtml(self.results_text.toHtml())
        clipboard.setText(self.results_text.toPlainText())

    def _save_rendered_output(self) -> None:
        file_path, _filter = QtWidgets.QFileDialog.getSaveFileName(
            self,
            "Save rendered output",
            "tools_output.html",
            "HTML Files (*.html);;All Files (*)",
        )
        if not file_path:
            return
        if not file_path.lower().endswith(".html"):
            file_path += ".html"
        with open(file_path, "w", encoding="utf-8") as file:
            file.write(self.results_text.toHtml())

    def _on_tool_changed(self, _index: int) -> None:
        tool = self.tool_combo.currentText()
        needs_target = tool not in (
            "Local Network Info",
            "ARP Table Viewer",
            "Route Table Viewer",
            "Active Connections",
            "Bandwidth Monitor",
            "Subnet Calculator",
            "MTU / Fragmentation Test",
        )
        is_dns = tool == "DNS Lookup"
        is_dns_prop = tool == "DNS Propagation"
        is_port = tool in ("Port Check", "TLS Inspector")
        is_arp = tool == "ARP Table Viewer"
        is_route = tool == "Route Table Viewer"
        is_conn = tool == "Active Connections"
        is_bw = tool == "Bandwidth Monitor"
        is_subnet = tool == "Subnet Calculator"
        is_mtu = tool == "MTU / Fragmentation Test"
        self.target_label.setVisible(needs_target)
        self.target_edit.setVisible(needs_target)
        self.dns_type_label.setVisible(is_dns)
        self.dns_type_combo.setVisible(is_dns)
        self.dns_filter_label.setVisible(is_dns)
        self.dns_filter_edit.setVisible(is_dns)
        self.dns_order_label.setVisible(is_dns)
        self.dns_order_combo.setVisible(is_dns)
        self.dns_prop_type_label.setVisible(is_dns_prop)
        self.dns_prop_type_combo.setVisible(is_dns_prop)
        self.port_label.setVisible(is_port)
        self.port_edit.setVisible(is_port)
        self.port_preset_label.setVisible(is_port)
        self.port_preset_combo.setVisible(is_port)
        self.arp_iface_label.setVisible(is_arp)
        self.arp_iface_edit.setVisible(is_arp)
        self.arp_type_label.setVisible(is_arp)
        self.arp_type_combo.setVisible(is_arp)
        self.arp_sort_label.setVisible(is_arp)
        self.arp_sort_combo.setVisible(is_arp)
        self.arp_order_combo.setVisible(is_arp)
        self.route_iface_label.setVisible(is_route)
        self.route_iface_edit.setVisible(is_route)
        self.route_gateway_label.setVisible(is_route)
        self.route_gateway_edit.setVisible(is_route)
        self.route_sort_label.setVisible(is_route)
        self.route_sort_combo.setVisible(is_route)
        self.route_order_combo.setVisible(is_route)
        self.conn_state_label.setVisible(is_conn)
        self.conn_state_combo.setVisible(is_conn)
        self.conn_port_label.setVisible(is_conn)
        self.conn_port_edit.setVisible(is_conn)
        self.conn_process_label.setVisible(is_conn)
        self.conn_process_edit.setVisible(is_conn)
        self.conn_sort_label.setVisible(is_conn)
        self.conn_sort_combo.setVisible(is_conn)
        self.conn_order_combo.setVisible(is_conn)
        self.bw_adapter_label.setVisible(is_bw)
        self.bw_adapter_edit.setVisible(is_bw)
        self.bw_active_label.setVisible(is_bw)
        self.bw_active_combo.setVisible(is_bw)
        self.bw_interval_label.setVisible(is_bw)
        self.bw_interval_edit.setVisible(is_bw)
        self.bw_sort_label.setVisible(is_bw)
        self.bw_sort_combo.setVisible(is_bw)
        self.bw_order_combo.setVisible(is_bw)
        self.subnet_value_label.setVisible(is_subnet)
        self.subnet_value_edit.setVisible(is_subnet)
        self.subnet_mask_label.setVisible(is_subnet)
        self.subnet_mask_edit.setVisible(is_subnet)
        self.subnet_mode_label.setVisible(is_subnet)
        self.subnet_mode_combo.setVisible(is_subnet)
        self.mtu_payload_label.setVisible(is_mtu)
        self.mtu_payload_edit.setVisible(is_mtu)
        if tool == "TLS Inspector" and not self.port_edit.text().strip():
            self.port_edit.setText("443")
        placeholders = {
            "DNS Lookup":    "hostname or IP address",
            "WHOIS Lookup":  "domain name or IP address",
            "Port Check":    "hostname or IP  (e.g. example.com)",
            "HTTP Check":    "https://example.com  (scheme optional)",
            "TLS Inspector": "hostname  (e.g. example.com)",
            "MTU / Fragmentation Test": "hostname or IP address",
        }
        self.target_edit.setPlaceholderText(placeholders.get(tool, "target"))

    def _on_port_preset_changed(self, _index: int) -> None:
        port_num = self.port_preset_combo.currentData()
        if port_num:
            self.port_edit.setText(str(port_num))
            self.port_preset_combo.blockSignals(True)
            self.port_preset_combo.setCurrentIndex(0)
            self.port_preset_combo.blockSignals(False)

    def _run_tool(self) -> None:
        if self._worker_thread is not None and self._worker_thread.isRunning():
            return

        tool = self.tool_combo.currentText()
        needs_target = tool not in (
            "Local Network Info",
            "ARP Table Viewer",
            "Route Table Viewer",
            "Active Connections",
            "Bandwidth Monitor",
            "Subnet Calculator",
            "MTU / Fragmentation Test",
        )
        target = self.target_edit.text().strip()
        subnet_input = self.subnet_value_edit.text().strip()
        subnet_mask = self.subnet_mask_edit.text().strip()
        if needs_target and not target:
            self.target_edit.setFocus()
            return
        if tool == "Subnet Calculator" and not subnet_input:
            self.subnet_value_edit.setFocus()
            return

        self.go_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.results_text.clear()

        if tool == "DNS Lookup":
            worker: QtCore.QObject = DnsWorker(
                target,
                self.dns_type_combo.currentText(),
                filter_text=self.dns_filter_edit.text(),
                sort_desc=bool(self.dns_order_combo.currentData()),
            )
        elif tool == "DNS Propagation":
            worker = DnsPropagationWorker(target, self.dns_prop_type_combo.currentText())
        elif tool == "WHOIS Lookup":
            worker = WhoisWorker(target)
        elif tool == "Port Check":
            port_str = self.port_edit.text().strip()
            try:
                port_num = int(port_str)
                if not (1 <= port_num <= 65535):
                    raise ValueError()
            except ValueError:
                self._append_tool_output("Error: Enter a valid port number (1-65535).")
                self.go_button.setEnabled(True)
                self.cancel_button.setEnabled(False)
                return
            worker = PortCheckWorker(target, port_num)
        elif tool == "HTTP Check":
            worker = HttpCheckWorker(target)
        elif tool == "TLS Inspector":
            port_str = self.port_edit.text().strip()
            try:
                port_num = int(port_str)
                if not (1 <= port_num <= 65535):
                    raise ValueError()
            except ValueError:
                self._append_tool_output("Error: Enter a valid port number (1-65535).")
                self.go_button.setEnabled(True)
                self.cancel_button.setEnabled(False)
                return
            worker = TlsInspectorWorker(target, port_num)
        elif tool == "Local Network Info":
            worker = LocalNetInfoWorker()
        elif tool == "ARP Table Viewer":
            worker = ArpTableWorker(
                interface_filter=self.arp_iface_edit.text(),
                type_filter=str(self.arp_type_combo.currentData() or "all"),
                sort_by=str(self.arp_sort_combo.currentData() or "ip"),
                descending=bool(self.arp_order_combo.currentData()),
            )
        elif tool == "Route Table Viewer":
            worker = RouteTableWorker(
                interface_filter=self.route_iface_edit.text(),
                gateway_filter=self.route_gateway_edit.text(),
                sort_by=str(self.route_sort_combo.currentData() or "destination"),
                descending=bool(self.route_order_combo.currentData()),
            )
        elif tool == "Active Connections":
            worker = ActiveConnectionsWorker(
                state_filter=str(self.conn_state_combo.currentData() or "all"),
                port_filter=self.conn_port_edit.text(),
                process_filter=self.conn_process_edit.text(),
                sort_by=str(self.conn_sort_combo.currentData() or "local"),
                descending=bool(self.conn_order_combo.currentData()),
            )
        elif tool == "Bandwidth Monitor":
            interval_text = self.bw_interval_edit.text().strip()
            try:
                interval = float(interval_text)
                if interval <= 0.0:
                    raise ValueError()
            except ValueError:
                self._append_tool_output("Error: Enter a valid interval in seconds (e.g. 1.0).")
                self.go_button.setEnabled(True)
                self.cancel_button.setEnabled(False)
                return

            worker = BandwidthMonitorWorker(
                adapter_filter=self.bw_adapter_edit.text(),
                active_only=bool(self.bw_active_combo.currentData()),
                interval_seconds=interval,
                sort_by=str(self.bw_sort_combo.currentData() or "recv_mbps"),
                descending=bool(self.bw_order_combo.currentData()),
            )
        elif tool == "Subnet Calculator":
            mode = str(self.subnet_mode_combo.currentData() or "auto")
            mask_arg = subnet_mask if mode == "reverse" else ""
            worker = SubnetCalculatorWorker(subnet_input, mask_arg)
        elif tool == "MTU / Fragmentation Test":
            payload_text = self.mtu_payload_edit.text().strip()
            try:
                max_payload = int(payload_text)
                if not (0 <= max_payload <= 1472):
                    raise ValueError()
            except ValueError:
                self._append_tool_output("Error: Enter a valid max payload between 0 and 1472.")
                self.go_button.setEnabled(True)
                self.cancel_button.setEnabled(False)
                return
            worker = MtuTestWorker(target, max_payload=max_payload)
        else:
            self.go_button.setEnabled(True)
            self.cancel_button.setEnabled(False)
            return

        self._worker = worker
        self._worker_thread = QtCore.QThread(self)
        self._worker.moveToThread(self._worker_thread)
        self._worker_thread.started.connect(self._worker.run)  # type: ignore[union-attr]
        self._worker.output.connect(self._append_tool_output)  # type: ignore[union-attr]
        self._worker.finished.connect(self._on_worker_finished)  # type: ignore[union-attr]
        self._worker.finished.connect(self._worker_thread.quit)  # type: ignore[union-attr]
        self._worker_thread.finished.connect(self._worker_thread.deleteLater)
        self._worker_thread.start()

    def _cancel_tool(self) -> None:
        if self._worker is not None:
            self._worker.cancel()

    def _on_worker_finished(self) -> None:
        self._worker = None
        self._worker_thread = None
        self.go_button.setEnabled(True)
        self.cancel_button.setEnabled(False)


class OverviewTab(QtWidgets.QWidget):
    def __init__(self) -> None:
        super().__init__()
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        title = QtWidgets.QLabel("Active Targets Overview")
        layout.addWidget(title)

        self.table = QtWidgets.QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["Tab", "Target", "Status", "Sets", "Avg", "Loss", "Updated"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QtWidgets.QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QtWidgets.QHeaderView.Stretch)
        for col in range(3, 7):
            self.table.horizontalHeader().setSectionResizeMode(col, QtWidgets.QHeaderView.ResizeToContents)
        layout.addWidget(self.table, 1)

    def update_targets(self, snapshots: List[Dict[str, object]]) -> None:
        self.table.setRowCount(len(snapshots))
        for row_idx, snapshot in enumerate(snapshots):
            values = [
                str(snapshot.get("tab_name", "")),
                str(snapshot.get("target", "—")),
                str(snapshot.get("status", "Idle")),
                str(snapshot.get("sets", 0)),
                str(snapshot.get("avg", "—")),
                str(snapshot.get("loss", "—")),
                str(snapshot.get("updated", "—")),
            ]
            for col, value in enumerate(values):
                item = QtWidgets.QTableWidgetItem(value)
                item.setToolTip(value)
                if col >= 3:
                    item.setTextAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
                self.table.setItem(row_idx, col, item)


# ----------------------------- main window -----------------------------


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(QtGui.QIcon(_resource_path("logo.ico")))
        self.resize(1400, 900)
        self._tab_counter = 0
        self._target_tabs: Dict[int, TargetTab] = {}
        self._target_history: List[str] = []

        self._build_ui()
        self._build_statusbar()
        self._apply_style()
        self._load_target_history()
        self._add_target_tab(make_active=True)
        self._refresh_overview()
        self._sync_statusbar_from_active_tab()

    def _history_file_path(self) -> str:
        base_dir = os.path.join(_app_data_dir(), LOG_DIR_NAME)
        return os.path.join(base_dir, TARGET_HISTORY_FILE)

    def _load_target_history(self) -> None:
        file_path = self._history_file_path()
        if not os.path.exists(file_path):
            self._target_history = []
            return

        try:
            with open(file_path, "r", encoding="utf-8") as file:
                raw = json.load(file)
        except Exception:
            self._target_history = []
            return

        if not isinstance(raw, list):
            self._target_history = []
            return

        normalized: List[str] = []
        seen = set()
        for value in raw:
            if not isinstance(value, str):
                continue
            entry = value.strip()
            key = entry.lower()
            if not key or key in seen:
                continue
            seen.add(key)
            normalized.append(entry)

        self._target_history = normalized[:TARGET_HISTORY_LIMIT]

    def _save_target_history(self) -> None:
        file_path = self._history_file_path()
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        try:
            with open(file_path, "w", encoding="utf-8") as file:
                json.dump(self._target_history[:TARGET_HISTORY_LIMIT], file, indent=2)
        except Exception:
            # Non-fatal: app should continue even if history cannot be persisted.
            pass

    def _build_ui(self) -> None:
        self.tab_widget = QtWidgets.QTabWidget()
        self.tab_widget.setTabsClosable(True)
        self.tab_widget.tabCloseRequested.connect(self._on_tab_close_requested)
        self.tab_widget.currentChanged.connect(self._on_current_tab_changed)

        self.tools_tab = ToolsTab()
        self.tab_widget.addTab(self.tools_tab, "Tools")

        self.overview_tab = OverviewTab()
        self.tab_widget.addTab(self.overview_tab, "Overview")

        self.new_tab_button = QtWidgets.QToolButton()
        self.new_tab_button.setText("+")
        self.new_tab_button.setToolTip("Add target tab")
        self.new_tab_button.clicked.connect(lambda: self._add_target_tab(make_active=True))
        self.tab_widget.setCornerWidget(self.new_tab_button, QtCore.Qt.TopRightCorner)

        self.setCentralWidget(self.tab_widget)

    def _build_statusbar(self) -> None:
        self.status_label = QtWidgets.QLabel("Ready.")
        self.statusBar().addWidget(self.status_label, 1)
        self.summary_label = QtWidgets.QLabel("Avg: —   Loss: —   Sets: 0")
        self.statusBar().addPermanentWidget(self.summary_label)

    def _apply_style(self) -> None:
        self.setStyleSheet(
            """
            QMainWindow {
                background: #030503;
                color: #8fff8f;
                font-family: Consolas, "Cascadia Mono", "Lucida Console", monospace;
                font-size: 10.5pt;
            }
            QTabWidget::pane {
                border: 1px solid #1f5f1f;
                top: -1px;
            }
            QTabBar::tab {
                background: #0a150a;
                color: #7ee97e;
                border: 1px solid #1f5f1f;
                padding: 6px 12px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: #103010;
                color: #a9ffa9;
            }
            QTabBar::tab:hover {
                background: #123212;
            }
            QPushButton {
                background: #0d1e0d;
                color: #8fff8f;
                border: 1px solid #297a29;
                border-radius: 4px;
                padding: 5px 10px;
            }
            QPushButton:hover {
                background: #123212;
                border: 1px solid #3db03d;
            }
            QPushButton:pressed {
                background: #0a180a;
            }
            QPushButton:disabled {
                color: #4b744b;
                border: 1px solid #294329;
            }
            QLineEdit, QComboBox {
                background: #070d07;
                color: #9dff9d;
                border: 1px solid #297a29;
                border-radius: 4px;
                padding: 5px 8px;
                selection-background-color: #1d5f1d;
                selection-color: #d9ffd9;
            }
            QComboBox QAbstractItemView {
                background: #070d07;
                color: #9dff9d;
                border: 1px solid #297a29;
                selection-background-color: #184418;
            }
            QTableWidget {
                background: #050a05;
                alternate-background-color: #091409;
                color: #99ff99;
                gridline-color: #1c4f1c;
                selection-background-color: #184818;
                selection-color: #d9ffd9;
                border: 1px solid #1c4f1c;
            }
            QHeaderView::section {
                background: #0b1a0b;
                color: #8fff8f;
                border: 1px solid #1f5f1f;
                padding: 5px;
            }
            QStatusBar {
                background: #081208;
                color: #8fff8f;
                border-top: 1px solid #185718;
            }
            QStatusBar QLabel {
                color: #8fff8f;
            }
            """
        )

    def _active_target_tab(self) -> Optional[TargetTab]:
        widget = self.tab_widget.currentWidget()
        if isinstance(widget, TargetTab):
            return widget
        return None

    def _add_target_tab(self, make_active: bool) -> TargetTab:
        self._tab_counter += 1
        tab_name = f"Target {self._tab_counter}"
        tab = TargetTab(tab_name, self._target_choices())
        tab.status_changed.connect(self._on_target_status_changed)
        tab.snapshot_changed.connect(self._on_target_snapshot_changed)
        tab.target_committed.connect(self._on_target_committed)
        index = self.tab_widget.addTab(tab, tab_name)
        self._target_tabs[id(tab)] = tab
        if make_active:
            self.tab_widget.setCurrentIndex(index)
        return tab

    def _target_choices(self) -> List[str]:
        ordered: List[str] = []
        seen = set()
        for value in self._target_history + COMMON_TARGETS:
            normalized = value.strip()
            key = normalized.lower()
            if not key or key in seen:
                continue
            seen.add(key)
            ordered.append(normalized)
        return ordered

    def _on_target_committed(self, target: str) -> None:
        normalized = target.strip()
        if not normalized:
            return
        lower = normalized.lower()
        self._target_history = [item for item in self._target_history if item.lower() != lower]
        self._target_history.insert(0, normalized)
        self._target_history = self._target_history[:TARGET_HISTORY_LIMIT]
        self._save_target_history()

        choices = self._target_choices()
        for tab in self._target_tabs.values():
            tab.update_target_choices(choices)
        self._refresh_overview()

    def _refresh_overview(self) -> None:
        snapshots = [tab.snapshot() for tab in self._target_tabs.values()]
        snapshots.sort(key=lambda s: str(s.get("tab_name", "")))
        self.overview_tab.update_targets(snapshots)

    def _sync_statusbar_from_active_tab(self) -> None:
        if not hasattr(self, "status_label") or not hasattr(self, "summary_label"):
            return

        current = self.tab_widget.currentWidget()
        if current is self.tools_tab:
            self.status_label.setText("Tools")
            self.summary_label.setText("")
            return
        if current is self.overview_tab:
            self.status_label.setText("Overview of all target tabs.")
            self.summary_label.setText("")
            return
        tab = self._active_target_tab()
        if tab is None:
            self.status_label.setText("Ready.")
            self.summary_label.setText("")
            return

        snap = tab.snapshot()
        self.status_label.setText(str(snap.get("status", "Ready.")))
        self.summary_label.setText(str(snap.get("summary", "Avg: —   Loss: —   Sets: 0")))

    @QtCore.Slot(int)
    def _on_current_tab_changed(self, _index: int) -> None:
        self._sync_statusbar_from_active_tab()

    @QtCore.Slot(int)
    def _on_tab_close_requested(self, index: int) -> None:
        if index == 0:
            return
        widget = self.tab_widget.widget(index)
        if not isinstance(widget, TargetTab):
            return
        widget.stop_monitoring()
        self._target_tabs.pop(id(widget), None)
        self.tab_widget.removeTab(index)
        widget.deleteLater()
        if not self._target_tabs:
            self._add_target_tab(make_active=True)
        self._refresh_overview()
        self._sync_statusbar_from_active_tab()

    def _on_target_status_changed(self, _message: str) -> None:
        self._sync_statusbar_from_active_tab()
        self._refresh_overview()

    def _on_target_snapshot_changed(self, _snapshot: Dict[str, object]) -> None:
        self._sync_statusbar_from_active_tab()
        self._refresh_overview()

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:  # noqa: N802
        for tab in list(self._target_tabs.values()):
            tab.stop_monitoring()
        super().closeEvent(event)


def main() -> int:
    pg.setConfigOptions(antialias=True)
    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setWindowIcon(QtGui.QIcon(_resource_path("logo.ico")))
    window = MainWindow()
    window.showMaximized()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())

