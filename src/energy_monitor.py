"""
src/energy_monitor.py
---------------------
Real-time offline energy and carbon emissions monitor.
Estimates system power using load-based modeling and tracks per-action resource consumption.
"""

from __future__ import annotations

import time
import csv
from datetime import datetime
from typing import List, Tuple, Dict, Optional
from PyQt6.QtCore import QObject, QTimer, pyqtSignal

# ── Power & Carbon Modeling Constants ─────────────────────────────────────────
# Estimated CPU TDP in Watts (typical laptop / ultrabook CPU)
CPU_TDP_W = 12.0

# Estimated RAM power consumption in Watts
RAM_W = 3.0

# Estimated power in Watts: P = RAM_W + CPU_TDP_W * cpu_load_fraction
# This is an estimate, using the same load-based method CodeCarbon uses
# when no hardware RAPL counter exists.

# Regional / Global grid carbon intensity in gCO2/kWh (commonly cited global average)
GRID_INTENSITY_G_PER_KWH = 475.0

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


class ActionRecord:
    def __init__(self, label: str, seconds: float, energy_mwh: float, co2_mg: float):
        self.label = label
        self.seconds = seconds
        self.energy_mwh = energy_mwh
        self.co2_mg = co2_mg

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "seconds": self.seconds,
            "energy_mwh": self.energy_mwh,
            "co2_mg": self.co2_mg,
        }


class EnergyMonitor(QObject):
    """
    Offline energy monitor sampling CPU load every second.
    Accumulates session energy and CO2, and tracks per-action slices.
    """
    updated = pyqtSignal()

    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)
        self.has_psutil = HAS_PSUTIL
        self.session_wh = 0.0
        self.session_co2_mg = 0.0
        self.current_power_mw = 0.0
        self.current_action: str = "idle"

        self.last_sample_time: float = time.monotonic()

        # Up to 120 samples: (timestamp_str, power_mw, energy_mwh, co2_mg, action_label)
        self.samples: List[Tuple[str, float, float, float, str]] = []

        # Last 10 actions: ActionRecord
        self.actions: List[ActionRecord] = []

        # Active action in flight: label -> (start_time, start_wh, start_co2)
        self._active_actions: Dict[str, Tuple[float, float, float]] = {}

        if self.has_psutil:
            try:
                psutil.cpu_percent(interval=None)
            except Exception:
                pass

        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self._on_tick)
        self.timer.start()

    def _on_tick(self):
        now_mono = time.monotonic()
        dt = max(0.1, min(5.0, now_mono - self.last_sample_time))
        self.last_sample_time = now_mono

        if not self.has_psutil:
            self.updated.emit()
            return

        try:
            cpu_pct = psutil.cpu_percent(interval=None)
        except Exception:
            cpu_pct = 0.0

        cpu_fraction = max(0.0, min(1.0, cpu_pct / 100.0))
        power_w = RAM_W + (CPU_TDP_W * cpu_fraction)
        self.current_power_mw = power_w * 1000.0

        # Wh = Watts * hours
        step_wh = power_w * (dt / 3600.0)
        self.session_wh += step_wh

        # CO2 mg = kWh * g/kWh * 1000 = (Wh / 1000) * GRID_INTENSITY * 1000 = Wh * GRID_INTENSITY
        step_co2_mg = step_wh * GRID_INTENSITY_G_PER_KWH
        self.session_co2_mg += step_co2_mg

        timestamp_str = datetime.now().strftime("%H:%M:%S")
        energy_mwh = self.session_wh * 1000.0

        self.samples.append((
            timestamp_str,
            round(self.current_power_mw, 2),
            round(energy_mwh, 3),
            round(self.session_co2_mg, 3),
            self.current_action,
        ))
        if len(self.samples) > 120:
            self.samples.pop(0)

        self.updated.emit()

    def start_action(self, label: str):
        self.current_action = label
        self._active_actions[label] = (time.monotonic(), self.session_wh, self.session_co2_mg)

    def end_action(self, label: str):
        self.current_action = "idle"
        if label in self._active_actions:
            start_t, start_wh, start_co2 = self._active_actions.pop(label)
            duration = max(0.01, round(time.monotonic() - start_t, 3))

            # Integrated energy during the window
            delta_wh = max(0.0, self.session_wh - start_wh)
            delta_mwh = delta_wh * 1000.0

            # If the action ran very fast (under 1s), use instant power estimate
            if delta_mwh <= 0.001 and self.current_power_mw > 0:
                delta_mwh = round((self.current_power_mw / 1000.0) * (duration / 3600.0) * 1000.0, 4)

            delta_co2 = max(0.001, (delta_mwh / 1000.0) * GRID_INTENSITY_G_PER_KWH)

            rec = ActionRecord(
                label=label,
                seconds=duration,
                energy_mwh=round(delta_mwh, 3),
                co2_mg=round(delta_co2, 3),
            )
            self.actions.append(rec)
            if len(self.actions) > 10:
                self.actions.pop(0)

            self.updated.emit()

    def get_last_action(self) -> Optional[ActionRecord]:
        return self.actions[-1] if self.actions else None

    def export_csv(self, filepath: str) -> bool:
        try:
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["timestamp", "power_mw", "energy_mwh", "co2_mg", "action"])
                for s in self.samples:
                    writer.writerow(s)
                if self.actions:
                    writer.writerow([])
                    writer.writerow(["# Action Table (Last 10 Actions)", "seconds", "energy_mwh", "co2_mg", "action"])
                    for a in self.actions:
                        writer.writerow(["action_record", a.seconds, a.energy_mwh, a.co2_mg, a.label])
            return True
        except Exception:
            return False


_global_monitor: Optional[EnergyMonitor] = None


def get_energy_monitor() -> EnergyMonitor:
    global _global_monitor
    if _global_monitor is None:
        _global_monitor = EnergyMonitor()
    return _global_monitor
