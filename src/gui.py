"""
gui.py
------
C++ Compiler Error Explainer & Auto-Healer Desktop GUI.
Designed with a classic, clean IDE layout supporting live dark & light themes.
"""

from __future__ import annotations

import sys
import os

_SRC_DIR = os.path.dirname(os.path.abspath(__file__))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)
import subprocess
import json
import re
import html
import time
import math
import platform
import socket
import tempfile
import warnings
import logging
from typing import Optional, List, Dict, Tuple

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QPlainTextEdit, QTextEdit, QPushButton, QFileDialog,
    QMessageBox, QLabel, QFrame, QCheckBox, QDialog, QTreeWidget,
    QTreeWidgetItem, QLineEdit, QScrollArea, QSizePolicy, QTextBrowser,
    QProgressBar, QStackedWidget, QGraphicsView, QGraphicsScene,
    QGraphicsRectItem, QGraphicsLineItem, QGraphicsTextItem, QGraphicsItem,
    QTabWidget
)
from PyQt6.QtCore import Qt, QRect, QSize, QThread, pyqtSignal, QTimer, QProcess
from PyQt6.QtGui import (
    QFont, QColor, QPainter, QTextFormat, QTextCharFormat,
    QSyntaxHighlighter, QTextCursor, QPainterPath, QPen, QLinearGradient, QBrush
)

# Suppress noisy logs & warnings
logging.getLogger("codecarbon").setLevel(logging.ERROR)
warnings.filterwarnings("ignore", message=r".*unpickle estimator.*")
warnings.filterwarnings("ignore", message=r".*InconsistentVersionWarning.*")

try:
    from codecarbon import EmissionsTracker
    CODECARBON_AVAILABLE = True
except ImportError:
    CODECARBON_AVAILABLE = False

try:
    from heal_loop import HealWorker
    HEALER_AVAILABLE = True
except ImportError:
    HEALER_AVAILABLE = False

try:
    from error_classifier import ErrorClassifier
except ImportError:
    ErrorClassifier = None

try:
    from second_opinion import get_second_opinion, format_second_opinion, RegexClassifier
    SECOND_OPINION_AVAILABLE = True
except ImportError:
    SECOND_OPINION_AVAILABLE = False

try:
    from accuracy_benchmark import BenchmarkWorker as _BenchmarkWorker
    BENCHMARK_AVAILABLE = True
except ImportError:
    BENCHMARK_AVAILABLE = False
    _BenchmarkWorker = None

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    from gui_new_pages import SecondOpinionPage, BenchmarkPage
    NEW_PAGES_AVAILABLE = True
except ImportError:
    NEW_PAGES_AVAILABLE = False
    SecondOpinionPage = None
    BenchmarkPage = None

from ast_extractor import extract_ast, extract_node_near_line, parse_ast_to_tree
from security_analyzer import analyze as analyze_security, format_security_report

import theme
from ui_components import (
    plain_label, badge, section_label, code_block,
    split_explanation, CollapsibleSection, IssueCard, AiCard
)

# ── Backward compatibility exports for external modules and gui_new_pages ─────
CURRENT_THEME = dict(theme.tokens("dark"))
BG_COLOR = CURRENT_THEME["bg"]
PANE_BG = CURRENT_THEME["surface"]
PANEL_BG = PANE_BG
HEADER_BG = CURRENT_THEME["surface_alt"]
BORDER_COLOR = CURRENT_THEME["border"]
PINK = CURRENT_THEME["accent"]
TEXT_MAIN = CURRENT_THEME["text"]
TEXT_DIM = CURRENT_THEME["muted"]
KEYWORD_COLOR = CURRENT_THEME["syn_keyword"]
ERROR_LINE_COLOR = CURRENT_THEME["error_line"]
RED = CURRENT_THEME["error"]
YELLOW = CURRENT_THEME["warn"]
GREEN = CURRENT_THEME["ok"]
FONT_FAMILY = "Segoe UI"


class _KeywordClassifier:
    """
    Lightweight fallback classifier using keyword and regex matching.
    Used when the ML model isn't trained or loaded yet.
    """
    def predict(self, message: str, ast_node: str = "") -> tuple:
        msg_lower = (str(message) + " " + str(ast_node)).lower()

        # Missing includes
        if "no such file or directory" in msg_lower:
            return "missing_include", 0.99
        if "was not declared in this scope" in msg_lower or "undeclared identifier" in msg_lower:
            std_syms = {
                "cout", "cin", "cerr", "endl", "string", "vector", "map", "set",
                "unordered_map", "unordered_set", "list", "queue", "stack", "deque", "array",
                "pair", "tuple", "sort", "find", "max", "min", "reverse", "count",
                "fill", "copy", "abs", "sqrt", "pow", "ceil", "floor",
                "unique_ptr", "shared_ptr", "make_unique", "make_shared",
                "strlen", "strcpy", "strcmp", "strcat", "memset", "memcpy", "memmove",
                "printf", "scanf", "fprintf", "puts", "fopen", "fclose", "sprintf", "snprintf",
                "INT_MAX", "INT_MIN", "size_t"
            }
            sym_match = re.search(r"['‘]([a-zA-Z_]\w*)['’]", message)
            if sym_match and sym_match.group(1) in std_syms:
                return "missing_include", 0.99
            if any(f"'{s}'" in msg_lower for s in ("cout", "cin", "vector", "string", "endl", "sort", "printf", "strlen")):
                return "missing_include", 0.99
            return "name_resolution", 0.95

        if any(kw in msg_lower for kw in ["undeclared", "not declared", "has not been declared", "does not name a type"]):
            return "name_resolution", 0.90

        if any(kw in msg_lower for kw in [
            "array subscript is not an integer", "subscripted value is not an array",
            "cannot convert", "invalid conversion", "no matching function", "no matching constructor",
            "incompatible", "invalid operands", "invalid cast", "static_cast", "invalid use of void",
            "sizeof' to a function"
        ]):
            return "type_error", 0.95

        if any(kw in msg_lower for kw in [
            "expected ';'", "expected ')'", "expected '{'", "expected '}'", "expected ']'",
            "break statement not within", "continue statement not within", "stray", "missing terminating"
        ]):
            return "syntax_error", 0.95

        if any(kw in msg_lower for kw in ["return type", "no return", "control reaches end"]):
            return "return_type_error", 0.90

        if any(kw in msg_lower for kw in ["redefinition", "already defined", "multiple definition"]):
            return "redefinition", 0.90

        if any(kw in msg_lower for kw in ["is private", "is protected", "inaccessible", "assignment of read-only"]):
            return "access_error", 0.90

        if any(kw in msg_lower for kw in ["undefined reference", "linker", "ld returned"]):
            return "linker_error", 0.90

        return "other", 0.5


def _read_rapl_energy_joules():
    root = "/sys/class/powercap"
    if not os.path.isdir(root):
        return None
    total_uj = 0
    found = False
    for dirpath, _, filenames in os.walk(root):
        if "energy_uj" not in filenames:
            continue
        try:
            with open(os.path.join(dirpath, "energy_uj"), "r", encoding="utf-8") as f:
                total_uj += int(f.read().strip())
                found = True
        except (OSError, ValueError):
            continue
    return total_uj / 1_000_000 if found else None


def _extract_cpp_call_graph(code):
    keywords = {
        "if", "for", "while", "switch", "return", "sizeof", "catch", "delete",
        "new", "static_cast", "dynamic_cast", "reinterpret_cast", "const_cast",
    }
    function_re = re.compile(
        r"(?:^|\n)\s*(?:template\s*<[^>{}]+>\s*)?"
        r"(?:[\w:<>,~*&\s]+\s+)+(?P<name>[A-Za-z_]\w*)\s*"
        r"\([^;{}]*\)\s*(?:const\s*)?(?:noexcept\s*)?\{",
        re.MULTILINE,
    )
    functions = []
    for match in function_re.finditer(code):
        name = match.group("name")
        if name in keywords:
            continue
        body_start = match.end()
        depth = 1
        i = body_start
        while i < len(code) and depth:
            if code[i] == "{":
                depth += 1
            elif code[i] == "}":
                depth -= 1
            i += 1
        functions.append({"name": name, "body": code[body_start:i - 1]})

    names = [f["name"] for f in functions]
    name_set = set(names)
    edges = set()
    external_calls = set()
    call_re = re.compile(r"\b([A-Za-z_]\w*)\s*\(")

    for function in functions:
        caller = function["name"]
        for callee in call_re.findall(function["body"]):
            if callee in keywords or callee == caller:
                continue
            if callee in name_set:
                edges.add((caller, callee))
            elif len(external_calls) < 12:
                external_calls.add((caller, callee))

    includes = re.findall(r"^\s*#include\s+[<\"]([^>\"]+)[>\"]", code, re.MULTILINE)
    modules = sorted(set(includes))
    return names, sorted(edges), sorted(external_calls), modules


def _extract_cpp_cfg(code):
    function_re = re.compile(
        r"(?:^|\n)\s*(?:[\w:<>,~*&\s]+\s+)+(?P<name>[A-Za-z_]\w*)\s*"
        r"\([^;{}]*\)\s*(?:const\s*)?(?:noexcept\s*)?\{",
        re.MULTILINE,
    )
    results = []
    for match in function_re.finditer(code):
        name = match.group("name")
        if name in {"if", "for", "while", "switch", "return"}:
            continue
        body_start = match.end()
        depth = 1
        i = body_start
        while i < len(code) and depth:
            if code[i] == "{":
                depth += 1
            elif code[i] == "}":
                depth -= 1
            i += 1
        body = code[body_start:i - 1]
        lines = [l.strip() for l in body.split("\n") if l.strip()]

        nodes = []
        edges = []
        nodes.append({"id": "start", "label": f"START: {name}", "type": "entry"})
        current_node_id = "start"
        block_counter = 0
        pending_text = []

        for line in lines:
            if any(kw in line for kw in ["if", "while", "for", "switch"]):
                if pending_text:
                    block_id = f"b{block_counter}"
                    nodes.append({"id": block_id, "label": "\n".join(pending_text[:3]), "type": "stmt"})
                    edges.append((current_node_id, block_id))
                    current_node_id = block_id
                    block_counter += 1
                    pending_text = []

                branch_id = f"c{block_counter}"
                nodes.append({"id": branch_id, "label": line, "type": "branch"})
                edges.append((current_node_id, branch_id))
                current_node_id = branch_id
                block_counter += 1
            elif "return" in line:
                if pending_text:
                    block_id = f"b{block_counter}"
                    nodes.append({"id": block_id, "label": "\n".join(pending_text[:3]), "type": "stmt"})
                    edges.append((current_node_id, block_id))
                    current_node_id = block_id
                    block_counter += 1
                    pending_text = []

                ret_id = f"r{block_counter}"
                nodes.append({"id": ret_id, "label": line, "type": "exit"})
                edges.append((current_node_id, ret_id))
                current_node_id = ret_id
                block_counter += 1
            else:
                pending_text.append(line)
                if len(pending_text) > 4:
                    block_id = f"b{block_counter}"
                    nodes.append({"id": block_id, "label": "\n".join(pending_text), "type": "stmt"})
                    edges.append((current_node_id, block_id))
                    current_node_id = block_id
                    block_counter += 1
                    pending_text = []

        if pending_text or current_node_id != "start":
            if pending_text:
                block_id = f"b{block_counter}"
                nodes.append({"id": block_id, "label": "\n".join(pending_text), "type": "stmt"})
                edges.append((current_node_id, block_id))
                current_node_id = block_id
            nodes.append({"id": "end", "label": "END", "type": "exit"})
            edges.append((current_node_id, "end"))

        results.append({"name": name, "nodes": nodes, "edges": edges})
    return results


def get_gcc_version() -> str:
    try:
        res = subprocess.run(["g++", "--version"], capture_output=True, text=True, timeout=3)
        if res.returncode == 0 and res.stdout:
            first_line = res.stdout.splitlines()[0]
            m = re.search(r"(\d+\.\d+(?:\.\d+)?)", first_line)
            if m:
                return f"GCC {m.group(1)}"
    except Exception:
        pass
    return "GCC 11.4"


# ── Custom Painted Theme-Aware Widgets ────────────────────────────────────────

class SparklineGraph(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(15)
        self.setMaximumHeight(36)
        self.values = [0.0] * 50
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_fluctuation)
        self.timer.start(250)
        theme.on_change(lambda m, t: self.update())

    def update_fluctuation(self):
        if HAS_PSUTIL:
            try:
                self.add_value(psutil.cpu_percent())
                return
            except Exception:
                pass
        import random
        self.add_value(random.uniform(0.5, 3.5))

    def add_value(self, val):
        self.values.pop(0)
        self.values.append(val)
        self.update()

    def trigger_spike(self):
        import random
        self.add_value(random.uniform(20.0, 35.0))

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()

        painter.setPen(theme.qcolor("border"))
        painter.drawLine(0, h - 1, w, h - 1)

        if not self.values:
            return

        max_val = max(max(self.values), 25.0)
        path = QPainterPath()
        step = w / max(1, len(self.values) - 1)

        for i, v in enumerate(self.values):
            x = i * step
            y = h - (v / max_val * (h - 6)) - 2
            if i == 0:
                path.moveTo(x, y)
            else:
                path.lineTo(x, y)

        painter.setPen(QPen(theme.qcolor("accent"), 1.6))
        painter.drawPath(path)

        fill_path = QPainterPath(path)
        fill_path.lineTo(w, h)
        fill_path.lineTo(0, h)
        fill_path.closeSubpath()

        acc_col = theme.qcolor("accent")
        c_top = QColor(acc_col.red(), acc_col.green(), acc_col.blue(), 55)
        c_bot = QColor(acc_col.red(), acc_col.green(), acc_col.blue(), 0)
        grad = QLinearGradient(0, 0, 0, h)
        grad.setColorAt(0, c_top)
        grad.setColorAt(1, c_bot)
        painter.fillPath(fill_path, grad)


class MetricsGraph(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(220)
        self.series = {"Power mW": [], "Carbon mg/Wh": [], "Time s": []}
        theme.on_change(lambda m, t: self.update())

    def add_sample(self, power_mw, carbon_mg_per_wh, execution_time):
        values = {
            "Power mW": power_mw,
            "Carbon mg/Wh": carbon_mg_per_wh,
            "Time s": execution_time,
        }
        for name, value in values.items():
            data = self.series[name]
            data.append(max(0.0, float(value or 0.0)))
            if len(data) > 80:
                data.pop(0)
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.fillRect(self.rect(), theme.qcolor("surface"))

        colors = {
            "Power mW": theme.qcolor("accent"),
            "Carbon mg/Wh": theme.qcolor("ok"),
            "Time s": theme.qcolor("warn"),
        }

        left, top, right, bottom = 52, 20, 18, 42
        width = max(1, self.width() - left - right)
        height = max(1, self.height() - top - bottom)
        graph_rect = QRect(left, top, width, height)

        painter.setPen(QPen(theme.qcolor("border"), 1))
        painter.drawRect(graph_rect)
        for i in range(1, 4):
            y = top + int(height * i / 4)
            painter.drawLine(left, y, left + width, y)

        painter.setFont(theme.ui_font(10))
        painter.setPen(theme.qcolor("muted"))
        painter.drawText(8, top + 8, "High")
        painter.drawText(12, top + height, "Low")

        legend_x = left
        for name, col in colors.items():
            painter.setPen(QPen(col, 2))
            painter.drawLine(legend_x, self.height() - 18, legend_x + 20, self.height() - 18)
            painter.setPen(theme.qcolor("muted"))
            painter.drawText(legend_x + 26, self.height() - 14, name)
            legend_x += 140

        for name, data in self.series.items():
            if len(data) < 2:
                continue
            max_value = max(max(data), 1e-9)
            step = width / max(1, len(data) - 1)
            path = QPainterPath()
            for i, val in enumerate(data):
                x = left + i * step
                y = top + height - ((val / max_value) * height)
                if i == 0:
                    path.moveTo(x, y)
                else:
                    path.lineTo(x, y)
            painter.setPen(QPen(colors[name], 2))
            painter.drawPath(path)


class GraphNode(QGraphicsRectItem):
    def __init__(self, label, x, y, w, h, border, fill):
        super().__init__(-w / 2, -h / 2, w, h)
        self.setPos(x + w / 2, y + h / 2)
        self.setBrush(fill)
        self.setPen(QPen(border, 1.8))
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges)

        self.text = QGraphicsTextItem(label, self)
        self.text.setFont(theme.mono_font(10, bold=True))
        self.text.setDefaultTextColor(theme.qcolor("text"))
        br = self.text.boundingRect()
        self.text.setPos(-br.width() / 2, -br.height() / 2)
        self.edges_out = []
        self.edges_in = []

    def itemChange(self, change, value):
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            for edge in self.edges_out:
                edge.updatePosition()
            for edge in self.edges_in:
                edge.updatePosition()
        return super().itemChange(change, value)


class GraphEdge(QGraphicsLineItem):
    def __init__(self, source_node, dest_node, color, pen_width=1.5):
        super().__init__()
        self.source_node = source_node
        self.dest_node = dest_node
        self.setPen(QPen(color, pen_width))
        self.setZValue(-1)
        self.source_node.edges_out.append(self)
        self.dest_node.edges_in.append(self)
        self.updatePosition()

    def updatePosition(self):
        self.setLine(
            self.source_node.pos().x(), self.source_node.pos().y(),
            self.dest_node.pos().x(), self.dest_node.pos().y()
        )


class CallGraphWidget(QGraphicsView):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("Console")
        self.setMinimumHeight(400)
        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setBackgroundBrush(theme.qcolor("surface"))
        theme.on_change(lambda m, t: self.setBackgroundBrush(theme.qcolor("surface")))

    def update_graph(self, functions, edges, external_calls, modules):
        self.scene.clear()
        if not functions:
            t = self.scene.addText("No C++ function definitions found in the current source.")
            t.setDefaultTextColor(theme.qcolor("muted"))
            t.setFont(theme.ui_font(12))
            return

        margin = 34
        module_y = 46
        function_y = 180
        external_y = 320
        node_w, node_h = 150, 42
        view_w = max(self.width(), 800)

        def positions(items, y):
            count = max(1, len(items))
            avail = max(1, view_w - 2 * margin - node_w)
            return {
                item: (margin + (avail * i / max(1, count - 1)), y)
                for i, item in enumerate(items)
            }

        function_pos = positions(functions, function_y)
        module_labels = modules[:6] or ["current source"]
        module_pos = positions(module_labels, module_y)
        external_names = sorted({callee for _, callee in external_calls})[:8]
        external_pos = positions(external_names, external_y)

        nodes = {}
        for mod, pos in module_pos.items():
            node = GraphNode(mod, pos[0], pos[1], node_w, node_h, theme.qcolor("muted"), theme.qcolor("surface_alt"))
            self.scene.addItem(node)
            nodes[mod] = node

        for func, pos in function_pos.items():
            node = GraphNode(func, pos[0], pos[1], node_w, node_h, theme.qcolor("accent"), theme.qcolor("surface"))
            self.scene.addItem(node)
            nodes[func] = node

        for ext, pos in external_pos.items():
            node = GraphNode(ext, pos[0], pos[1], node_w, node_h, theme.qcolor("ok"), theme.qcolor("ok_soft"))
            self.scene.addItem(node)
            nodes[ext] = node

        for mod in module_labels:
            for func in functions:
                edge = GraphEdge(nodes[mod], nodes[func], theme.qcolor("border"), 1.5)
                self.scene.addItem(edge)

        for caller, callee in edges:
            if caller in nodes and callee in nodes:
                edge = GraphEdge(nodes[caller], nodes[callee], theme.qcolor("accent"), 2.0)
                self.scene.addItem(edge)

        for caller, callee in external_calls:
            if caller in nodes and callee in nodes:
                edge = GraphEdge(nodes[caller], nodes[callee], theme.qcolor("ok"), 1.5)
                self.scene.addItem(edge)


class CFGWidget(QGraphicsView):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("Console")
        self.setMinimumHeight(400)
        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setBackgroundBrush(theme.qcolor("surface"))
        theme.on_change(lambda m, t: self.setBackgroundBrush(theme.qcolor("surface")))

    def update_graph(self, functions_data):
        self.scene.clear()
        if not functions_data:
            t = self.scene.addText("No functions found for CFG analysis.")
            t.setDefaultTextColor(theme.qcolor("muted"))
            t.setFont(theme.ui_font(12))
            return

        y_offset = 50
        margin_x = 100
        for func in functions_data:
            nodes_data = func["nodes"]
            edges_data = func["edges"]
            node_map = {}
            node_w, node_h = 180, 50

            f_lbl = self.scene.addText(f"FUNCTION: {func['name']}")
            f_lbl.setFont(theme.ui_font(11, bold=True))
            f_lbl.setDefaultTextColor(theme.qcolor("accent"))
            f_lbl.setPos(margin_x, y_offset - 30)

            for n in nodes_data:
                border = {
                    "entry": theme.qcolor("info"),
                    "exit": theme.qcolor("error"),
                    "branch": theme.qcolor("warn"),
                    "stmt": theme.qcolor("border"),
                }.get(n["type"], theme.qcolor("border"))

                fill = {
                    "entry": theme.qcolor("surface_alt"),
                    "exit": theme.qcolor("error_soft"),
                    "branch": theme.qcolor("warn_soft"),
                    "stmt": theme.qcolor("surface"),
                }.get(n["type"], theme.qcolor("surface"))

                node = GraphNode(n["label"], margin_x, y_offset, node_w, node_h, border, fill)
                self.scene.addItem(node)
                node_map[n["id"]] = node
                y_offset += 75

            for start_id, end_id in edges_data:
                if start_id in node_map and end_id in node_map:
                    edge = GraphEdge(node_map[start_id], node_map[end_id], theme.qcolor("muted"))
                    self.scene.addItem(edge)

            y_offset += 40


# ── Code Editor & Syntax Highlighter ──────────────────────────────────────────

class LineNumberArea(QWidget):
    def __init__(self, editor: CodeEditor):
        super().__init__(editor)
        self.editor = editor

    def sizeHint(self):
        return QSize(self.editor.line_number_area_width(), 0)

    def paintEvent(self, event):
        self.editor.line_number_area_paint_event(event)


class CodeEditor(QPlainTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("Editor")
        self.setFont(theme.mono_font(13))
        # Line number margin fix so gutter does not overlap first character
        self.document().setDocumentMargin(10)

        self.line_number_area = LineNumberArea(self)
        self.blockCountChanged.connect(self.update_line_number_area_width)
        self.updateRequest.connect(self.update_line_number_area)
        self.cursorPositionChanged.connect(self.highlight_current_line)

        self.error_line = None
        self.errors = []
        self.fixed_lines = set()

        self.update_line_number_area_width(0)
        self.highlight_current_line()
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)

        fm = self.fontMetrics()
        self.setTabStopDistance(4 * fm.horizontalAdvance(' '))

        theme.on_change(lambda m, t: self._on_theme_changed())

    def _on_theme_changed(self):
        self.setFont(theme.mono_font(13))
        self.highlight_current_line()
        self.line_number_area.update()

    def set_errors(self, errors):
        self.errors = errors
        self.highlight_current_line()
        self.viewport().update()

    def set_fixed_lines(self, lines):
        self.fixed_lines = set(lines)
        self.highlight_current_line()
        self.viewport().update()

    def clear_fixed_lines(self):
        self.fixed_lines.clear()
        self.highlight_current_line()
        self.viewport().update()

    def line_number_area_width(self):
        digits = 1
        max_blocks = max(1, self.blockCount())
        while max_blocks >= 10:
            max_blocks /= 10
            digits += 1
        # Added ~12px padding so numbers never clip code
        return 17 + self.fontMetrics().horizontalAdvance('9') * digits

    def update_line_number_area_width(self, _):
        self.setViewportMargins(self.line_number_area_width(), 0, 0, 0)

    def update_line_number_area(self, rect, dy):
        if dy:
            self.line_number_area.scroll(0, dy)
        else:
            self.line_number_area.update(0, rect.y(), self.line_number_area.width(), rect.height())
        if rect.contains(self.viewport().rect()):
            self.update_line_number_area_width(0)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        cr = self.contentsRect()
        self.line_number_area.setGeometry(QRect(cr.left(), cr.top(), self.line_number_area_width(), cr.height()))

    def line_number_area_paint_event(self, event):
        painter = QPainter(self.line_number_area)
        painter.fillRect(event.rect(), theme.qcolor("editor_bg"))

        block = self.firstVisibleBlock()
        block_number = block.blockNumber()
        top = round(self.blockBoundingGeometry(block).translated(self.contentOffset()).top())
        bottom = top + round(self.blockBoundingRect(block).height())

        pen_normal = theme.qcolor("gutter_fg")
        pen_error = theme.qcolor("accent")
        font_normal = theme.mono_font(13)
        font_bold = theme.mono_font(13, bold=True)

        while block.isValid() and top <= event.rect().bottom():
            if block.isVisible() and bottom >= event.rect().top():
                number = str(block_number + 1)
                if self.error_line and block_number + 1 == self.error_line:
                    painter.setPen(pen_error)
                    painter.setFont(font_bold)
                else:
                    painter.setPen(pen_normal)
                    painter.setFont(font_normal)

                painter.drawText(
                    0, top, self.line_number_area.width() - 8, self.fontMetrics().height(),
                    Qt.AlignmentFlag.AlignRight, number
                )
            block = block.next()
            top = bottom
            bottom = top + round(self.blockBoundingRect(block).height())
            block_number += 1

    def highlight_current_line(self):
        extraSelections = []

        if not self.isReadOnly():
            selection = QTextEdit.ExtraSelection()
            selection.format.setBackground(theme.qcolor("current_line"))
            selection.format.setProperty(QTextFormat.Property.FullWidthSelection, True)
            selection.cursor = self.textCursor()
            selection.cursor.clearSelection()
            extraSelections.append(selection)

        fixed_bg = theme.qcolor("fixed_line")
        for line in self.fixed_lines:
            fixed_selection = QTextEdit.ExtraSelection()
            fixed_selection.format.setBackground(fixed_bg)
            fixed_selection.format.setProperty(QTextFormat.Property.FullWidthSelection, True)
            cursor = QTextCursor(self.document())
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            if line > 1:
                cursor.movePosition(QTextCursor.MoveOperation.Down, n=line - 1)
            fixed_selection.cursor = cursor
            extraSelections.append(fixed_selection)

        for err in self.errors:
            line = err.get("line")
            col = err.get("column")
            etype = (err.get("error_type") or err.get("type") or "error").lower()
            if not line or line <= 0:
                continue

            error_selection = QTextEdit.ExtraSelection()
            fmt = QTextCharFormat()
            underline_color = theme.qcolor("error") if etype == "error" else theme.qcolor("warn")
            fmt.setUnderlineColor(underline_color)
            fmt.setUnderlineStyle(QTextCharFormat.UnderlineStyle.SpellCheckUnderline)
            error_selection.format = fmt

            cursor = QTextCursor(self.document())
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            cursor.movePosition(QTextCursor.MoveOperation.Down, n=line - 1)

            if col and col > 0:
                cursor.movePosition(QTextCursor.MoveOperation.StartOfLine)
                cursor.movePosition(QTextCursor.MoveOperation.Right, n=col - 1)
                cursor.movePosition(QTextCursor.MoveOperation.NextWord, QTextCursor.MoveMode.KeepAnchor)
            else:
                cursor.movePosition(QTextCursor.MoveOperation.StartOfLine)
                cursor.movePosition(QTextCursor.MoveOperation.EndOfLine, QTextCursor.MoveMode.KeepAnchor)

            error_selection.cursor = cursor
            extraSelections.append(error_selection)

        self.setExtraSelections(extraSelections)

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Backspace and event.modifiers() & (Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.MetaModifier):
            cursor = self.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.StartOfLine, QTextCursor.MoveMode.KeepAnchor)
            cursor.removeSelectedText()
            return

        if event.key() == Qt.Key.Key_Backspace and event.modifiers() & Qt.KeyboardModifier.AltModifier:
            cursor = self.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.PreviousWord, QTextCursor.MoveMode.KeepAnchor)
            cursor.removeSelectedText()
            return

        if event.key() == Qt.Key.Key_Backspace and not event.modifiers():
            cursor = self.textCursor()
            if cursor.atBlockStart() and not cursor.atStart():
                cursor.deletePreviousChar()
                return

        if event.key() == Qt.Key.Key_Tab:
            self.insertPlainText("    ")
            return

        if event.key() == Qt.Key.Key_Return:
            cursor = self.textCursor()
            current_line = cursor.block().text()
            indentation = ""
            for char in current_line:
                if char.isspace():
                    indentation += char
                else:
                    break
            if current_line.strip().endswith('{'):
                indentation += "    "
            super().keyPressEvent(event)
            self.insertPlainText(indentation)
            return

        super().keyPressEvent(event)


class CppSyntaxHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.rules: List[Tuple[re.Pattern, QTextCharFormat]] = []
        self._build_rules()
        theme.on_change(lambda m, t: self._on_theme_changed())

    def _on_theme_changed(self):
        self._build_rules()
        self.rehighlight()

    def _build_rules(self):
        self.rules = []
        kw_fmt = theme.syntax_format("keyword", bold=True)
        keywords = [
            "int", "return", "if", "else", "for", "while", "class", "public", "private",
            "protected", "void", "namespace", "using", "auto", "double", "float", "char",
            "bool", "string", "vector", "const", "static", "struct", "template", "typename",
            "switch", "case", "break", "continue", "default", "new", "delete", "sizeof"
        ]
        for w in keywords:
            self.rules.append((re.compile(r"\b" + w + r"\b"), kw_fmt))

        type_fmt = theme.syntax_format("type")
        types = ["size_t", "uint32_t", "int64_t", "uint64_t", "pair", "map", "set", "unordered_map", "unordered_set", "shared_ptr", "unique_ptr"]
        for t in types:
            self.rules.append((re.compile(r"\b" + t + r"\b"), type_fmt))

        preproc_fmt = theme.syntax_format("preproc")
        self.rules.append((re.compile(r"#[a-zA-Z_]+"), preproc_fmt))

        str_fmt = theme.syntax_format("string")
        self.rules.append((re.compile(r'".*?"'), str_fmt))
        self.rules.append((re.compile(r"'.*?'"), str_fmt))

        num_fmt = theme.syntax_format("number")
        self.rules.append((re.compile(r"\b[0-9]+(?:\.[0-9]+)?\b"), num_fmt))

        comment_fmt = theme.syntax_format("comment")
        self.rules.append((re.compile(r"//[^\n]*"), comment_fmt))

    def highlightBlock(self, text: str):
        for pattern, fmt in self.rules:
            for match in pattern.finditer(text):
                start, end = match.span()
                self.setFormat(start, end - start, fmt)


# ── Terminal Display ──────────────────────────────────────────────────────────

class TerminalDisplay(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("Console")
        self.setReadOnly(True)
        self.setFont(theme.mono_font(12))
        self.process: Optional[QProcess] = None
        self.prompt_pos = 0

    def append_output(self, text: str, is_html: bool = False):
        self.setReadOnly(False)
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.setTextCursor(cursor)
        if is_html:
            self.insertHtml(text)
        else:
            self.insertPlainText(text)
        self.prompt_pos = self.document().characterCount() - 1
        self.ensureCursorVisible()
        if not (self.process and self.process.state() == QProcess.ProcessState.Running):
            self.setReadOnly(True)


# ── Generic Reusable CustomFrame ──────────────────────────────────────────────

class CustomFrame(QFrame):
    """Container wrapped in a Card frame with a title header."""
    def __init__(self, title: str, left_padding: bool = False, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        header_bar = QWidget()
        hb_lay = QHBoxLayout(header_bar)
        hb_lay.setContentsMargins(16, 12, 16, 12)
        self.header = QLabel(title)
        self.header.setObjectName("Title")
        hb_lay.addWidget(self.header)
        hb_lay.addStretch(1)
        lay.addWidget(header_bar)

        div = QFrame()
        div.setObjectName("Divider")
        lay.addWidget(div)

        self.content_widget = QWidget()
        self.content_layout = QVBoxLayout(self.content_widget)
        pad = 16 if left_padding else 12
        self.content_layout.setContentsMargins(pad, pad, pad, pad)
        self.content_layout.setSpacing(10)
        lay.addWidget(self.content_widget, 1)

    def set_title(self, title: str):
        self.header.setText(title)

    def apply_theme(self, theme_dict=None):
        pass


# ── Worker Threads ────────────────────────────────────────────────────────────

class ASTWorker(QThread):
    finished = pyqtSignal(list)

    def __init__(self, file_path, code=""):
        super().__init__()
        self.file_path = file_path
        self.code = code

    def run(self):
        try:
            ast_raw = extract_ast(self.file_path, code=self.code)
            if ast_raw:
                ast_tree = parse_ast_to_tree(ast_raw, self.file_path)
                self.finished.emit(ast_tree)
            else:
                self.finished.emit([])
        except Exception:
            self.finished.emit([])


class CompilerWorker(QThread):
    finished = pyqtSignal(str, str, int)

    def __init__(self, cmd):
        super().__init__()
        self.cmd = cmd

    def run(self):
        try:
            result = subprocess.run(self.cmd, capture_output=True, text=True)
            self.finished.emit(result.stdout, result.stderr, result.returncode)
        except Exception as e:
            self.finished.emit("", str(e), -1)


class RunnerWorker(QThread):
    finished = pyqtSignal(str, str, int)

    def __init__(self, cmd):
        super().__init__()
        self.cmd = cmd

    def run(self):
        try:
            result = subprocess.run(self.cmd, capture_output=True, text=True, timeout=5)
            self.finished.emit(result.stdout, result.stderr, result.returncode)
        except subprocess.TimeoutExpired as e:
            self.finished.emit(e.stdout.decode() if e.stdout else "", "Timeout expired after 5s", -1)
        except Exception as e:
            self.finished.emit("", str(e), -1)


class SyntaxWorker(QThread):
    finished = pyqtSignal(list)

    def __init__(self, code, file_path):
        super().__init__()
        self.code = code
        self.file_path = file_path

    def run(self):
        try:
            from compiler_runner import _sanitize_code
            if not _sanitize_code(self.code):
                self.finished.emit([{
                    "line": 1,
                    "column": 1,
                    "error_type": "error",
                    "message": "Security Error: Malicious command injection or forbidden system call detected."
                }])
                return

            dir_name = os.path.dirname(os.path.abspath(self.file_path)) if self.file_path else tempfile.gettempdir()
            fd, temp_path = tempfile.mkstemp(suffix=".cpp", dir=dir_name)
            with os.fdopen(fd, 'w', encoding="utf-8") as f:
                f.write(self.code)

            res = subprocess.run(
                ["g++", "-fsyntax-only", "-std=c++17", temp_path],
                capture_output=True, text=True
            )
            errors = []
            pattern = r"(.+):(\d+):(\d+):\s+(error|warning):\s+(.*)"
            for line in res.stderr.splitlines():
                m = re.match(pattern, line)
                if m and (temp_path in m.group(1) or os.path.basename(temp_path) in m.group(1)):
                    errors.append({
                        "line": int(m.group(2)),
                        "column": int(m.group(3)),
                        "error_type": m.group(4),
                        "message": m.group(5)
                    })
            if os.path.exists(temp_path):
                os.remove(temp_path)
            self.finished.emit(errors)
        except Exception:
            self.finished.emit([])


# ── Sidebar Navigation ────────────────────────────────────────────────────────

class Sidebar(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("Sidebar")
        self.is_collapsed = False
        self.expanded_width = 200
        self.collapsed_width = 56
        self.setFixedWidth(self.expanded_width)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 12, 8, 12)
        lay.setSpacing(4)

        self.sec_lbl = section_label("NAVIGATION")
        lay.addWidget(self.sec_lbl)

        self.btn1 = self._create_btn("💻", "Code Editor", "Main C++ editor, diagnostics, and I/O runner")
        self.btn2 = self._create_btn("🌳", "AST Explorer", "Abstract Syntax Tree hierarchy viewer")
        self.btn3 = self._create_btn("⚡", "Energy Metrics", "Real-time energy consumption and carbon emissions")
        self.btn4 = self._create_btn("🔄", "Call Graph", "Function call relationship diagram")
        self.btn5 = self._create_btn("🛡️", "Security Scan", "Static security vulnerability inspection")
        self.btn6 = self._create_btn("🔀", "Control Flow", "Control flow graph (CFG) visualizer")
        self.btn7 = self._create_btn("🧠", "Second Opinion", "ML Classifier vs Regex error categorization")
        self.btn8 = self._create_btn("📊", "Benchmark", "Measured accuracy benchmark comparison")

        self.buttons = [
            self.btn1, self.btn2, self.btn3, self.btn4,
            self.btn5, self.btn6, self.btn7, self.btn8
        ]

        for btn in self.buttons:
            lay.addWidget(btn)

        lay.addStretch(1)

        self.btn_toggle = QPushButton("«  Collapse")
        self.btn_toggle.setObjectName("NavButton")
        self.btn_toggle.setToolTip("Toggle Sidebar (Collapse / Expand)")
        self.btn_toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_toggle.clicked.connect(self.toggle_collapse)
        lay.addWidget(self.btn_toggle)

    def _create_btn(self, icon: str, label: str, tooltip: str) -> QPushButton:
        btn = QPushButton(f"{icon}  {label}")
        btn.setObjectName("NavButton")
        btn.icon_symbol = icon
        btn.label_text = label
        btn.setToolTip(f"{label}: {tooltip}")
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        return btn

    def set_active(self, index: int):
        for i, btn in enumerate(self.buttons):
            theme.set_prop(btn, "active", "true" if i == index else "false")

    def toggle_collapse(self):
        self.is_collapsed = not self.is_collapsed
        w = self.collapsed_width if self.is_collapsed else self.expanded_width
        self.setFixedWidth(w)
        self.sec_lbl.setVisible(not self.is_collapsed)
        self.btn_toggle.setText("»" if self.is_collapsed else "«  Collapse")
        for btn in self.buttons:
            if self.is_collapsed:
                btn.setText(btn.icon_symbol)
            else:
                btn.setText(f"{btn.icon_symbol}  {btn.label_text}")


# ── Analysis Pages ────────────────────────────────────────────────────────────

class ASTDiagramWidget(QGraphicsView):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("Console")
        self.setMinimumHeight(400)
        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setBackgroundBrush(theme.qcolor("surface"))
        theme.on_change(lambda m, t: self.setBackgroundBrush(theme.qcolor("surface")))

    def update_diagram(self, ast_tree):
        self.scene.clear()
        if not ast_tree:
            t = self.scene.addText("No AST nodes available to render diagram.")
            t.setDefaultTextColor(theme.qcolor("muted"))
            t.setFont(theme.ui_font(12))
            return

        node_w, node_h = 160, 44
        level_gap = 85
        sibling_gap = 180

        def compute_width(node):
            children = node.get("children", [])
            if not children:
                return 1
            return max(1, sum(compute_width(c) for c in children))

        def layout_node(node, x, y):
            ntype = node.get("type", "Node")
            details = node.get("details", "")
            short_details = (details[:14] + "..") if len(details) > 14 else details
            label = f"{ntype}\n{short_details}" if short_details else ntype

            border = theme.qcolor("accent")
            fill = theme.qcolor("surface")
            if "Decl" in ntype:
                border = theme.qcolor("accent")
                fill = theme.qcolor("surface_alt")
            elif "Stmt" in ntype:
                border = theme.qcolor("warn")
                fill = theme.qcolor("warn_soft")
            elif "Expr" in ntype:
                border = theme.qcolor("ok")
                fill = theme.qcolor("ok_soft")

            gnode = GraphNode(label, x - node_w / 2, y, node_w, node_h, border, fill)
            self.scene.addItem(gnode)

            children = node.get("children", [])
            if children:
                total_w = sum(compute_width(c) for c in children)
                current_x = x - (total_w * sibling_gap) / 2
                for c in children:
                    cw = compute_width(c)
                    child_cx = current_x + (cw * sibling_gap) / 2
                    child_gnode = layout_node(c, child_cx, y + level_gap)
                    edge = GraphEdge(gnode, child_gnode, theme.qcolor("muted"), 1.5)
                    self.scene.addItem(edge)
                    current_x += cw * sibling_gap

            return gnode

        start_x = 350
        start_y = 40
        for r in ast_tree:
            w_units = compute_width(r)
            layout_node(r, start_x + (w_units * sibling_gap) / 2, start_y)
            start_x += (w_units + 1) * sibling_gap


class ASTPage(CustomFrame):
    def __init__(self, parent=None):
        super().__init__("ABSTRACT SYNTAX TREE EXPLORER & DIAGRAM", left_padding=True)

        action_bar = QHBoxLayout()
        action_bar.setContentsMargins(0, 0, 0, 6)
        action_bar.setSpacing(8)

        self.info_lbl = QLabel("Parsed Abstract Syntax Tree representing your C++ declarations, statements, and expressions.")
        self.info_lbl.setObjectName("Muted")
        self.info_lbl.setWordWrap(True)
        action_bar.addWidget(self.info_lbl, 1)

        self.btn_reload = QPushButton("🔄 Reload AST")
        self.btn_reload.setProperty("variant", "ghost")
        self.btn_reload.setCursor(Qt.CursorShape.PointingHandCursor)
        action_bar.addWidget(self.btn_reload)

        self.btn_expand = QPushButton("➕ Expand All")
        self.btn_expand.setProperty("variant", "ghost")
        self.btn_expand.setCursor(Qt.CursorShape.PointingHandCursor)
        action_bar.addWidget(self.btn_expand)

        self.btn_collapse = QPushButton("➖ Collapse All")
        self.btn_collapse.setProperty("variant", "ghost")
        self.btn_collapse.setCursor(Qt.CursorShape.PointingHandCursor)
        action_bar.addWidget(self.btn_collapse)

        self.content_layout.addLayout(action_bar)

        self.ast_tabs = QTabWidget()
        self.tabs = self.ast_tabs
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["NODE TYPE", "DETAILS / SOURCE"])
        self.tree.setColumnWidth(0, 320)
        self.tree.setAlternatingRowColors(True)

        self.diagram = ASTDiagramWidget()

        self.ast_tabs.addTab(self.tree, "🌳 Tree View")
        self.ast_tabs.addTab(self.diagram, "📐 Visual Graph Diagram")
        self.content_layout.addWidget(self.ast_tabs, 1)

        self.btn_expand.clicked.connect(self.tree.expandAll)
        self.btn_collapse.clicked.connect(self.tree.collapseAll)

    def update_tree(self, ast_tree):
        self.tree.clear()
        if not ast_tree:
            empty_item = QTreeWidgetItem(self.tree.invisibleRootItem())
            empty_item.setText(0, "No AST Nodes")
            empty_item.setText(1, "Click 'Compile' or 'Reload AST' to parse your C++ code into an AST tree.")
            self.diagram.update_diagram([])
            return
        self._populate(ast_tree, self.tree.invisibleRootItem())
        self.tree.expandToDepth(2)
        self.diagram.update_diagram(ast_tree)

    def _populate(self, nodes, parent_item):
        for n in nodes:
            item = QTreeWidgetItem(parent_item)
            ntype = n.get("type", "Unknown")
            item.setText(0, ntype)
            item.setText(1, n.get("details", ""))

            # Colorize node label based on syntax category
            if "Decl" in ntype:
                item.setForeground(0, QColor(CURRENT_THEME.get("accent", "#6C7BFF")))
            elif "Stmt" in ntype:
                item.setForeground(0, QColor(CURRENT_THEME.get("syn_keyword", "#8E9BFF")))
            elif "Expr" in ntype:
                item.setForeground(0, QColor(CURRENT_THEME.get("ok", "#3DBE8B")))
            elif "Literal" in ntype:
                item.setForeground(0, QColor(CURRENT_THEME.get("warn", "#E8B339")))
            else:
                item.setForeground(0, QColor(CURRENT_THEME.get("muted", "#8B95A7")))
            item.setForeground(1, QColor(CURRENT_THEME.get("muted", "#8B95A7")))

            if n.get("children"):
                self._populate(n["children"], item)


class EnergyPage(CustomFrame):
    def __init__(self, parent=None):
        super().__init__("CODECARBON INDEX :: ENERGY TELEMETRY", left_padding=True)

        self.desc = QLabel("Real-time power usage, carbon emissions, execution duration, and Linux RAPL readings.")
        self.desc.setObjectName("Muted")
        self.content_layout.addWidget(self.desc)

        self.metric_row = QWidget()
        metric_layout = QHBoxLayout(self.metric_row)
        metric_layout.setContentsMargins(0, 0, 0, 0)
        metric_layout.setSpacing(12)

        self.power_card, self.power_title, self.power_value = self._create_card("POWER USAGE", "0.000 mW")
        self.carbon_card, self.carbon_title, self.carbon_value = self._create_card("CARBON INTENSITY", "0.000 mgCO2/Wh")
        self.time_card, self.time_title, self.time_value = self._create_card("EXECUTION TIME", "0.000 s")
        self.rapl_card, self.rapl_title, self.rapl_value = self._create_card("RAPL STATUS", "Unavailable")

        for c in [self.power_card, self.carbon_card, self.time_card, self.rapl_card]:
            metric_layout.addWidget(c)
        self.content_layout.addWidget(self.metric_row)

        self.graph = MetricsGraph()
        self.content_layout.addWidget(self.graph, 1)

        self.notes = QTextBrowser()
        self.notes.setObjectName("Console")
        self.notes.setFont(theme.mono_font(12))
        self.notes.setMaximumHeight(110)
        self.content_layout.addWidget(self.notes)

        self.btn_download_csv = QPushButton("📥 Download CSV Report")
        self.btn_download_csv.setProperty("variant", "ghost")
        self.btn_download_csv.clicked.connect(self._download_csv)
        self.content_layout.addWidget(self.btn_download_csv, 0, Qt.AlignmentFlag.AlignRight)

        self.update_metrics(0, 0, 0, "Unavailable", "CodeCarbon has not produced a sample yet.")

        self.csv_path = "emissions.csv"
        self.poll_timer = QTimer(self)
        self.poll_timer.setInterval(1000)
        self.poll_timer.timeout.connect(self._poll_csv)
        self.poll_timer.start()

    def _create_card(self, title_text: str, value_text: str):
        card = QFrame()
        card.setObjectName("Card")
        lay = QVBoxLayout(card)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(4)
        sec = section_label(title_text)
        val = QLabel(value_text)
        val.setObjectName("Title")
        lay.addWidget(sec)
        lay.addWidget(val)
        return card, sec, val

    def _download_csv(self):
        if not os.path.exists(self.csv_path):
            QMessageBox.information(self, "No Data", "CodeCarbon has not produced a report yet.")
            return
        save_path, _ = QFileDialog.getSaveFileName(self, "Save CSV Report", "codecarbon_emissions.csv", "CSV Files (*.csv)")
        if save_path:
            import shutil
            try:
                shutil.copy2(self.csv_path, save_path)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save CSV:\n{e}")

    def _poll_csv(self):
        if not os.path.exists(self.csv_path):
            return
        try:
            import csv
            with open(self.csv_path, "r", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            if not rows:
                return
            latest = rows[-1]
            energy_kwh = float(latest.get("energy_consumed", 0))
            power_mw = energy_kwh * 1_000_000
            emissions_kg = float(latest.get("emissions", 0))
            carbon_mg = emissions_kg * 1_000_000
            duration = float(latest.get("duration", 0))
            intensity = carbon_mg / power_mw if power_mw > 0 else 0.0
            rapl_j = _read_rapl_energy_joules()
            rapl_str = f"{rapl_j:.2f} J" if rapl_j is not None else "Linux RAPL Unavailable"
            self.update_metrics(power_mw, intensity, duration, rapl_str, f"CodeCarbon poll #{len(rows)} | {latest.get('timestamp')}")
        except Exception:
            pass

    def update_metrics(self, power_mw, carbon_mg_per_wh, execution_time, rapl_text, note):
        self.power_value.setText(f"{power_mw:.3f} mW")
        self.carbon_value.setText(f"{carbon_mg_per_wh:.3f} mgCO2/Wh")
        self.time_value.setText(f"{execution_time:.3f} s")
        self.rapl_value.setText(str(rapl_text))
        self.graph.add_sample(power_mw, carbon_mg_per_wh, execution_time)
        self.notes.setPlainText(
            f"Telemetry Source: {note}\n"
            f"RAPL: Reads Linux powercap energy counters when available (/sys/class/powercap)."
        )


class CallGraphPage(CustomFrame):
    def __init__(self, parent=None):
        super().__init__("CALL GRAPH :: ARCHITECTURE ANALYSIS", left_padding=True)
        self.summary = QLabel("Visualizing function call relationships, dependencies, and external module boundaries.")
        self.summary.setObjectName("Muted")
        self.content_layout.addWidget(self.summary)
        self.graph = CallGraphWidget()
        self.content_layout.addWidget(self.graph, 1)


class CFGPage(CustomFrame):
    def __init__(self, parent=None):
        super().__init__("CONTROL FLOW GRAPH :: EXECUTION PATHS", left_padding=True)
        self.summary = QLabel("Visualizing the logical structure, branches, and execution paths of your C++ functions.")
        self.summary.setObjectName("Muted")
        self.content_layout.addWidget(self.summary)
        self.graph = CFGWidget()
        self.content_layout.addWidget(self.graph, 1)


class SecurityCard(QFrame):
    """Vulnerability finding styled with an IssueCard severity strip."""
    def __init__(self, finding: dict, parent=None):
        super().__init__(parent)
        self.setObjectName("IssueCard")

        sev = str(finding.get("severity", "Low")).lower()
        sev_prop = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(sev, "note")
        sev_tone = {"critical": "error", "high": "error", "medium": "warn", "low": "ok"}.get(sev, "muted")
        self.setProperty("sev", sev_prop)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(8)

        top = QHBoxLayout()
        top.setSpacing(8)
        top.addWidget(badge(sev.upper(), sev_tone))
        vuln = finding.get("vulnerability_type", "Security Finding")
        top.addWidget(plain_label(vuln, "IssueTitle"))
        top.addStretch()

        line_no = finding.get("line")
        loc_str = finding.get("location") or (f"Line {line_no}" if line_no else "")
        if loc_str:
            loc_lbl = QLabel(loc_str)
            loc_lbl.setObjectName("Muted")
            top.addWidget(loc_lbl)
        lay.addLayout(top)

        desc = finding.get("description", "")
        if desc:
            lay.addWidget(plain_label(desc))

        rec = finding.get("recommendation", "")
        if rec:
            lay.addWidget(section_label("RECOMMENDATION"))
            lay.addWidget(plain_label(rec))

        fix = finding.get("suggested_fix") or finding.get("fix") or ""
        if fix:
            lay.addWidget(section_label("SUGGESTED FIX"))
            lay.addWidget(code_block(fix, copy_button=True))


class SecurityPage(CustomFrame):
    def __init__(self, parent=None):
        super().__init__("SECURITY ANALYZER :: VULNERABILITY REPORT", left_padding=True)
        self.findings = []
        self.current_filter = "All"

        header_row = QHBoxLayout()
        header_row.setSpacing(12)

        title_box = QVBoxLayout()
        title_box.setSpacing(2)
        self.summary = QLabel("0 findings detected")
        self.summary.setObjectName("Title")
        title_box.addWidget(self.summary)

        self.subsummary = QLabel("Grouped security findings with exact source lines and secure remediation guidance.")
        self.subsummary.setObjectName("Muted")
        title_box.addWidget(self.subsummary)
        header_row.addLayout(title_box, 1)

        self.risk_badge = badge("Risk Score: 0 • Clean", "ok")
        header_row.addWidget(self.risk_badge, 0, Qt.AlignmentFlag.AlignTop)
        self.content_layout.addLayout(header_row)

        # Sanitizer Policies
        pbox = QFrame()
        pbox.setObjectName("Card")
        pbox_lay = QHBoxLayout(pbox)
        pbox_lay.setContentsMargins(12, 8, 12, 8)
        pbox_lay.setSpacing(14)
        pbox_lay.addWidget(section_label("SANITIZER POLICY:"))

        self.perm_system_calls = QCheckBox("Allow System Calls")
        self.perm_assembly = QCheckBox("Allow Inline Assembly")
        self.perm_sys_includes = QCheckBox("Allow <sys/*>")

        for chk in [self.perm_system_calls, self.perm_assembly, self.perm_sys_includes]:
            pbox_lay.addWidget(chk)
            chk.stateChanged.connect(self._update_permissions)
        pbox_lay.addStretch(1)
        self.content_layout.addWidget(pbox)
        self._update_permissions()

        self.risk_bar = QProgressBar()
        self.risk_bar.setRange(0, 100)
        self.risk_bar.setTextVisible(False)
        self.content_layout.addWidget(self.risk_bar)

        # Filter buttons
        filter_row = QHBoxLayout()
        filter_row.setSpacing(8)
        self.filter_buttons = {}
        for label in ["All", "High", "Medium", "Low"]:
            btn = QPushButton(label)
            btn.setProperty("variant", "primary" if label == "All" else "ghost")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda _c=False, val=label: self.set_filter(val))
            self.filter_buttons[label] = btn
            filter_row.addWidget(btn)
        filter_row.addStretch(1)
        self.content_layout.addLayout(filter_row)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.report_host = QWidget()
        self.report_layout = QVBoxLayout(self.report_host)
        self.report_layout.setContentsMargins(0, 0, 0, 0)
        self.report_layout.setSpacing(10)
        self.report_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.scroll.setWidget(self.report_host)
        self.content_layout.addWidget(self.scroll, 1)

        self.update_report([])

    def _normalize_findings(self, findings):
        normalized = []
        for f in findings or []:
            if hasattr(f, "to_dict"):
                normalized.append(f.to_dict())
            elif isinstance(f, dict):
                normalized.append(f)
        return normalized

    def set_filter(self, val: str):
        self.current_filter = val
        for label, btn in self.filter_buttons.items():
            theme.set_prop(btn, "variant", "primary" if label == val else "ghost")
        self._render()

    def update_report(self, findings):
        self.findings = self._normalize_findings(findings)
        self._render()

    def _render(self):
        while self.report_layout.count():
            item = self.report_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        score = 0
        weights = {"Critical": 10, "High": 5, "Medium": 2, "Low": 1}

        for f in self.findings:
            sev = str(f.get("severity", "Low")).capitalize()
            if sev in counts:
                counts[sev] += 1
            score += weights.get(sev, 1)

        self.summary.setText(f"{counts['Critical']} critical, {counts['High']} high, {counts['Medium']} medium, {counts['Low']} low findings")
        risk_text = "Clean" if score == 0 else ("Low Risk" if score <= 10 else ("Moderate" if score <= 30 else "High Risk"))
        tone = "ok" if score == 0 else ("warn" if score <= 30 else "error")
        self.risk_badge.setText(f"Risk Score: {score} • {risk_text}")
        theme.set_prop(self.risk_badge, "tone", tone)
        self.risk_bar.setValue(min(100, score * 4))

        filtered = []
        for f in self.findings:
            sev = str(f.get("severity", "Low")).capitalize()
            if self.current_filter == "All":
                filtered.append(f)
            elif self.current_filter == "High" and sev in ("Critical", "High"):
                filtered.append(f)
            elif self.current_filter == sev:
                filtered.append(f)

        if not filtered:
            self.report_layout.addWidget(plain_label("No security findings detected. Code passes sanitizer checks.", "Muted"))
            return

        for f in filtered:
            self.report_layout.addWidget(SecurityCard(f))

    def _update_permissions(self):
        os.environ["ALLOW_SYSTEM_CALLS"] = "1" if self.perm_system_calls.isChecked() else "0"
        os.environ["ALLOW_ASSEMBLY"] = "1" if self.perm_assembly.isChecked() else "0"
        os.environ["ALLOW_SYS_INCLUDES"] = "1" if self.perm_sys_includes.isChecked() else "0"


# ── Main Application Window ───────────────────────────────────────────────────

class AppGUI(QMainWindow):
    def __init__(self, initial_file: Optional[str] = None):
        super().__init__()
        self.setWindowTitle("🌿 C++ Compiler Error Explainer & Auto-Healer")
        self.resize(1280, 800)
        self.setMinimumSize(1100, 700)

        self.has_cli_file = False
        if initial_file and os.path.isfile(initial_file):
            self.file_path = os.path.abspath(initial_file)
            self.file_name = os.path.basename(self.file_path)
            self.has_cli_file = True
        elif len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
            self.file_path = os.path.abspath(sys.argv[1])
            self.file_name = os.path.basename(self.file_path)
            self.has_cli_file = True
        else:
            self.file_name = "untitled.cpp"
            self.file_path = os.path.join(os.getcwd(), self.file_name)

        self.gcc_version = get_gcc_version()
        self.errors_count = 0
        self.warnings_count = 0
        self.execution_count = 0
        self.manual_co2_offset = 0.0
        self.energy_started_at = time.monotonic()
        self.rapl_start_j = _read_rapl_energy_joules()
        self.latest_security_findings = []
        self.latest_security_report = ""
        self.cumulative_compilation_co2 = 0.0
        self.issue_cards: List[IssueCard] = []
        self.is_dark_mode = (theme.mode() == "dark")
        self.last_heal_backup = None

        # Root container
        root_widget = QWidget()
        root_widget.setObjectName("Root")
        self.setCentralWidget(root_widget)
        root_layout = QVBoxLayout(root_widget)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # ── 1. Top Bar ────────────────────────────────────────────────────────
        top_bar = QFrame()
        top_bar.setObjectName("TopBar")
        top_lay = QHBoxLayout(top_bar)
        top_lay.setContentsMargins(16, 10, 16, 10)
        top_lay.setSpacing(10)

        app_title = QLabel("🌿 C++ Compiler Error Explainer & Auto-Healer")
        app_title.setObjectName("Title")
        top_lay.addWidget(app_title)
        top_lay.addSpacing(16)

        btn_compile = QPushButton("Compile")
        btn_compile.setProperty("variant", "primary")
        btn_compile.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_compile.clicked.connect(self.analyze)
        top_lay.addWidget(btn_compile)

        btn_run = QPushButton("Run")
        btn_run.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_run.clicked.connect(self.run_code)
        top_lay.addWidget(btn_run)

        self.btn_heal = QPushButton("Auto-Heal")
        self.btn_heal.setProperty("variant", "success")
        self.btn_heal.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_heal.setToolTip("Auto-detect and heal compiler errors")
        self.btn_heal.clicked.connect(self.start_heal)
        top_lay.addWidget(self.btn_heal)

        top_lay.addStretch(1)

        btn_load = QPushButton("📂  Load")
        btn_load.setProperty("variant", "ghost")
        btn_load.setToolTip("Load C++ source file")
        btn_load.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_load.clicked.connect(self.load_file)
        top_lay.addWidget(btn_load)

        self.btn_undo_heal = QPushButton("↺  Undo")
        self.btn_undo_heal.setProperty("variant", "ghost")
        self.btn_undo_heal.setToolTip("Restore code to state before auto-heal")
        self.btn_undo_heal.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_undo_heal.clicked.connect(self.undo_heal)
        self.btn_undo_heal.setEnabled(False)
        top_lay.addWidget(self.btn_undo_heal)

        self.btn_theme_toggle = QPushButton("☀️  Light" if self.is_dark_mode else "🌙  Dark")
        self.btn_theme_toggle.setProperty("variant", "ghost")
        self.btn_theme_toggle.setToolTip("Toggle between Light and Dark mode")
        self.btn_theme_toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_theme_toggle.clicked.connect(self.toggle_dark_mode)
        top_lay.addWidget(self.btn_theme_toggle)

        root_layout.addWidget(top_bar)

        # ── 2. Middle Central Split (Sidebar + Stack) ─────────────────────────
        center_row = QWidget()
        center_lay = QHBoxLayout(center_row)
        center_lay.setContentsMargins(0, 0, 0, 0)
        center_lay.setSpacing(0)
        root_layout.addWidget(center_row, 1)

        self.sidebar = Sidebar()
        center_lay.addWidget(self.sidebar)

        self.stack = QStackedWidget()
        center_lay.addWidget(self.stack, 1)

        # ── Stack Index 0: IDE Editor + Console + Problems ────────────────────
        page_editor = QWidget()
        pe_lay = QHBoxLayout(page_editor)
        pe_lay.setContentsMargins(12, 12, 12, 12)
        pe_lay.setSpacing(12)

        self.h_splitter = QSplitter(Qt.Orientation.Horizontal)
        pe_lay.addWidget(self.h_splitter)

        # Editor Column (Vertical Split: Editor Card 70% | Tabs 30%)
        editor_col = QSplitter(Qt.Orientation.Vertical)

        # Editor Card
        editor_card = QFrame()
        editor_card.setObjectName("Card")
        ec_lay = QVBoxLayout(editor_card)
        ec_lay.setContentsMargins(0, 0, 0, 0)
        ec_lay.setSpacing(0)

        file_tab_bar = QWidget()
        ftb_lay = QHBoxLayout(file_tab_bar)
        ftb_lay.setContentsMargins(14, 8, 14, 8)
        self.file_tab_label = QLabel(f"📄  {self.file_name}")
        self.file_tab_label.setObjectName("Muted")
        ftb_lay.addWidget(self.file_tab_label)
        ftb_lay.addStretch(1)
        ec_lay.addWidget(file_tab_bar)

        div_file = QFrame()
        div_file.setObjectName("Divider")
        ec_lay.addWidget(div_file)

        self.editor = CodeEditor()
        self.highlighter = CppSyntaxHighlighter(self.editor.document())
        self.editor.textChanged.connect(self.on_code_changed)
        ec_lay.addWidget(self.editor, 1)
        editor_col.addWidget(editor_card)

        # Bottom Tabs (Output | Input | Log)
        self.tabs = QTabWidget()
        self.terminal = TerminalDisplay()
        self.input_terminal = QPlainTextEdit()
        self.input_terminal.setFont(theme.mono_font(12))
        self.input_terminal.setPlaceholderText("Paste program test cases / standard input (stdin) here...")

        self.log_terminal = QTextBrowser()
        self.log_terminal.setObjectName("Console")
        self.log_terminal.setFont(theme.mono_font(12))

        self.tabs.addTab(self.terminal, "Output")
        self.tabs.addTab(self.input_terminal, "Input (stdin)")
        self.tabs.addTab(self.log_terminal, "Log")
        editor_col.addWidget(self.tabs)

        editor_col.setStretchFactor(0, 7)
        editor_col.setStretchFactor(1, 3)
        self.h_splitter.addWidget(editor_col)

        # Problems Column (~38% width)
        problems_card = QFrame()
        problems_card.setObjectName("Card")
        pc_lay = QVBoxLayout(problems_card)
        pc_lay.setContentsMargins(0, 0, 0, 0)
        pc_lay.setSpacing(0)

        prob_header = QWidget()
        ph_lay = QHBoxLayout(prob_header)
        ph_lay.setContentsMargins(14, 10, 14, 10)
        ph_lay.setSpacing(8)
        ph_lay.addWidget(section_label("PROBLEMS"))
        self.problems_count_badge = badge("0", "ok")
        ph_lay.addWidget(self.problems_count_badge)
        ph_lay.addStretch(1)
        pc_lay.addWidget(prob_header)

        div_prob = QFrame()
        div_prob.setObjectName("Divider")
        pc_lay.addWidget(div_prob)

        self.error_cards_scroll = QScrollArea()
        self.error_cards_scroll.setWidgetResizable(True)
        self.error_cards_widget = QWidget()
        self.error_cards_layout = QVBoxLayout(self.error_cards_widget)
        self.error_cards_layout.setContentsMargins(14, 12, 14, 12)
        self.error_cards_layout.setSpacing(10)
        self.error_cards_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.error_cards_scroll.setWidget(self.error_cards_widget)
        pc_lay.addWidget(self.error_cards_scroll, 1)

        self.h_splitter.addWidget(problems_card)
        self.h_splitter.setStretchFactor(0, 62)
        self.h_splitter.setStretchFactor(1, 38)

        self.stack.addWidget(page_editor)  # Index 0

        # ── Stack Index 1..7: Analysis Pages ──────────────────────────────────
        self.ast_page = ASTPage()
        self.ast_page.btn_reload.clicked.connect(self.switch_to_ast)
        self.stack.addWidget(self.ast_page)  # Index 1

        self.energy_page = EnergyPage()
        self.stack.addWidget(self.energy_page)  # Index 2

        self.call_graph_page = CallGraphPage()
        self.stack.addWidget(self.call_graph_page)  # Index 3

        self.security_page = SecurityPage()
        self.stack.addWidget(self.security_page)  # Index 4

        self.cfg_page = CFGPage()
        self.stack.addWidget(self.cfg_page)  # Index 5

        if NEW_PAGES_AVAILABLE and SecondOpinionPage is not None:
            self.second_opinion_page = SecondOpinionPage()
        else:
            self.second_opinion_page = QWidget()
        self.stack.addWidget(self.second_opinion_page)  # Index 6

        if NEW_PAGES_AVAILABLE and BenchmarkPage is not None:
            self.benchmark_page = BenchmarkPage()
        else:
            self.benchmark_page = QWidget()
        self.stack.addWidget(self.benchmark_page)  # Index 7

        # Sidebar navigation triggers
        self.sidebar.btn1.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        self.sidebar.btn2.clicked.connect(self.switch_to_ast)
        self.sidebar.btn3.clicked.connect(lambda: self.stack.setCurrentIndex(2))
        self.sidebar.btn4.clicked.connect(self.switch_to_call_graph)
        self.sidebar.btn5.clicked.connect(self.switch_to_security)
        self.sidebar.btn6.clicked.connect(self.switch_to_cfg)
        self.sidebar.btn7.clicked.connect(self.switch_to_second_opinion)
        self.sidebar.btn8.clicked.connect(lambda: self.stack.setCurrentIndex(7))

        self.stack.currentChanged.connect(self.sidebar.set_active)
        self.sidebar.set_active(0)

        # Backwards compatibility aliases
        self._btn_second_opinion = self.sidebar.btn7
        self._btn_benchmark = self.sidebar.btn8

        # ── 3. Status Bar ─────────────────────────────────────────────────────
        status_bar = QFrame()
        status_bar.setObjectName("StatusBar")
        sb_lay = QHBoxLayout(status_bar)
        sb_lay.setContentsMargins(16, 6, 16, 6)
        sb_lay.setSpacing(14)

        self.footer_lbl = QLabel()
        self.footer_lbl.setObjectName("Muted")
        sb_lay.addWidget(self.footer_lbl, 1)

        has_llm_keys = False
        ai_status_text = "AI: offline"
        trail_tooltip = "AI: offline"
        try:
            import llm_client
            has_llm_keys = bool(llm_client.get_gemini_key() or llm_client.get_groq_key())
            ai_status_text = llm_client.status()
            trail_tooltip = llm_client.get_status_trail() if hasattr(llm_client, "get_status_trail") else ai_status_text
        except ImportError:
            pass

        self.cb_ai_assist = QCheckBox("AI assist")
        self.cb_ai_assist.setChecked(True)
        self.cb_ai_assist.setEnabled(True)
        self.cb_ai_assist.setToolTip("Sends error messages to Gemini / Groq for explanations with offline fallback")
        self.cb_ai_assist.stateChanged.connect(self._on_ai_assist_toggled)
        sb_lay.addWidget(self.cb_ai_assist)

        self.ai_status_label = QLabel(self._format_ai_status(ai_status_text))
        self.ai_status_label.setObjectName("Muted")
        self.ai_status_label.setToolTip(trail_tooltip)
        sb_lay.addWidget(self.ai_status_label)

        self.status_label = QLabel("STATUS: ● READY")
        self.status_label.setObjectName("Muted")
        sb_lay.addWidget(self.status_label)

        root_layout.addWidget(status_bar)

        # Initialize classifier
        try:
            from error_classifier import get_default_classifier
            self.error_classifier = get_default_classifier()
        except Exception:
            self.error_classifier = _KeywordClassifier()

        # CodeCarbon telemetry tracker
        if CODECARBON_AVAILABLE:
            try:
                self.tracker = EmissionsTracker(
                    save_to_file=False, log_level="error",
                    force_cpu_power=12, force_ram_power=3,
                    force_mode_cpu_load=True, allow_multiple_runs=True,
                )
                self.tracker.start()
            except Exception:
                self.tracker = None

        # If an explicit file was passed, load and analyze it; otherwise start completely empty
        if self.has_cli_file and os.path.exists(self.file_path):
            self.file_tab_label.setText(f"📄  {self.file_name}")
            try:
                with open(self.file_path, "r", encoding="utf-8", errors="ignore") as f:
                    self.editor.setPlainText(f.read())
            except Exception:
                pass
            self.editor.clear_fixed_lines()
            self._update_footer()
            theme.on_change(lambda m, t: self._on_global_theme_changed(m, t))
            QTimer.singleShot(150, self.analyze)
        else:
            self.file_tab_label.setText("📄  untitled.cpp")
            self.editor.setPlainText("")
            self.editor.clear_fixed_lines()
            self._update_footer()
            theme.on_change(lambda m, t: self._on_global_theme_changed(m, t))
            self.status_label.setText("STATUS: ● READY")
            self.problems_count_badge.setText("0")
            theme.set_prop(self.problems_count_badge, "tone", "ok")
            self.terminal.append_output("Ready. Paste or load a C++ source file to compile and analyze.\n")

    def _on_global_theme_changed(self, mode_name: str, tokens: dict):
        global CURRENT_THEME, BG_COLOR, PANE_BG, PANEL_BG, HEADER_BG, BORDER_COLOR
        global PINK, TEXT_MAIN, TEXT_DIM, KEYWORD_COLOR, ERROR_LINE_COLOR, RED, YELLOW, GREEN
        CURRENT_THEME = dict(tokens)
        BG_COLOR = tokens["bg"]
        PANE_BG = tokens["surface"]
        PANEL_BG = PANE_BG
        HEADER_BG = tokens["surface_alt"]
        BORDER_COLOR = tokens["border"]
        PINK = tokens["accent"]
        TEXT_MAIN = tokens["text"]
        TEXT_DIM = tokens["muted"]
        KEYWORD_COLOR = tokens["syn_keyword"]
        ERROR_LINE_COLOR = tokens["error_line"]
        RED = tokens["error"]
        YELLOW = tokens["warn"]
        GREEN = tokens["ok"]

        self.is_dark_mode = (mode_name == "dark")
        self.btn_theme_toggle.setText("☀️  Light" if self.is_dark_mode else "🌙  Dark")
        self._update_footer()

        theme_dict = {
            "PINK": PINK, "PANE_BG": PANE_BG, "BORDER_COLOR": BORDER_COLOR,
            "TEXT_MAIN": TEXT_MAIN, "TEXT_DIM": TEXT_DIM, "BG_COLOR": BG_COLOR,
            "GREEN": GREEN, "RED": RED, "YELLOW": YELLOW,
        }
        if hasattr(self, "second_opinion_page") and hasattr(self.second_opinion_page, "apply_theme"):
            try:
                self.second_opinion_page.apply_theme(theme_dict)
            except Exception:
                pass
        if hasattr(self, "benchmark_page") and hasattr(self.benchmark_page, "apply_theme"):
            try:
                self.benchmark_page.apply_theme(theme_dict)
            except Exception:
                pass

    def toggle_dark_mode(self):
        new_mode = theme.toggle_theme(QApplication.instance())
        self.is_dark_mode = (new_mode == "dark")

    def _format_ai_status(self, text: str) -> str:
        s = (text or "").lower()
        if "ready" in s or "groq ready" in s or "gemini ready" in s:
            return "AI: Ready ●"
        if "groq" in s:
            return "AI: Groq ●"
        if "gemini" in s:
            return "AI: Gemini ●"
        if "offline" in s:
            return "AI: Offline ○"
        return f"AI: {text[:16]} ●"

    def update_ai_status(self):
        try:
            import llm_client
            if not self.is_ai_enabled():
                self.ai_status_label.setText("AI: disabled ○")
            else:
                self.ai_status_label.setText(self._format_ai_status(llm_client.status()))
        except Exception:
            self.ai_status_label.setText("AI: offline ○")

    def _on_ai_assist_toggled(self, state=None):
        self.update_ai_status()
        if self.is_ai_enabled():
            self.request_ai_explanations()

    def request_ai_explanations(self):
        if not self.is_ai_enabled():
            return
        if getattr(self, "ai_explain_worker", None) is not None and self.ai_explain_worker.isRunning():
            return
        errors = list(getattr(self.editor, "errors", []))
        if not errors or not self.issue_cards:
            return
        try:
            from ai_explainer import AIExplainWorker
            self.ai_status_label.setText("AI: analyzing...")
            src_code = self.editor.toPlainText()
            cards_snapshot = list(self.issue_cards)
            self.ai_explain_worker = AIExplainWorker(errors[:5], src_code)

            def on_ai_batch_ready(results_by_idx: dict, provider: str):
                prov = (provider or "AI").capitalize()
                self.ai_status_label.setText(f"AI: {prov} ●")
                for idx, ai_data in results_by_idx.items():
                    if 0 <= idx < len(cards_snapshot):
                        cards_snapshot[idx].add_ai_explanation(ai_data)

            def on_ai_failed(reason: str):
                self.ai_status_label.setText("AI: NLP Local ●")
                try:
                    from ai_explainer import _generate_offline_explanations
                    off_res = _generate_offline_explanations(errors[:5], src_code)
                    for idx, ai_data in off_res.items():
                        if 0 <= idx < len(cards_snapshot):
                            cards_snapshot[idx].add_ai_explanation(ai_data)
                except Exception:
                    pass

            self.ai_explain_worker.batch_ready.connect(on_ai_batch_ready)
            self.ai_explain_worker.failed.connect(on_ai_failed)
            self.ai_explain_worker.start()
        except Exception as ex:
            self.ai_status_label.setText("AI: offline ○")

    def is_ai_enabled(self) -> bool:
        return self.cb_ai_assist.isChecked()

    def _update_footer(self):
        err_str = f"{self.errors_count} error" if self.errors_count == 1 else f"{self.errors_count} errors"
        warn_str = f"{self.warnings_count} warning" if self.warnings_count == 1 else f"{self.warnings_count} warnings"
        self.footer_lbl.setText(
            f"{self.gcc_version}  ·  C++17  ·  {err_str}  ·  {warn_str}  ·  {self.file_name}"
        )

    # ── Page switchers ────────────────────────────────────────────────────────

    def switch_to_ast(self):
        self.stack.setCurrentIndex(1)
        self.status_label.setText("STATUS: ● PARSING AST...")
        self.ast_worker = ASTWorker(self.file_path, code=self.editor.toPlainText())
        self.ast_worker.finished.connect(self._on_ast_ready)
        self.ast_worker.start()

    def _on_ast_ready(self, ast_tree):
        self.ast_page.update_tree(ast_tree)
        self.status_label.setText("STATUS: ● AST READY")

    def switch_to_call_graph(self):
        self.stack.setCurrentIndex(3)
        code = self.editor.toPlainText()
        functions, edges, external_calls, modules = _extract_cpp_call_graph(code)
        self.call_graph_page.graph.update_graph(functions, edges, external_calls, modules)

    def switch_to_security(self):
        self.stack.setCurrentIndex(4)
        findings = self.latest_security_findings
        if not findings and self.file_path and os.path.exists(self.file_path):
            try:
                findings = analyze_security(self.file_path, [])
            except Exception:
                findings = []
        self.latest_security_findings = findings
        self.security_page.update_report(findings)

    def switch_to_cfg(self):
        self.stack.setCurrentIndex(5)
        code = self.editor.toPlainText()
        cfg_data = _extract_cpp_cfg(code)
        self.cfg_page.graph.update_graph(cfg_data)

    def switch_to_second_opinion(self):
        self.stack.setCurrentIndex(6)
        if hasattr(self, "second_opinion_page") and hasattr(self.second_opinion_page, "show_opinion"):
            current_errors = getattr(self.editor, "errors", [])
            if current_errors:
                first = current_errors[0]
                self.second_opinion_page.show_opinion(first.get("message", ""), first.get("ast_node", ""))

    # ── Auto-Heal & Undo Heal ─────────────────────────────────────────────────

    def _cleanup_heal_loading(self):
        if hasattr(self, "heal_loading_card") and self.heal_loading_card:
            try:
                self.error_cards_layout.removeWidget(self.heal_loading_card)
                self.heal_loading_card.deleteLater()
            except Exception:
                pass
            self.heal_loading_card = None

    def start_heal(self):
        if not HEALER_AVAILABLE:
            QMessageBox.warning(self, "Auto-Heal", "Auto-healer engine is not available.")
            return

        if not self.editor.toPlainText().strip():
            QMessageBox.information(self, "Auto-Heal", "The code editor is empty. Please type or load a C++ source file first.")
            return

        if getattr(self, "heal_worker", None) is not None and self.heal_worker.isRunning():
            QMessageBox.warning(self, "Auto-Heal", "Auto-heal is already in progress.")
            return

        self.save_file()
        self.status_label.setText("STATUS: ● AUTO-HEALING IN PROGRESS...")
        self.btn_heal.setEnabled(False)
        self.btn_heal.setText("Healing...")

        while self.error_cards_layout.count():
            item = self.error_cards_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()
        self.issue_cards = []

        # ── Loading Banner with animated indeterminate progress bar ──
        self.heal_loading_card = QFrame()
        self.heal_loading_card.setObjectName("Card")
        load_lay = QVBoxLayout(self.heal_loading_card)
        load_lay.setContentsMargins(16, 14, 16, 14)
        load_lay.setSpacing(10)

        load_head = QHBoxLayout()
        load_head.addWidget(badge("HEALING IN PROGRESS", "accent"))
        load_head.addStretch(1)
        load_lay.addLayout(load_head)

        load_title = plain_label("⚕ Auto-Healing in Progress...", "Title")
        load_title.setFont(theme.ui_font(13, True))
        load_lay.addWidget(load_title)

        self.heal_progress_bar = QProgressBar()
        self.heal_progress_bar.setRange(0, 0)   # Indeterminate pulsing animation
        self.heal_progress_bar.setFixedHeight(6)
        self.heal_progress_bar.setTextVisible(False)
        load_lay.addWidget(self.heal_progress_bar)

        load_sub = plain_label("Analyzing diagnostics, computing AST patches, and validating compilation...", "Muted")
        load_lay.addWidget(load_sub)

        self.error_cards_layout.addWidget(self.heal_loading_card)

        classifier = self.error_classifier
        if classifier is None:
            try:
                from error_classifier import get_default_classifier
                classifier = get_default_classifier()
            except Exception:
                classifier = _KeywordClassifier()

        enable_ai = self.is_ai_enabled()
        self.heal_worker = HealWorker(
            file_path=self.file_path,
            classifier=classifier,
            enable_ai=enable_ai,
        )

        def on_worker_finished():
            self._cleanup_heal_loading()
            self.btn_heal.setEnabled(True)
            self.btn_heal.setText("Auto-Heal")

        self.heal_worker.finished.connect(on_worker_finished)
        self.heal_worker.backup_created.connect(self._on_heal_backup_created)
        self.heal_worker.attempt_started.connect(self._on_heal_attempt)
        self.heal_worker.diff_ready.connect(self._on_heal_diff)
        self.heal_worker.compile_clean.connect(self._on_heal_success)
        self.heal_worker.error_signal.connect(self._on_heal_error)
        self.heal_worker.give_up.connect(self._on_heal_give_up)
        self.heal_worker.heal_summary.connect(self._on_heal_summary)
        self.heal_worker.lines_fixed.connect(lambda lines: self.editor.set_fixed_lines(lines))
        self.heal_worker.telemetry_ready.connect(self._on_telemetry_ready)
        self.heal_worker.status_update.connect(lambda t: self.status_label.setText(t))
        self.heal_worker.info_message.connect(self._on_heal_info)
        self.heal_worker.start()

    def _on_heal_backup_created(self, backup_path: str):
        self.last_heal_backup = backup_path
        self.btn_undo_heal.setEnabled(True)

    def _on_heal_info(self, msg: str):
        lbl = plain_label(f"ℹ️ {msg}", "Muted")
        self.error_cards_layout.addWidget(lbl)
        self.log_terminal.append(f"[HEAL] {msg}")

    def undo_heal(self):
        if not self.last_heal_backup or not os.path.exists(self.last_heal_backup):
            QMessageBox.information(self, "Undo Heal", "No backup available to restore.")
            return
        try:
            with open(self.last_heal_backup, "r", encoding="utf-8") as f:
                content = f.read()
            with open(self.file_path, "w", encoding="utf-8") as f:
                f.write(content)
            self.editor.blockSignals(True)
            self.editor.setPlainText(content)
            self.editor.blockSignals(False)
            self.editor.clear_fixed_lines()
            self.btn_undo_heal.setEnabled(False)
            self.status_label.setText("STATUS: ● RESTORED BACKUP")
            self.error_cards_layout.addWidget(plain_label(f"↺ Restored original code from {os.path.basename(self.last_heal_backup)}", "IssueTitle"))
            self.analyze()
        except Exception as e:
            QMessageBox.critical(self, "Undo Heal Error", f"Failed to restore backup: {e}")

    def _on_telemetry_ready(self, telemetry: list):
        for entry in telemetry:
            self.cumulative_compilation_co2 += entry.get("emissions", 0.0)

    def _on_heal_attempt(self, attempt_no: int, error: dict):
        msg = error.get("message", "?")
        cat = error.get("category", "?")
        lbl = plain_label(f"Attempt {attempt_no} — [{cat.replace('_', ' ').upper()}] {msg}", "IssueTitle")
        self.error_cards_layout.addWidget(lbl)

    def _on_heal_diff(self, attempt_no: int, diff_html: str, label: str = ""):
        title_text = f"Diff — {label}" if label else f"Diff — Attempt {attempt_no}"
        diff_card = QFrame()
        diff_card.setObjectName("Card")
        d_lay = QVBoxLayout(diff_card)
        d_lay.setContentsMargins(12, 10, 12, 10)
        d_lay.setSpacing(6)
        d_lay.addWidget(section_label(title_text))

        diff_box = QTextBrowser()
        diff_box.setObjectName("Console")
        diff_box.setFont(theme.mono_font(12))
        diff_box.setOpenLinks(False)
        diff_box.setHtml(diff_html)
        diff_box.setMaximumHeight(160)
        d_lay.addWidget(diff_box)
        self.error_cards_layout.addWidget(diff_card)

        try:
            self.editor.blockSignals(True)
            with open(self.file_path, "r", encoding="utf-8") as f:
                self.editor.setPlainText(f.read())
            self.editor.blockSignals(False)
        except Exception:
            self.editor.blockSignals(False)

    def _on_heal_summary(self, summary: dict):
        self._cleanup_heal_loading()
        clean = summary.get("clean", False)
        rounds = summary.get("rounds", [])
        total_sec = summary.get("total_duration", 0.0)
        status_msg = summary.get("message", "Compiles OK")

        # ── 1. Clear out ALL old cards (removes loading card and old pre-heal error cards) ──
        while self.error_cards_layout.count():
            item = self.error_cards_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()
        self.issue_cards = []

        # ── 2. Prominent Auto-Heal Completed Banner Card ──
        comp_card = QFrame()
        comp_card.setObjectName("Card")
        c_layout = QVBoxLayout(comp_card)
        c_layout.setContentsMargins(16, 14, 16, 14)
        c_layout.setSpacing(8)

        status_badge = badge("AUTO-HEAL COMPLETED", "ok" if clean else "warn")
        c_layout.addWidget(status_badge)

        if clean:
            comp_title = plain_label("🎉 Auto-heal completed! All compiler errors resolved.", "Title")
            comp_title.setFont(theme.ui_font(13, True))
            c_layout.addWidget(comp_title)
            c_layout.addWidget(plain_label(f"Clean compilation verified with 0 errors in {total_sec:.2f}s ({len(rounds)} round(s)).", "Muted"))
        else:
            comp_title = plain_label(f"⚕ Auto-heal completed — {status_msg}", "Title")
            comp_title.setFont(theme.ui_font(13, True))
            c_layout.addWidget(comp_title)
            c_layout.addWidget(plain_label(f"Finished {len(rounds)} healing round(s) in {total_sec:.2f}s. Review the applied changes.", "Muted"))

        for r in rounds:
            r_no = r.get("round_no", 1)
            r_method = r.get("method", "offline rules")
            r_sec = r.get("seconds", 0.0)
            c_layout.addWidget(plain_label(f"• Round {r_no}: {r_method} ({r_sec:.2f}s)"))

        self.error_cards_layout.addWidget(comp_card)

        # ── 3. Re-analyze healed code and update UI ──
        self._silent_reanalysis_after_heal(summary, c_layout)
        self.terminal.append_output("\n[Auto-Heal] Auto-heal completed!\n")

    def _silent_reanalysis_after_heal(self, summary: dict, card_layout=None):
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.editor.blockSignals(True)
            self.editor.setPlainText(content)
            self.editor.blockSignals(False)

            from heal_engine import compile_source
            clean_errors, clean_warnings, _ = compile_source(content, syntax_only=False)

            sec_findings = []
            try:
                from security_analyzer import analyze
                sec_findings = [f for f in analyze(self.file_path, []) if f.source != "compiler_diagnostic"]
            except Exception:
                pass

            self.errors_count = len(clean_errors) + len([f for f in sec_findings if (f.severity or "").lower() in ("critical", "high")])
            self.warnings_count = len(clean_warnings) + len([f for f in sec_findings if (f.severity or "").lower() not in ("critical", "high")])
            self._update_footer()
            self.editor.set_errors(clean_errors)

            if len(clean_errors) == 0 and len(clean_warnings) == 0 and len(sec_findings) == 0:
                self.problems_count_badge.setText("0")
                theme.set_prop(self.problems_count_badge, "tone", "ok")
                self.status_label.setText("STATUS: ● AUTO-HEAL COMPLETED ✅")
                if card_layout:
                    card_layout.addWidget(plain_label("✨ Code compiles cleanly with 0 errors and 0 warnings.", "Muted"))
            else:
                total_issues = len(clean_errors) + len(clean_warnings) + len(sec_findings)
                self.problems_count_badge.setText(str(total_issues))
                tone = "warn" if self.errors_count == 0 else "error"
                theme.set_prop(self.problems_count_badge, "tone", tone)
                self.status_label.setText("STATUS: ● AUTO-HEAL COMPLETED" if self.errors_count == 0 and not clean_errors else "STATUS: ● HEALING INCOMPLETE")

                # Show only remaining issues in the healed code
                from error_parser import CompilerError
                from error_explainer import enrich_error
                classifier = self.error_classifier or _KeywordClassifier()

                self.error_cards_layout.addWidget(section_label("REMAINING ISSUES IN HEALED CODE"))
                for item in clean_errors + clean_warnings:
                    ce = CompilerError(
                        file=self.file_name,
                        line=item.get("line", 1),
                        column=item.get("column", 1),
                        error_type=item.get("type", "warning"),
                        message=item.get("message", ""),
                        raw=item.get("raw", "")
                    )
                    cat, _ = classifier.predict(ce.message)
                    ce.category = cat or "other"
                    enrich_error(ce)
                    card = IssueCard(ce, co2_offset=self.manual_co2_offset)
                    card.clicked.connect(self._on_issue_clicked)
                    self.issue_cards.append(card)
                    self.error_cards_layout.addWidget(card)

                for sf in sec_findings:
                    ce = CompilerError(
                        file=self.file_name,
                        line=sf.line or 1,
                        column=sf.column or 1,
                        error_type="error" if (sf.severity or "").lower() in ("critical", "high") else "warning",
                        message=sf.description,
                        raw=f"[{sf.severity.upper()}] {sf.description}"
                    )
                    ce.category = sf.vulnerability_type.lower().replace(" ", "_")
                    ce.explanation = f"What happened:\n{sf.description}\n\nWhy it happened:\nViolation of C++ runtime safety or undefined behavior.\n\nHow to fix it:\n{sf.recommendation}"
                    ce.suggestion = sf.recommendation
                    ce.security_risk = (sf.severity or "Medium").upper()
                    card = IssueCard(ce, co2_offset=self.manual_co2_offset)
                    card.clicked.connect(self._on_issue_clicked)
                    self.issue_cards.append(card)
                    self.error_cards_layout.addWidget(card)

                if self.is_ai_enabled():
                    self.request_ai_explanations()
        except Exception:
            pass

    def _on_heal_success(self, method: str = "Healed"):
        self._cleanup_heal_loading()
        self.btn_heal.setEnabled(True)
        self.btn_heal.setText("Auto-Heal")
        self.status_label.setText("STATUS: ● AUTO-HEAL COMPLETED ✅")
        lbl = plain_label(f"✅ Auto-heal completed: {method} — Compiles cleanly! Review the changes.", "IssueTitle")
        self.error_cards_layout.addWidget(lbl)

    def _on_heal_error(self, msg: str):
        self._cleanup_heal_loading()
        self.btn_heal.setEnabled(True)
        self.btn_heal.setText("Auto-Heal")
        self.status_label.setText("STATUS: ● AUTO-HEAL COMPLETED (Error)")
        lbl = plain_label(f"⚠️ Auto-heal error: {msg}")
        self.error_cards_layout.addWidget(lbl)

    def _on_heal_give_up(self, history: list):
        self._cleanup_heal_loading()
        self.btn_heal.setEnabled(True)
        self.btn_heal.setText("Auto-Heal")
        self.status_label.setText("STATUS: ● AUTO-HEAL COMPLETED")
        lbl = plain_label("ℹ️ Auto-heal completed. Review the healed source above.", "IssueTitle")
        self.error_cards_layout.addWidget(lbl)

    # ── Code Compilation & Diagnostics Rendering ──────────────────────────────

    def load_file_path(self, file_path: str):
        if file_path and os.path.exists(file_path):
            self.file_path = os.path.abspath(file_path)
            self.file_name = os.path.basename(file_path)
            self.file_tab_label.setText(f"📄  {self.file_name}")
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                self.editor.setPlainText(f.read())
            self.editor.clear_fixed_lines()
            self.analyze()

    def load_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open C++ File", "", "C++ Files (*.cpp *.h *.hpp);;All Files (*)")
        if file_path:
            self.load_file_path(file_path)

    def save_file(self):
        if self.file_path:
            with open(self.file_path, "w", encoding="utf-8") as f:
                f.write(self.editor.toPlainText())

    def on_code_changed(self):
        self.status_label.setText("STATUS: ● CODE MODIFIED")

    def analyze(self):
        if not self.editor.toPlainText().strip():
            self.errors_count = 0
            self.warnings_count = 0
            self._update_footer()
            self.status_label.setText("STATUS: ● READY")
            self.problems_count_badge.setText("0")
            theme.set_prop(self.problems_count_badge, "tone", "ok")
            while self.error_cards_layout.count():
                item = self.error_cards_layout.takeAt(0)
                w = item.widget()
                if w:
                    w.deleteLater()
            self.issue_cards = []
            self.terminal.clear()
            self.terminal.append_output("Ready. Paste or load a C++ source file to compile and analyze.\n")
            return

        if getattr(self, "compile_worker", None) is not None and self.compile_worker.isRunning():
            return
        self.save_file()
        self.status_label.setText("STATUS: ● ANALYZING...")
        self.terminal.clear()
        self.editor.clear_fixed_lines()

        script_dir = os.path.dirname(os.path.abspath(__file__))
        main_script = os.path.join(script_dir, "main.py")
        cmd = [sys.executable, main_script, self.file_path, "-j", "-v"]

        self.compile_worker = CompilerWorker(cmd)
        self.compile_worker.finished.connect(self._on_analysis_finished)
        self.compile_worker.start()

    def _on_analysis_finished(self, stdout: str, stderr: str, returncode: int):
        data = {}
        try:
            data = json.loads(stdout)
        except Exception:
            s = (stdout or "").strip()
            first_brace = s.find("{")
            last_brace = s.rfind("}")
            if first_brace != -1 and last_brace != -1:
                try:
                    data = json.loads(s[first_brace:last_brace + 1])
                except Exception:
                    data = {}

        if not data:
            data = {"status": "error" if returncode != 0 else "success", "errors": []}

        self.render_json(data, stderr)

        # Background generation of AST, Call Graph, and CFG
        try:
            code = self.editor.toPlainText()
            self.ast_worker = ASTWorker(self.file_path, code=code)
            self.ast_worker.finished.connect(self._on_ast_ready)
            self.ast_worker.start()

            if hasattr(self, "call_graph_page"):
                functions, edges, external_calls, modules = _extract_cpp_call_graph(code)
                self.call_graph_page.graph.update_graph(functions, edges, external_calls, modules)

            if hasattr(self, "cfg_page"):
                cfg_data = _extract_cpp_cfg(code)
                self.cfg_page.graph.update_graph(cfg_data)
        except Exception:
            pass

    def render_json(self, data: dict, raw_stderr: str):
        self.terminal.clear()

        while self.error_cards_layout.count():
            item = self.error_cards_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()
        self.issue_cards = []

        status = data.get("status", "")
        errors = data.get("errors", [])
        findings = data.get("security_findings", [])
        report_text = data.get("security_report", "")

        self.latest_security_findings = findings
        self.latest_security_report = report_text
        self.security_page.update_report(findings)

        # Fallback: promote any standalone static findings into diagnostic problems if not already present
        if findings and not errors:
            for f in findings:
                if f.get("source") != "compiler_diagnostic":
                    sev = "error" if (f.get("severity") or "").lower() in ("critical", "high") else "warning"
                    errors.append({
                        "file": f.get("file") or self.file_name,
                        "line": f.get("line", 1),
                        "column": f.get("column", 1),
                        "error_type": sev,
                        "type": sev,
                        "message": f.get("description", "Security vulnerability or runtime flaw"),
                        "category": (f.get("vulnerability_type") or "security_flaw").lower().replace(" ", "_"),
                        "explanation": f"What happened:\n{f.get('description', '')}\n\nWhy it happened:\nViolation of C++ runtime safety or undefined behavior.\n\nHow to fix it:\n{f.get('recommendation', '')}",
                        "suggestion": f.get("recommendation", ""),
                        "security_risk": (f.get("severity") or "Medium").upper(),
                        "risk_reason": f.get("description", ""),
                    })

        if not errors:
            self.status_label.setText("STATUS: ● COMPILES OK ✅")
            self.errors_count = 0
            self.warnings_count = 0
            self._update_footer()
            self.editor.set_errors([])

            self.problems_count_badge.setText("0")
            theme.set_prop(self.problems_count_badge, "tone", "ok")

            empty_lbl = plain_label("No compiler errors or warnings detected. Code compiles cleanly.", "Muted")
            self.error_cards_layout.addWidget(empty_lbl)

            self.terminal.append_output("Compilation finished cleanly with 0 errors.\nClick 'Run' to execute binary.\n")
            return

        self.errors_count = data.get("error_count", len([e for e in errors if e.get("type", e.get("error_type")) == "error"]))
        self.warnings_count = data.get("warning_count", len([e for e in errors if e.get("type", e.get("error_type")) == "warning"]))
        if self.errors_count > 0 and self.warnings_count > 0:
            self.status_label.setText(f"STATUS: ● {self.errors_count} ERRORS, {self.warnings_count} WARNINGS")
        elif self.errors_count > 0:
            self.status_label.setText(f"STATUS: ● {self.errors_count} ERRORS FOUND")
        elif self.warnings_count > 0:
            self.status_label.setText(f"STATUS: ● {self.warnings_count} WARNINGS FOUND")
        else:
            self.status_label.setText(f"STATUS: ● {len(errors)} ISSUES FOUND")
        self._update_footer()
        self.editor.set_errors(errors)

        self.problems_count_badge.setText(str(len(errors)))
        theme.set_prop(self.problems_count_badge, "tone", "error" if self.errors_count > 0 else "warn")

        # Second opinion page update
        if errors and NEW_PAGES_AVAILABLE and hasattr(self, "second_opinion_page") and hasattr(self.second_opinion_page, "show_opinion"):
            try:
                first = errors[0]
                self.second_opinion_page.show_opinion(first.get("message", ""), first.get("ast_node", ""))
            except Exception:
                pass

        # Populate issue cards
        created_cards = []
        for idx, e in enumerate(errors):
            card = IssueCard(e, co2_offset=self.manual_co2_offset)
            card.clicked.connect(self._on_issue_clicked)
            self.issue_cards.append(card)
            created_cards.append(card)
            self.error_cards_layout.addWidget(card)

        # Output rich compiler messages into terminal
        compiler_html = ""
        for e in errors:
            etype = (e.get("type") or e.get("error_type") or "error").lower()
            tag_color = RED if etype == "error" else YELLOW
            fname = os.path.basename(e.get("file") or self.file_name)
            line = e.get("line", "?")
            col = e.get("column", "?")
            msg = e.get("message", "")

            compiler_html += f"<span style='color:{tag_color}; font-weight:bold;'>[{etype.upper()}]</span> {fname}:{line}:{col}: <span style='color:{tag_color};'>{etype}:</span> {msg}<br>"
            context = e.get("context", {})
            lines = context.get("lines", [])
            start = context.get("start_line", 1)
            if lines and isinstance(lines, list):
                for i, lt in enumerate(lines, start=start):
                    txt = lt.replace('<', '&lt;').replace('>', '&gt;').rstrip('\r\n')
                    if str(i) == str(line):
                        compiler_html += f" <span style='color:{tag_color}; font-weight:bold;'>&gt;</span> {i:3} | <b style='color:{TEXT_MAIN}'>{txt}</b><br>"
                        if col != "?":
                            try:
                                c_int = int(col)
                                compiler_html += f"       {' ' * (len(str(i)) + 2 + c_int)}<span style='color:{tag_color}; font-weight:bold;'>^</span><br>"
                            except Exception:
                                pass
                    else:
                        compiler_html += f"   {i:3} | <span style='color:{TEXT_DIM}'>{txt}</span><br>"
            compiler_html += "<br>"

        compiler_html += f"<span style='color:{TEXT_DIM};'>C++_ANALYZER_V2.0.1_READY &gt; _</span>"
        self.terminal.append_output(f"<div style='white-space:pre-wrap; font-family:{FONT_FAMILY};'>{compiler_html}</div>", is_html=True)

        # Asynchronously fetch AI explanations if enabled
        if self.is_ai_enabled() and errors:
            self.request_ai_explanations()
        else:
            self.update_ai_status()

    def _on_issue_clicked(self, line: int):
        sender = self.sender()
        for card in self.issue_cards:
            card.set_selected(card is sender)
        if line and line > 0:
            cursor = QTextCursor(self.editor.document())
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            cursor.movePosition(QTextCursor.MoveOperation.Down, n=line - 1)
            self.editor.setTextCursor(cursor)
            self.editor.setFocus()

    # ── Code Execution & Process Runner ───────────────────────────────────────

    def _find_executable(self) -> Optional[str]:
        candidates = ["a.exe", "a.out", "main.exe", "main.out"]
        for c in candidates:
            if os.path.exists(c):
                return os.path.abspath(c)
        base = os.path.splitext(self.file_path)[0]
        ext = ".exe" if os.name == "nt" else ".out"
        if os.path.exists(base + ext):
            return base + ext
        return None

    def run_code(self):
        self.tabs.setCurrentIndex(0)
        if not self.editor.toPlainText().strip():
            self.terminal.clear()
            self.terminal.append_output("Cannot run: Editor is empty. Please type or load C++ code first.\n")
            return
        exe = self._find_executable()
        if not exe:
            # Recompile first
            self.save_file()
            self.terminal.append_output("Building binary...\n")
            out_name = "a.exe" if os.name == "nt" else "a.out"
            res = subprocess.run(["g++", "-std=c++17", self.file_path, "-o", out_name], capture_output=True, text=True)
            if res.returncode != 0:
                self.terminal.append_output(f"Build failed:\n{res.stderr}\n")
                return
            exe = os.path.abspath(out_name)

        self.terminal.clear()
        self.terminal.append_output(f"Running {os.path.basename(exe)}...\n")

        stdin_input = self.input_terminal.toPlainText()
        try:
            res = subprocess.run(
                [exe],
                input=stdin_input,
                capture_output=True,
                text=True,
                timeout=5
            )
            if res.stdout:
                self.terminal.append_output(res.stdout)
            if res.stderr:
                self.terminal.append_output(res.stderr)
            self.terminal.append_output(f"\n[Process exited with code {res.returncode}]\n")
        except subprocess.TimeoutExpired:
            self.terminal.append_output("\n[Execution timed out after 5 seconds]\n")
        except Exception as e:
            self.terminal.append_output(f"\n[Execution error: {e}]\n")


# ── Application Entry Point ───────────────────────────────────────────────────

ModernCompilerApp = AppGUI


def main():
    app = QApplication(sys.argv)
    theme.apply_theme(app, theme.load_saved_mode())
    window = AppGUI()
    window.show()
    exit_code = app.exec()
    if CODECARBON_AVAILABLE and hasattr(window, 'tracker') and window.tracker:
        try:
            window.tracker.stop()
        except Exception:
            pass
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
