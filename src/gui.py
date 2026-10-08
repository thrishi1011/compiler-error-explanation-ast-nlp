import sys
import os
import subprocess
import json
import re
import html
import time
import math
from typing import Optional, List, Dict, Tuple
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QSplitter, QPlainTextEdit, QTextEdit,
                             QPushButton, QFileDialog, QMessageBox, QLabel, QFrame,
                             QCheckBox, QDialog, QTreeWidget, QTreeWidgetItem, QLineEdit,
                             QGraphicsOpacityEffect, QGraphicsDropShadowEffect, QScrollArea, QSizePolicy, QTextBrowser,
                             QProgressBar, QStyleFactory,
                             QStackedWidget, QGraphicsView, QGraphicsScene, QGraphicsRectItem, QGraphicsLineItem, QGraphicsTextItem, QGraphicsItem)
from PyQt6.QtCore import Qt, QRect, QSize, QThread, pyqtSignal, QTimer, QVariantAnimation, QProcess, QPropertyAnimation, QRectF, QPointF
from PyQt6.QtGui import QFont, QColor, QPainter, QTextFormat, QTextCharFormat, QSyntaxHighlighter, QTextCursor, QPainterPath, QPen, QLinearGradient, QBrush
import platform
import socket
import tempfile
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

from ast_extractor import extract_ast, extract_node_near_line, parse_ast_to_tree
from security_analyzer import analyze as analyze_security, format_security_report

LIGHT_THEME = {
    "BG_COLOR": "#f4f7f9",
    "PANE_BG": "#ffffff",
    "HEADER_BG": "#f4f7f9",
    "BORDER_COLOR": "#e6ebf1",
    "PINK": "#5469d4",
    "TEXT_MAIN": "#1a1f36",
    "TEXT_DIM": "#4f566b",
    "KEYWORD_COLOR": "#5469d4",
    "ERROR_LINE_COLOR": "#fefafb",
    "RED": "#d12441",
    "YELLOW": "#ffcc00",
    "GREEN": "#24b47e",
    "ACTIVE_NAV_BG": "#e9ecf8",
    "HOVER_NAV_BG": "#eef2f7",
    "CODE_BG": "#ffffff",
    "TERMINAL_BG": "#f8fafc",
}

DARK_THEME = {
    "BG_COLOR": "#0f172a",          # Deep slate 900
    "PANE_BG": "#1e293b",           # Card slate 800
    "HEADER_BG": "#0f172a",         # Header dark
    "BORDER_COLOR": "#334155",      # Slate 700 border
    "PINK": "#818cf8",              # Indigo 400
    "TEXT_MAIN": "#f8fafc",         # Slate 50
    "TEXT_DIM": "#94a3b8",          # Slate 400
    "KEYWORD_COLOR": "#a5b4fc",     # Light indigo 300
    "ERROR_LINE_COLOR": "#371b26",  # Dark red highlight
    "RED": "#f87171",               # Coral red
    "YELLOW": "#fbbf24",            # Amber
    "GREEN": "#34d399",             # Emerald
    "ACTIVE_NAV_BG": "#312e81",     # Indigo 900
    "HOVER_NAV_BG": "#334155",      # Slate 700
    "CODE_BG": "#1e293b",
    "TERMINAL_BG": "#0b1120",
}

CURRENT_THEME = dict(LIGHT_THEME)

BG_COLOR = CURRENT_THEME["BG_COLOR"]
PANE_BG = CURRENT_THEME["PANE_BG"]
HEADER_BG = CURRENT_THEME["HEADER_BG"]
BORDER_COLOR = CURRENT_THEME["BORDER_COLOR"]
PINK = CURRENT_THEME["PINK"]
TEXT_MAIN = CURRENT_THEME["TEXT_MAIN"]
TEXT_DIM = CURRENT_THEME["TEXT_DIM"]
KEYWORD_COLOR = CURRENT_THEME["KEYWORD_COLOR"]
ERROR_LINE_COLOR = CURRENT_THEME["ERROR_LINE_COLOR"]
RED = CURRENT_THEME["RED"]
YELLOW = CURRENT_THEME["YELLOW"]
GREEN = CURRENT_THEME["GREEN"]

def set_global_theme(theme_dict):
    global BG_COLOR, PANE_BG, HEADER_BG, BORDER_COLOR, PINK, TEXT_MAIN, TEXT_DIM, KEYWORD_COLOR, ERROR_LINE_COLOR, RED, YELLOW, GREEN, CURRENT_THEME
    CURRENT_THEME.update(theme_dict)
    BG_COLOR = theme_dict["BG_COLOR"]
    PANE_BG = theme_dict["PANE_BG"]
    HEADER_BG = theme_dict["HEADER_BG"]
    BORDER_COLOR = theme_dict["BORDER_COLOR"]
    PINK = theme_dict["PINK"]
    TEXT_MAIN = theme_dict["TEXT_MAIN"]
    TEXT_DIM = theme_dict["TEXT_DIM"]
    KEYWORD_COLOR = theme_dict["KEYWORD_COLOR"]
    ERROR_LINE_COLOR = theme_dict["ERROR_LINE_COLOR"]
    RED = theme_dict["RED"]
    YELLOW = theme_dict["YELLOW"]
    GREEN = theme_dict["GREEN"]

FONT_FAMILY = "Menlo" if platform.system() == "Darwin" else "Consolas"

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
            if code[i] == "{": depth += 1
            elif code[i] == "}": depth -= 1
            i += 1
            
        body = code[body_start:i-1]
        lines = [l.strip() for l in body.split("\n") if l.strip()]
        
        nodes = []
        edges = []
        
        # Start node
        nodes.append({"id": "start", "label": f"START: {name}", "type": "entry"})
        
        current_node_id = "start"
        block_counter = 0
        
        pending_text = []
        
        for line in lines:
            # Check for control flow
            if any(kw in line for kw in ["if", "while", "for", "switch"]):
                # Close current block
                if pending_text:
                    block_id = f"b{block_counter}"
                    nodes.append({"id": block_id, "label": "\n".join(pending_text[:3]), "type": "stmt"})
                    edges.append((current_node_id, block_id))
                    current_node_id = block_id
                    block_counter += 1
                    pending_text = []
                
                # Create branch node
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
                current_node_id = ret_id # Technically current becomes terminal here
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

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


def get_gcc_version() -> str:
    """Read actual installed g++ version once at startup."""
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


class SparklineGraph(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(15)
        self.setMaximumHeight(40)
        self.values = [0] * 50
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_fluctuation)
        self.timer.start(200)
        self.peak = 0

    def update_fluctuation(self):
        if HAS_PSUTIL:
            try:
                val = psutil.cpu_percent()
                self.add_value(val)
                return
            except Exception:
                pass
        # Base noise fallback
        import random
        noise = random.uniform(0, 2)
        self.add_value(noise)

    def add_value(self, val):
        self.values.pop(0)
        self.values.append(val)
        self.update()

    def trigger_spike(self):
        import random
        self.add_value(random.uniform(15, 25))
        self.add_value(random.uniform(10, 15))

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        width = self.width()
        height = self.height()
        
        # Draw background line
        painter.setPen(QColor(BORDER_COLOR))
        painter.drawLine(0, height - 1, width, height - 1)
        
        if not self.values:
            return
            
        max_val = max(max(self.values), 30)
        
        path = QPainterPath()
        step = width / (len(self.values) - 1)
        
        for i, v in enumerate(self.values):
            x = i * step
            y = height - (v / max_val * (height - 5)) - 2
            if i == 0:
                path.moveTo(x, y)
            else:
                path.lineTo(x, y)
        
        painter.setPen(QPen(QColor(PINK), 1.5))
        painter.drawPath(path)
        
        # Fill under
        fill_path = QPainterPath(path)
        fill_path.lineTo(width, height)
        fill_path.lineTo(0, height)
        fill_path.closeSubpath()
        
        gradient = QLinearGradient(0, 0, 0, height)
        gradient.setColorAt(0, QColor(211, 141, 186, 60)) # PINK with alpha
        gradient.setColorAt(1, QColor(211, 141, 186, 0))
        painter.fillPath(fill_path, gradient)

class MetricsGraph(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(220)
        self.series = {
            "Power mW": [],
            "Carbon mg/Wh": [],
            "Time s": [],
        }
        self.colors = {
            "Power mW": QColor(PINK),
            "Carbon mg/Wh": QColor(GREEN),
            "Time s": QColor(YELLOW),
        }

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
        painter.fillRect(self.rect(), QColor(PANE_BG))

        left, top, right, bottom = 52, 20, 18, 42
        width = max(1, self.width() - left - right)
        height = max(1, self.height() - top - bottom)
        graph_rect = QRect(left, top, width, height)

        painter.setPen(QPen(QColor(BORDER_COLOR), 1))
        painter.drawRect(graph_rect)
        for i in range(1, 4):
            y = top + int(height * i / 4)
            painter.drawLine(left, y, left + width, y)

        painter.setFont(QFont(FONT_FAMILY, 9))
        painter.setPen(QColor(TEXT_DIM))
        painter.drawText(8, top + 5, "High")
        painter.drawText(12, top + height, "Low")

        legend_x = left
        for name, color in self.colors.items():
            painter.setPen(QPen(color, 2))
            painter.drawLine(legend_x, self.height() - 18, legend_x + 20, self.height() - 18)
            painter.setPen(QColor(TEXT_DIM))
            painter.drawText(legend_x + 25, self.height() - 14, name)
            legend_x += 145

        for name, data in self.series.items():
            if len(data) < 2:
                continue
            max_value = max(max(data), 1e-9)
            step = width / max(1, len(data) - 1)
            path = QPainterPath()
            for i, value in enumerate(data):
                x = left + i * step
                y = top + height - ((value / max_value) * height)
                if i == 0:
                    path.moveTo(x, y)
                else:
                    path.lineTo(x, y)
            painter.setPen(QPen(self.colors[name], 2))
            painter.drawPath(path)

class GraphNode(QGraphicsRectItem):
    def __init__(self, label, x, y, w, h, border, fill):
        super().__init__(-w/2, -h/2, w, h)
        self.setPos(x + w/2, y + h/2)
        self.setBrush(fill)
        self.setPen(QPen(border, 1.8))
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges)
        
        self.text = QGraphicsTextItem(label, self)
        self.text.setFont(QFont(FONT_FAMILY, 9, QFont.Weight.Bold))
        self.text.setDefaultTextColor(QColor(TEXT_MAIN))
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
        self.setLine(self.source_node.pos().x(), self.source_node.pos().y(), 
                     self.dest_node.pos().x(), self.dest_node.pos().y())

class CallGraphWidget(QGraphicsView):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(420)
        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setBackgroundBrush(QColor(PANE_BG))

    def update_graph(self, functions, edges, external_calls, modules):
        self.scene.clear()
        if not functions:
            t = self.scene.addText("No C++ function definitions found in the current source.")
            t.setDefaultTextColor(QColor(TEXT_DIM))
            t.setFont(QFont(FONT_FAMILY, 12))
            return

        margin = 34
        module_y = 46
        function_y = 180
        external_y = 320
        node_w, node_h = 150, 42

        view_w = max(self.width(), 800)

        def positions(items, y):
            count = max(1, len(items))
            available = max(1, view_w - 2 * margin - node_w)
            return {
                item: (margin + (available * i / max(1, count - 1)), y)
                for i, item in enumerate(items)
            }

        function_pos = positions(functions, function_y)
        module_labels = modules[:6] or ["current source"]
        module_pos = positions(module_labels, module_y)
        external_names = sorted({callee for _, callee in external_calls})[:8]
        external_pos = positions(external_names, external_y)

        nodes = {}
        for module, pos in module_pos.items():
            node = GraphNode(module, pos[0], pos[1], node_w, node_h, QColor(TEXT_DIM), QColor(HEADER_BG))
            self.scene.addItem(node)
            nodes[module] = node
            
        for function, pos in function_pos.items():
            node = GraphNode(function, pos[0], pos[1], node_w, node_h, QColor(PINK), QColor("#ffffff"))
            self.scene.addItem(node)
            nodes[function] = node
            
        for external, pos in external_pos.items():
            node = GraphNode(external, pos[0], pos[1], node_w, node_h, QColor(GREEN), QColor("#f8fffb"))
            self.scene.addItem(node)
            nodes[external] = node
            
        for module in module_labels:
            for function in functions:
                edge = GraphEdge(nodes[module], nodes[function], QColor(BORDER_COLOR), 1.5)
                self.scene.addItem(edge)
                
        for caller, callee in edges:
            if caller in nodes and callee in nodes:
                edge = GraphEdge(nodes[caller], nodes[callee], QColor(PINK), 2.0)
                self.scene.addItem(edge)
        
        for caller, callee in external_calls:
            if caller in nodes and callee in nodes:
                edge = GraphEdge(nodes[caller], nodes[callee], QColor(GREEN), 1.5)
                self.scene.addItem(edge)


class StyledButton(QPushButton):
    def __init__(self, text, style_type="outline_dim", parent=None):
        super().__init__(text, parent)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFont(QFont(FONT_FAMILY, 11, QFont.Weight.Bold))
        
        self.style_type = style_type
        self._update_style(0)
        
        self.hover_anim = QVariantAnimation(self)
        self.hover_anim.setDuration(150)
        self.hover_anim.valueChanged.connect(self._update_style)

    def enterEvent(self, event):
        self.hover_anim.setStartValue(0)
        self.hover_anim.setEndValue(1)
        self.hover_anim.start()
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.hover_anim.setStartValue(1)
        self.hover_anim.setEndValue(0)
        self.hover_anim.start()
        super().leaveEvent(event)

    def _update_style(self, progress):
        if self.style_type == "outline_dim":
            c = QColor(BORDER_COLOR)
            h = QColor(HEADER_BG)
            r = int(c.red() + (h.red() - c.red()) * progress)
            g = int(c.green() + (h.green() - c.green()) * progress)
            b = int(c.blue() + (h.blue() - c.blue()) * progress)
            bg = f"rgb({r}, {g}, {b})"
            
            self.setStyleSheet(f"""
                QPushButton {{
                    border: 1px solid {BORDER_COLOR};
                    background-color: {PANE_BG};
                    color: {TEXT_MAIN};
                    border-radius: 4px;
                    padding: 8px 15px;
                }}
                QPushButton:hover {{
                    background-color: {HEADER_BG};
                    border: 1px solid {PINK};
                }}
                QPushButton:pressed {{
                    background-color: {BORDER_COLOR};
                }}
            """)
        elif self.style_type == "solid_pink":
            c = QColor(PINK)
            h = QColor("#df9cc6")
            r = int(c.red() + (h.red() - c.red()) * progress)
            g = int(c.green() + (h.green() - c.green()) * progress)
            b = int(c.blue() + (h.blue() - c.blue()) * progress)
            bg = f"rgb({r}, {g}, {b})"
            
            self.setStyleSheet(f"""
                QPushButton {{
                    border: 1px solid {PINK};
                    background-color: {PINK};
                    color: {BG_COLOR};
                    padding: 8px 15px;
                }}
                QPushButton:hover {{
                    background-color: {bg};
                }}
                QPushButton:pressed {{
                    background-color: {KEYWORD_COLOR};
                }}
            """)


class StyledCheckBox(QCheckBox):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setFont(QFont(FONT_FAMILY, 10, QFont.Weight.Bold))
        self.setStyleSheet(f"color: {PINK};")

class LineNumberArea(QWidget):
    def __init__(self, editor):
        super().__init__(editor)
        self.editor = editor
    def sizeHint(self):
        return QSize(self.editor.line_number_area_width(), 0)
    def paintEvent(self, event):
        self.editor.line_number_area_paint_event(event)

class CodeEditor(QPlainTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.line_number_area = LineNumberArea(self)
        self.blockCountChanged.connect(self.update_line_number_area_width)
        self.updateRequest.connect(self.update_line_number_area)
        self.cursorPositionChanged.connect(self.highlight_current_line)

        self.error_line = None
        self.errors = []
        self.fixed_lines = set() # Set of 1-based line numbers

        self.update_line_number_area_width(0)
        self.highlight_current_line()
        
        self.setFont(QFont(FONT_FAMILY, 13))
        self.setStyleSheet(f"QPlainTextEdit {{ background-color: {PANE_BG}; color: {TEXT_MAIN}; border: none; }}")
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        
        # Set tab stop width to 4 spaces
        font_metrics = self.fontMetrics()
        self.setTabStopDistance(4 * font_metrics.horizontalAdvance(' '))

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
        return 5 + self.fontMetrics().horizontalAdvance('9') * digits

    def update_line_number_area_width(self, _):
        self.setViewportMargins(self.line_number_area_width(), 0, 0, 0)

    def update_line_number_area(self, rect, dy):
        if dy: self.line_number_area.scroll(0, dy)
        else: self.line_number_area.update(0, rect.y(), self.line_number_area.width(), rect.height())
        if rect.contains(self.viewport().rect()): self.update_line_number_area_width(0)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        cr = self.contentsRect()
        self.line_number_area.setGeometry(QRect(cr.left(), cr.top(), self.line_number_area_width(), cr.height()))

    def line_number_area_paint_event(self, event):
        painter = QPainter(self.line_number_area)
        painter.fillRect(event.rect(), QColor(PANE_BG))

        block = self.firstVisibleBlock()
        block_number = block.blockNumber()
        top = round(self.blockBoundingGeometry(block).translated(self.contentOffset()).top())
        bottom = top + round(self.blockBoundingRect(block).height())

        while block.isValid() and top <= event.rect().bottom():
            if block.isVisible() and bottom >= event.rect().top():
                number = str(block_number + 1)
                
                if self.error_line and block_number + 1 == self.error_line:
                    painter.setPen(QColor(PINK))
                    painter.setFont(QFont(FONT_FAMILY, 13, QFont.Weight.Bold))
                else:
                    painter.setPen(QColor(TEXT_DIM))
                    painter.setFont(QFont(FONT_FAMILY, 13))
                    
                painter.drawText(0, top, self.line_number_area.width() - 5, self.fontMetrics().height(),
                                 Qt.AlignmentFlag.AlignRight, number)
            block = block.next()
            top = bottom
            bottom = top + round(self.blockBoundingRect(block).height())
            block_number += 1

    def highlight_current_line(self):
        extraSelections = []
        
        if not self.isReadOnly():
            selection = QTextEdit.ExtraSelection()
            lineColor = QColor(HEADER_BG)
            selection.format.setBackground(lineColor)
            selection.format.setProperty(QTextFormat.Property.FullWidthSelection, True)
            selection.cursor = self.textCursor()
            selection.cursor.clearSelection()
            extraSelections.append(selection)

        # Draw green background for lines changed by the healer
        for line in self.fixed_lines:
            fixed_selection = QTextEdit.ExtraSelection()
            # Very light green background for modern feel
            fixed_selection.format.setBackground(QColor("#edfff2")) 
            fixed_selection.format.setProperty(QTextFormat.Property.FullWidthSelection, True)
            
            cursor = QTextCursor(self.document())
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            if line > 1:
                cursor.movePosition(QTextCursor.MoveOperation.Down, n=line - 1)
            
            fixed_selection.cursor = cursor
            extraSelections.append(fixed_selection)

        # Draw red squigglies for errors
        for err in self.errors:
            line = err.get("line")
            col = err.get("column")
            etype = err.get("error_type", "error").lower()
            
            if not line or line <= 0:
                continue
                
            error_selection = QTextEdit.ExtraSelection()
            
            # Wavy underline
            fmt = QTextCharFormat()
            underline_color = QColor(RED) if etype == "error" else QColor(YELLOW)
            fmt.setUnderlineColor(underline_color)
            fmt.setUnderlineStyle(QTextCharFormat.UnderlineStyle.SpellCheckUnderline)
            error_selection.format = fmt
            
            cursor = QTextCursor(self.document())
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            cursor.movePosition(QTextCursor.MoveOperation.Down, n=line - 1)
            
            if col and col > 0:
                # If we have a column, try to highlight the word at that position
                cursor.movePosition(QTextCursor.MoveOperation.StartOfLine)
                cursor.movePosition(QTextCursor.MoveOperation.Right, n=col - 1)
                # Select the word or at least a few chars
                cursor.movePosition(QTextCursor.MoveOperation.NextWord, QTextCursor.MoveMode.KeepAnchor)
            else:
                # Otherwise highlight the whole line
                cursor.movePosition(QTextCursor.MoveOperation.StartOfLine)
                cursor.movePosition(QTextCursor.MoveOperation.EndOfLine, QTextCursor.MoveMode.KeepAnchor)
                
            error_selection.cursor = cursor
            extraSelections.append(error_selection)

        self.setExtraSelections(extraSelections)

    def keyPressEvent(self, event):
        # Handle Command/Control + Backspace to delete to start of line
        if event.key() == Qt.Key.Key_Backspace and event.modifiers() & (Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.MetaModifier):
            cursor = self.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.StartOfLine, QTextCursor.MoveMode.KeepAnchor)
            cursor.removeSelectedText()
            return

        # Handle Alt/Option + Backspace to delete previous word
        if event.key() == Qt.Key.Key_Backspace and event.modifiers() & Qt.KeyboardModifier.AltModifier:
            cursor = self.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.PreviousWord, QTextCursor.MoveMode.KeepAnchor)
            cursor.removeSelectedText()
            return

        # Handle Backspace at the start of a line to go to previous line
        if event.key() == Qt.Key.Key_Backspace and not event.modifiers():
            cursor = self.textCursor()
            if cursor.atBlockStart() and not cursor.atStart():
                cursor.deletePreviousChar()
                return

        if event.key() == Qt.Key.Key_Tab:
            # Insert 4 spaces instead of a tab character
            self.insertPlainText("    ")
            return

        if event.key() == Qt.Key.Key_Return:
            # Handle auto-indentation
            cursor = self.textCursor()
            current_line = cursor.block().text()
            indentation = ""
            for char in current_line:
                if char.isspace():
                    indentation += char
                else:
                    break
            
            # If the line ends with an opening brace, add one more level of indentation
            if current_line.strip().endswith('{'):
                indentation += "    "
            
            super().keyPressEvent(event)
            self.insertPlainText(indentation)
            return

        super().keyPressEvent(event)


class CppSyntaxHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.apply_theme(CURRENT_THEME)

    def apply_theme(self, theme):
        self.highlightingRules = []

        keywordFormat = QTextCharFormat()
        keywordFormat.setForeground(QColor(theme.get("KEYWORD_COLOR", KEYWORD_COLOR)))
        keywords = ["int", "return", "if", "else", "for", "while", "class", "public", "private", "protected", "void", "namespace", "using", "auto", "double", "float", "char", "bool", "string", "vector"]
        for word in keywords:
            pattern = r"\b" + word + r"\b"
            self.highlightingRules.append((pattern, keywordFormat))

        stdFormat = QTextCharFormat()
        stdFormat.setForeground(QColor(theme.get("TEXT_MAIN", TEXT_MAIN)))
        self.highlightingRules.append((r"\bstd::\w+\b", stdFormat))

        stringFormat = QTextCharFormat()
        stringFormat.setForeground(QColor(theme.get("PINK", PINK)))
        self.highlightingRules.append((r'".*"', stringFormat))
        self.highlightingRules.append((r"\b[0-9]+\b", stringFormat))

        commentFormat = QTextCharFormat()
        commentFormat.setForeground(QColor(theme.get("TEXT_DIM", TEXT_DIM)))
        self.highlightingRules.append((r"//[^\n]*", commentFormat))

        includeFormat = QTextCharFormat()
        includeFormat.setForeground(QColor(theme.get("TEXT_DIM", TEXT_DIM)))
        self.highlightingRules.append((r"#\w+", includeFormat))

        bracketFormat = QTextCharFormat()
        bracketFormat.setForeground(QColor(theme.get("TEXT_MAIN", TEXT_MAIN)))
        self.highlightingRules.append((r"[\{\}\(\)\[\]]", bracketFormat))
        self.rehighlight()

    def highlightBlock(self, text):
        for pattern, format in self.highlightingRules:
            for match in re.finditer(pattern, text):
                self.setFormat(match.start(), match.end() - match.start(), format)


class CustomFrame(QFrame):
    def __init__(self, title, left_padding=False):
        super().__init__()
        self.setStyleSheet(f"QFrame {{ border: 1px solid {BORDER_COLOR}; background-color: {PANE_BG}; border-radius: 8px; }}")
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)

        self.header = QLabel(f" {title} ")
        self.header.setFont(QFont(FONT_FAMILY, 9, QFont.Weight.Bold))
        self.header.setStyleSheet(f"QLabel {{ background-color: {HEADER_BG}; color: {PINK}; border: none; border-bottom: 1px solid {BORDER_COLOR}; padding: 8px 15px; border-top-left-radius: 7px; border-top-right-radius: 7px; }}")
        self.layout.addWidget(self.header)
            
        self.content_widget = QWidget()
        self.content_layout = QVBoxLayout(self.content_widget)
        pad = 20 if left_padding else 10
        self.content_layout.setContentsMargins(pad, pad, pad, pad)
        self.content_widget.setStyleSheet(f"QWidget {{ border: none; background-color: transparent; border-bottom-left-radius: 7px; border-bottom-right-radius: 7px; }}")
        self.layout.addWidget(self.content_widget)

    def set_title(self, title):
        self.header.setText(f" {title} ")

    def apply_theme(self, theme):
        self.setStyleSheet(f"QFrame {{ border: 1px solid {theme['BORDER_COLOR']}; background-color: {theme['PANE_BG']}; border-radius: 8px; }}")
        self.header.setStyleSheet(f"QLabel {{ background-color: {theme['HEADER_BG']}; color: {theme['PINK']}; border: none; border-bottom: 1px solid {theme['BORDER_COLOR']}; padding: 8px 15px; border-top-left-radius: 7px; border-top-right-radius: 7px; }}")


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
            
            import tempfile, os, subprocess, re
            
            dir_name = os.path.dirname(os.path.abspath(self.file_path)) if self.file_path else tempfile.gettempdir()
            fd, temp_path = tempfile.mkstemp(suffix=".cpp", dir=dir_name)
            
            with os.fdopen(fd, 'w') as f:
                f.write(self.code)
                
            res = subprocess.run(
                ["g++", "-fsyntax-only", "-std=c++17", temp_path],
                capture_output=True,
                text=True
            )
            
            errors = []
            pattern = r"(.+):(\d+):(\d+):\s+(error|warning):\s+(.*)"
            for line in res.stderr.splitlines():
                match = re.match(pattern, line)
                if match:
                    if temp_path in match.group(1) or os.path.basename(temp_path) in match.group(1):
                        errors.append({
                            "line": int(match.group(2)),
                            "column": int(match.group(3)),
                            "error_type": match.group(4),
                            "message": match.group(5)
                        })
            
            os.remove(temp_path)
            self.finished.emit(errors)
        except Exception as e:
            self.finished.emit([])
            try:
                if 'temp_path' in locals() and os.path.exists(temp_path):
                    os.remove(temp_path)
            except:
                pass


class ASTViewerDialog(QDialog):
    def __init__(self, ast_tree, parent=None):
        super().__init__(parent)
        self.setWindowTitle("AST EXPLORER :: ARCHITECTURE VIEW")
        self.resize(1000, 700)
        self.setStyleSheet(f"QDialog {{ background-color: {BG_COLOR}; }}")
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        
        label = QLabel("ABSTRACT SYNTAX TREE")
        label.setFont(QFont(FONT_FAMILY, 14, QFont.Weight.Bold))
        label.setStyleSheet(f"color: {PINK}; margin-bottom: 10px;")
        layout.addWidget(label)

        self.tree = QTreeWidget()
        self.tree.setStyle(QStyleFactory.create("windows"))
        self.tree.setHeaderLabels(["NODE TYPE", "DETAILS / SOURCE"])
        self.tree.setColumnWidth(0, 300)
        self.tree.setAlternatingRowColors(True)
        self.tree.setStyleSheet(f"""
            QTreeWidget {{
                background-color: {PANE_BG};
                color: {TEXT_MAIN};
                border: 1px solid {BORDER_COLOR};
                font-family: {FONT_FAMILY};
                font-size: 12px;
                alternate-background-color: {BG_COLOR};
            }}
            QHeaderView::section {{
                background-color: {HEADER_BG};
                color: {PINK};
                border: 1px solid {BORDER_COLOR};
                padding: 10px;
                font-weight: bold;
            }}
            QTreeWidget::item {{
                padding: 5px;
                border-bottom: 1px solid {HEADER_BG};
            }}
            QTreeWidget::item:selected {{
                background-color: {BORDER_COLOR};
                color: {PINK};
            }}
        """)
        
        self._populate(ast_tree, self.tree.invisibleRootItem())
        
        layout.addWidget(self.tree)
        
        btn_close = StyledButton(" CLOSE VIEWER ", "solid_pink")
        btn_close.clicked.connect(self.close)
        btn_close.setFixedWidth(150)
        layout.addWidget(btn_close, 0, Qt.AlignmentFlag.AlignCenter)

    def _populate(self, nodes, parent_item):
        for n in nodes:
            item = QTreeWidgetItem(parent_item)
            item.setText(0, n["type"])
            item.setText(1, n["details"])
            
            if "Decl" in n["type"]:
                item.setForeground(0, QColor(PINK))
            elif "Stmt" in n["type"]:
                item.setForeground(0, QColor(KEYWORD_COLOR))
            elif "Expr" in n["type"]:
                item.setForeground(0, QColor(TEXT_MAIN))
            else:
                item.setForeground(0, QColor(TEXT_DIM))
                
            item.setForeground(1, QColor(TEXT_DIM))
            
            if n["children"]:
                self._populate(n["children"], item)


class TerminalDisplay(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.process = None 
        self.prompt_pos = 0
        self.setFont(QFont(FONT_FAMILY, 11))
        self.setStyleSheet(f"QTextEdit {{ background-color: transparent; border: 1px solid {BORDER_COLOR}; border-radius: 4px; color: {TEXT_MAIN}; line-height: 1.5; }}")

    def append_output(self, text, is_html=False):
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

    def keyPressEvent(self, event):
        if event.key() in [Qt.Key.Key_Up, Qt.Key.Key_Down, Qt.Key.Key_Left, Qt.Key.Key_Right, 
                           Qt.Key.Key_PageUp, Qt.Key.Key_PageDown, Qt.Key.Key_Home, Qt.Key.Key_End]:
            if event.key() == Qt.Key.Key_Left and self.textCursor().position() <= self.prompt_pos:
                return
            super().keyPressEvent(event)
            return

        if (event.modifiers() & (Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.MetaModifier)):
            if event.key() in [Qt.Key.Key_C, Qt.Key.Key_A]:
                super().keyPressEvent(event)
                return

        if not self.process or self.process.state() != QProcess.ProcessState.Running:
            return

        cursor = self.textCursor()
        if cursor.position() < self.prompt_pos:
            cursor.movePosition(QTextCursor.MoveOperation.End)
            self.setTextCursor(cursor)

        if event.key() == Qt.Key.Key_Return:
            cursor.setPosition(self.prompt_pos)
            cursor.movePosition(QTextCursor.MoveOperation.End, QTextCursor.MoveMode.KeepAnchor)
            text = cursor.selectedText().replace('\u2029', '\n')
            self.process.write((text + "\n").encode())
            
            self.setReadOnly(False)
            super().keyPressEvent(event)
            self.prompt_pos = self.document().characterCount() - 1
            self.ensureCursorVisible()
        elif event.key() == Qt.Key.Key_Backspace:
            if cursor.position() > self.prompt_pos:
                self.setReadOnly(False)
                super().keyPressEvent(event)
        else:
            if event.text():
                self.setReadOnly(False)
                super().keyPressEvent(event)

    def mousePressEvent(self, event):
        super().mousePressEvent(event)
        if self.process and self.process.state() == QProcess.ProcessState.Running:
            if self.textCursor().position() < self.prompt_pos:
                cursor = self.textCursor()
                cursor.movePosition(QTextCursor.MoveOperation.End)
                self.setTextCursor(cursor)


class _KeywordClassifier:
    """
    Lightweight fallback classifier using keyword matching.
    Used when the ML model isn't trained yet.
    """
    _RULES = [
        ("missing_include",  ["'std::", "was not declared", "no member named", "include"]),
        ("syntax_error",     ["expected ';'", "expected ')'", "expected '{'", "parse error", "stray"]),
        ("name_resolution",  ["undeclared", "not declared", "undefined", "cannot find"]),
        ("type_error",       ["cannot convert", "invalid conversion", "no matching function", "incompatible"]),
        ("return_type_error",["return type", "no return", "control reaches end"]),
        ("redefinition",     ["redefinition", "already defined", "multiple definition"]),
        ("linker_error",     ["undefined reference", "linker", "ld returned"]),
        ("access_error",     ["is private", "is protected", "inaccessible"]),
    ]

    def predict(self, message: str, ast_node: str = "") -> tuple:
        msg_lower = (message + " " + ast_node).lower()
        for category, keywords in self._RULES:
            if any(kw in msg_lower for kw in keywords):
                return category, 0.8
        return "other", 0.5


class UserGuidanceDialog(QDialog):
    """
    Shown when the healer exhausts all 3 attempts without fixing the error.
    Offers three actions: Edit Manually, Skip This Error, Give Me a Hint.
    """
    EDIT_MANUALLY = 1
    SKIP          = 2
    GIVE_HINT     = 3

    def __init__(self, history: list, parent=None):
        super().__init__(parent)
        self.setWindowTitle("⚕ Auto-Heal — Guidance Needed")
        self.setModal(True)
        self.setMinimumWidth(500)
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {BG_COLOR};
                color: {TEXT_MAIN};
                font-family: {FONT_FAMILY};
            }}
            QLabel {{ color: {TEXT_MAIN}; font-family: {FONT_FAMILY}; }}
            QLineEdit {{
                background-color: {PANE_BG};
                color: {TEXT_MAIN};
                border: 1px solid {BORDER_COLOR};
                border-radius: 4px;
                padding: 6px;
                font-family: {FONT_FAMILY};
            }}
        """)
        self._result_code = self.SKIP
        self._hint = ""

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(20, 20, 20, 20)

        # Header
        warn = QLabel("⚠️  I tried 3 fixes but couldn't resolve this error.")
        warn.setStyleSheet(f"color: {YELLOW}; font-size: 13px; font-weight: bold;")
        layout.addWidget(warn)

        # Last error detail
        last_err = next((h.get("error") for h in reversed(history) if h.get("error")), {})
        raw_msg = last_err.get("message", "Unknown error")
        cat     = last_err.get("category", "other")
        line_no = last_err.get("line", "?")
        suggestion = last_err.get("suggestion", "")

        layout.addWidget(QLabel(f"<b>Error:</b> {raw_msg}"))
        layout.addWidget(QLabel(f"<b>Category:</b> {cat}  |  <b>Line:</b> {line_no}"))

        if suggestion:
            suggestion_title = QLabel("<b>Suggested fix:</b>")
            layout.addWidget(suggestion_title)
            suggestion_box = QLabel(suggestion.replace("\n", "<br>"))
            suggestion_box.setTextFormat(Qt.TextFormat.RichText)
            suggestion_box.setWordWrap(True)
            suggestion_box.setStyleSheet(
                f"background-color: {PANE_BG}; border: 1px solid {BORDER_COLOR}; "
                f"border-radius: 4px; padding: 8px; color: {TEXT_MAIN};"
            )
            layout.addWidget(suggestion_box)

        # What was tried
        tried_label = QLabel("<b>What I tried:</b>")
        layout.addWidget(tried_label)
        for h in history:
            if h.get("patch"):
                attempt_lbl = QLabel(f"  • Attempt {h['attempt']}: applied a patch for [{h['error'].get('category', '?').upper()}]")
                attempt_lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")
                layout.addWidget(attempt_lbl)
            elif h.get("reason"):
                attempt_lbl = QLabel(f"  • Attempt {h.get('attempt', '?')}: {h['reason']}")
                attempt_lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")
                layout.addWidget(attempt_lbl)

        # Hint input
        hint_label = QLabel("→ Give me a hint (optional):")
        layout.addWidget(hint_label)
        self._hint_input = QLineEdit()
        self._hint_input.setPlaceholderText("e.g.  the variable x should be a pointer")
        layout.addWidget(self._hint_input)

        # Action buttons
        btn_row = QHBoxLayout()
        btn_edit = StyledButton("✏️  Edit Manually", "outline_dim")
        btn_skip = StyledButton("⏭  Skip This Error", "outline_dim")
        btn_hint = StyledButton("💡  Give Hint & Retry", "solid_pink")
        btn_edit.clicked.connect(self._do_edit)
        btn_skip.clicked.connect(self._do_skip)
        btn_hint.clicked.connect(self._do_hint)
        btn_row.addWidget(btn_edit)
        btn_row.addWidget(btn_skip)
        btn_row.addWidget(btn_hint)
        layout.addLayout(btn_row)

    def _do_edit(self):
        self._result_code = self.EDIT_MANUALLY
        self.done(self.EDIT_MANUALLY)

    def _do_skip(self):
        self._result_code = self.SKIP
        self.done(self.SKIP)

    def _do_hint(self):
        self._hint = self._hint_input.text().strip()
        self._result_code = self.GIVE_HINT
        self.done(self.GIVE_HINT)

    def hint_text(self) -> str:
        return self._hint


class SidebarButton(QPushButton):
    def __init__(self, text: str, tooltip: str = "", parent=None):
        super().__init__(text, parent)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(38)
        self.setFont(QFont(FONT_FAMILY, 10))
        self.setToolTip(tooltip)
        self.is_active = False
        self._apply_style()

    def set_active(self, active: bool):
        self.is_active = active
        self._apply_style()

    def _apply_style(self):
        active_bg = CURRENT_THEME.get("ACTIVE_NAV_BG", "#e9ecf8")
        hover_bg = CURRENT_THEME.get("HOVER_NAV_BG", "#eef2f7")
        if self.is_active:
            self.setStyleSheet(f"""
                QPushButton {{
                    text-align: left;
                    padding-left: 12px;
                    border: 1px solid {PINK};
                    background-color: {active_bg};
                    color: {PINK};
                    font-weight: bold;
                    border-radius: 6px;
                }}
            """)
        else:
            self.setStyleSheet(f"""
                QPushButton {{
                    text-align: left;
                    padding-left: 12px;
                    border: 1px solid transparent;
                    background-color: transparent;
                    color: {TEXT_MAIN};
                    border-radius: 6px;
                }}
                QPushButton:hover {{
                    background-color: {hover_bg};
                    border: 1px solid {BORDER_COLOR};
                    color: {PINK};
                }}
                QPushButton:pressed {{
                    background-color: {BORDER_COLOR};
                }}
            """)


class Sidebar(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedWidth(185)
        
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(8, 12, 8, 12)
        self.layout.setSpacing(6)
        
        self.title_lbl = QLabel("NAVIGATION")
        self.title_lbl.setFont(QFont(FONT_FAMILY, 8, QFont.Weight.Bold))
        self.title_lbl.setStyleSheet(f"color: {TEXT_DIM}; letter-spacing: 1px; padding: 2px 8px 6px 8px;")
        self.layout.addWidget(self.title_lbl)

        self.btn1 = SidebarButton("💻  Code Editor", "Main C++ editor, diagnostics, and I/O runner")
        self.btn2 = SidebarButton("🌳  AST Explorer", "Abstract Syntax Tree hierarchy viewer")
        self.btn3 = SidebarButton("⚡  Energy Metrics", "Real-time energy consumption and carbon emissions")
        self.btn4 = SidebarButton("🔄  Call Graph", "Function call relationship diagram")
        self.btn5 = SidebarButton("🛡️  Security Scan", "Static security vulnerability inspection")
        self.btn6 = SidebarButton("🔀  Control Flow", "Control flow graph (CFG) visualizer")
        self.btn7 = SidebarButton("🧠  Second Opinion", "ML Classifier vs Regex error categorization")
        self.btn8 = SidebarButton("📊  Benchmark", "Measured accuracy benchmark comparison")

        self.buttons = [
            self.btn1, self.btn2, self.btn3, self.btn4,
            self.btn5, self.btn6, self.btn7, self.btn8
        ]

        # Compatibility aliases
        self._btn_second_opinion = self.btn7
        self._btn_benchmark = self.btn8

        for btn in self.buttons:
            self.layout.addWidget(btn)

        self.layout.addStretch()

        self.setStyleSheet(f"""
            QWidget {{
                background-color: {HEADER_BG};
                border-right: 1px solid {BORDER_COLOR};
                border-top-left-radius: 0px;
                border-bottom-left-radius: 6px;
            }}
        """)
        self.set_active(0)

    def set_active(self, active_index: int):
        for idx, btn in enumerate(self.buttons):
            btn.set_active(idx == active_index)

    def apply_theme(self, theme):
        self.setStyleSheet(f"""
            QWidget {{
                background-color: {theme['HEADER_BG']};
                border-right: 1px solid {theme['BORDER_COLOR']};
                border-top-left-radius: 0px;
                border-bottom-left-radius: 6px;
            }}
        """)
        if hasattr(self, "title_lbl"):
            self.title_lbl.setStyleSheet(f"color: {theme['TEXT_DIM']}; letter-spacing: 1px; padding: 2px 8px 6px 8px;")
        for btn in self.buttons:
            btn._apply_style()


class ASTPage(CustomFrame):
    def __init__(self, parent=None):
        super().__init__("ABSTRACT SYNTAX TREE EXPLORER", left_padding=True)
        
        # Action bar with Reload, Expand All, Collapse All
        action_bar = QHBoxLayout()
        action_bar.setContentsMargins(0, 0, 0, 8)
        action_bar.setSpacing(8)

        self.info_lbl = QLabel("Parsed Abstract Syntax Tree representing your C++ declarations, statements, and expressions.")
        self.info_lbl.setFont(QFont(FONT_FAMILY, 9))
        self.info_lbl.setStyleSheet(f"color: {TEXT_DIM};")
        self.info_lbl.setWordWrap(True)
        action_bar.addWidget(self.info_lbl, 1)

        self.btn_reload = StyledButton("🔄 RELOAD AST", "outline_dim")
        self.btn_reload.setFixedHeight(30)
        self.btn_reload.setFont(QFont(FONT_FAMILY, 9, QFont.Weight.Bold))
        self.btn_reload.setToolTip("Parse current editor code into AST tree")
        action_bar.addWidget(self.btn_reload)

        self.btn_expand = StyledButton("➕ EXPAND ALL", "outline_dim")
        self.btn_expand.setFixedHeight(30)
        self.btn_expand.setFont(QFont(FONT_FAMILY, 9, QFont.Weight.Bold))
        self.btn_expand.setToolTip("Expand all tree branches")
        action_bar.addWidget(self.btn_expand)

        self.btn_collapse = StyledButton("➖ COLLAPSE ALL", "outline_dim")
        self.btn_collapse.setFixedHeight(30)
        self.btn_collapse.setFont(QFont(FONT_FAMILY, 9, QFont.Weight.Bold))
        self.btn_collapse.setToolTip("Collapse all tree branches")
        action_bar.addWidget(self.btn_collapse)

        self.content_layout.addLayout(action_bar)

        self.tree = QTreeWidget()
        self.tree.setStyle(QStyleFactory.create("windows"))
        self.tree.setHeaderLabels(["NODE TYPE", "DETAILS / SOURCE"])
        self.tree.setColumnWidth(0, 320)
        self.tree.setAlternatingRowColors(True)
        self.tree.setStyleSheet(f"""
            QTreeWidget {{
                background-color: {PANE_BG};
                color: {TEXT_MAIN};
                border: 1px solid {BORDER_COLOR};
                border-radius: 6px;
                font-family: {FONT_FAMILY};
                font-size: 12px;
                alternate-background-color: {BG_COLOR};
            }}
            QHeaderView::section {{
                background-color: {HEADER_BG};
                color: {PINK};
                border: none;
                border-bottom: 1px solid {BORDER_COLOR};
                padding: 10px;
                font-weight: bold;
            }}
            QTreeWidget::item {{
                padding: 6px;
            }}
            QTreeWidget::item:selected {{
                background-color: {BORDER_COLOR};
                color: {PINK};
            }}
        """)
        self.content_layout.addWidget(self.tree, 1)

        self.btn_expand.clicked.connect(self.tree.expandAll)
        self.btn_collapse.clicked.connect(self.tree.collapseAll)

    def update_tree(self, ast_tree):
        self.tree.clear()
        if not ast_tree:
            empty_item = QTreeWidgetItem(self.tree.invisibleRootItem())
            empty_item.setText(0, "No AST Nodes")
            empty_item.setText(1, "Click 'COMPILE' or 'RELOAD AST' to parse your C++ code into an AST tree.")
            empty_item.setForeground(0, QColor(CURRENT_THEME["TEXT_DIM"]))
            empty_item.setForeground(1, QColor(CURRENT_THEME["TEXT_DIM"]))
            return
        self._populate(ast_tree, self.tree.invisibleRootItem())
        self.tree.expandAll()

    def _populate(self, nodes, parent_item):
        for n in nodes:
            item = QTreeWidgetItem(parent_item)
            item.setText(0, n.get("type", ""))
            item.setText(1, n.get("details", ""))
            
            t = n.get("type", "")
            if "Decl" in t:
                item.setForeground(0, QColor(CURRENT_THEME["PINK"]))
            elif "Stmt" in t:
                item.setForeground(0, QColor(CURRENT_THEME["KEYWORD_COLOR"]))
            elif "Expr" in t:
                item.setForeground(0, QColor(CURRENT_THEME["TEXT_MAIN"]))
            else:
                item.setForeground(0, QColor(CURRENT_THEME["TEXT_DIM"]))
                
            item.setForeground(1, QColor(CURRENT_THEME["TEXT_DIM"]))
            
            if "children" in n and n["children"]:
                self._populate(n["children"], item)

    def apply_theme(self, theme):
        super().apply_theme(theme)
        self.tree.setStyleSheet(f"""
            QTreeWidget {{
                background-color: {theme['PANE_BG']};
                color: {theme['TEXT_MAIN']};
                border: 1px solid {theme['BORDER_COLOR']};
                border-radius: 6px;
                font-family: {FONT_FAMILY};
                font-size: 12px;
                alternate-background-color: {theme['BG_COLOR']};
            }}
            QHeaderView::section {{
                background-color: {theme['HEADER_BG']};
                color: {theme['PINK']};
                border: none;
                border-bottom: 1px solid {theme['BORDER_COLOR']};
                padding: 10px;
                font-weight: bold;
            }}
            QTreeWidget::item {{
                padding: 6px;
            }}
            QTreeWidget::item:selected {{
                background-color: {theme['BORDER_COLOR']};
                color: {theme['PINK']};
            }}
        """)
        if hasattr(self, "info_lbl"):
            self.info_lbl.setStyleSheet(f"color: {theme['TEXT_DIM']};")
        if hasattr(self, "btn_reload"):
            self.btn_reload._update_style(0)
            self.btn_expand._update_style(0)
            self.btn_collapse._update_style(0)


class EnergyPage(CustomFrame):
    def __init__(self, parent=None):
        super().__init__("CODECARBON INDEX :: ENERGY TELEMETRY", left_padding=True)
        
        self.desc = QLabel("Power usage, carbon intensity, execution time, and RAPL")
        self.desc.setStyleSheet(f"color: {PINK}; font-weight: bold; font-size: 14px;")
        self.content_layout.addWidget(self.desc)

        self.metric_row = QWidget()
        metric_layout = QHBoxLayout(self.metric_row)
        metric_layout.setContentsMargins(0, 0, 0, 0)
        metric_layout.setSpacing(10)
        self.power_value = self._metric_label("Power Usage", "0.000 mW")
        self.carbon_value = self._metric_label("Carbon Intensity", "0.000 mgCO2/Wh")
        self.time_value = self._metric_label("Execution Time", "0.000 s")
        self.rapl_value = self._metric_label("RAPL", "Unavailable")
        for label in [self.power_value, self.carbon_value, self.time_value, self.rapl_value]:
            metric_layout.addWidget(label)
        self.content_layout.addWidget(self.metric_row)

        self.graph = MetricsGraph()
        self.graph.setStyleSheet(f"""
            MetricsGraph {{
                background-color: {BG_COLOR};
                border: 1px solid {BORDER_COLOR};
                border-radius: 6px;
            }}
        """)
        self.content_layout.addWidget(self.graph, 1)

        self.notes = QTextBrowser()
        self.notes.setMaximumHeight(145)
        self.notes.setStyleSheet(f"""
            QTextBrowser {{
                background-color: {BG_COLOR};
                border: 1px solid {BORDER_COLOR};
                border-radius: 6px;
                color: {TEXT_MAIN};
                font-family: {FONT_FAMILY};
                font-size: 12px;
                padding: 10px;
            }}
        """)
        self.content_layout.addWidget(self.notes)
        
        self.btn_download_csv = StyledButton(" 📥 DOWNLOAD CSV REPORT ", "outline_dim")
        self.btn_download_csv.clicked.connect(self._download_csv)
        self.content_layout.addWidget(self.btn_download_csv, 0, Qt.AlignmentFlag.AlignRight)

        self.update_metrics(0, 0, 0, "Unavailable", "CodeCarbon has not produced a sample yet.")
        
        self.csv_path = "emissions.csv"
        self.poll_timer = QTimer(self)
        self.poll_timer.setInterval(1000)
        self.poll_timer.timeout.connect(self._poll_csv)
        self.poll_timer.start()

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
            
            # Map correct CodeCarbon columns and adjust units
            energy_kwh = float(latest.get("energy_consumed", 0))
            power_mw = energy_kwh * 1_000_000  # kWh to mWh
            
            emissions_kg = float(latest.get("emissions", 0))
            carbon_mg = emissions_kg * 1_000_000  # kg to mg
            
            duration = float(latest.get("duration", 0))
            
            intensity = carbon_mg / power_mw if power_mw > 0 else 0.0

            # On macOS, RAPL might be missing so handle cpu_energy gracefully
            cpu_energy = latest.get("cpu_energy", "")
            rapl_text = f"{float(cpu_energy):.3f} kWh" if cpu_energy and float(cpu_energy) > 0 else "Unavailable"
            
            self.update_metrics(power_mw, intensity, duration, rapl_text, "Live polling from CodeCarbon CSV output.")
        except Exception as e:
            pass

    def _metric_label(self, title, value):
        label = QLabel(f"<span style='color:{TEXT_DIM};'>{title}</span><br><b style='color:{PINK}; font-size:18px;'>{value}</b>")
        label.setTextFormat(Qt.TextFormat.RichText)
        label.setMinimumHeight(72)
        label.setStyleSheet(f"""
            QLabel {{
                background-color: {BG_COLOR};
                border: 1px solid {BORDER_COLOR};
                border-radius: 6px;
                padding: 10px;
                font-family: {FONT_FAMILY};
            }}
        """)
        return label

    def update_metrics(self, power_mw, carbon_mg_per_wh, execution_time, rapl_text, note):
        self.power_value.setText(f"<span style='color:{TEXT_DIM};'>Power Usage</span><br><b style='color:{PINK}; font-size:18px;'>{power_mw:.3f} mW</b>")
        self.carbon_value.setText(f"<span style='color:{TEXT_DIM};'>Carbon Intensity</span><br><b style='color:{GREEN}; font-size:18px;'>{carbon_mg_per_wh:.3f} mgCO2/Wh</b>")
        self.time_value.setText(f"<span style='color:{TEXT_DIM};'>Execution Time</span><br><b style='color:{YELLOW}; font-size:18px;'>{execution_time:.3f} s</b>")
        self.rapl_value.setText(f"<span style='color:{TEXT_DIM};'>RAPL</span><br><b style='color:{TEXT_MAIN}; font-size:16px;'>{rapl_text}</b>")
        self.graph.add_sample(power_mw, carbon_mg_per_wh, execution_time)
        self.notes.setHtml(f"""
            <b style="color:{PINK};">Telemetry source</b><br>
            {note}<br><br>
            <b style="color:{TEXT_DIM};">RAPL</b>: Reads Linux powercap energy counters when available.
            <code>/sys/class/powercap</code>.
        """)

    def apply_theme(self, theme):
        super().apply_theme(theme)
        if hasattr(self, "desc"):
            self.desc.setStyleSheet(f"color: {theme['PINK']}; font-weight: bold; font-size: 14px;")
        for lbl in [getattr(self, "power_value", None), getattr(self, "carbon_value", None), getattr(self, "time_value", None), getattr(self, "rapl_value", None)]:
            if lbl:
                lbl.setStyleSheet(f"""
                    QLabel {{
                        background-color: {theme['BG_COLOR']};
                        border: 1px solid {theme['BORDER_COLOR']};
                        border-radius: 6px;
                        padding: 10px;
                        font-family: {FONT_FAMILY};
                    }}
                """)
        if hasattr(self, "graph"):
            self.graph.setStyleSheet(f"""
                MetricsGraph {{
                    background-color: {theme['BG_COLOR']};
                    border: 1px solid {theme['BORDER_COLOR']};
                    border-radius: 6px;
                }}
            """)
        if hasattr(self, "notes"):
            self.notes.setStyleSheet(f"""
                QTextBrowser {{
                    background-color: {theme['BG_COLOR']};
                    border: 1px solid {theme['BORDER_COLOR']};
                    border-radius: 6px;
                    color: {theme['TEXT_MAIN']};
                    font-family: {FONT_FAMILY};
                    font-size: 12px;
                    padding: 10px;
                }}
            """)
        if hasattr(self, "btn_download_csv"):
            self.btn_download_csv._update_style(0)


class CallGraphPage(CustomFrame):
    def __init__(self, parent=None):
        super().__init__("FUNCTION CALL GRAPH :: MODULE RELATIONSHIPS", left_padding=True)
        self.summary = QLabel("Compile or open this page to map functions, internal calls, external calls, and included modules.")
        self.summary.setStyleSheet(f"color: {TEXT_DIM}; font-family: {FONT_FAMILY};")
        self.summary.setWordWrap(True)
        self.content_layout.addWidget(self.summary)

        self.graph = CallGraphWidget()
        self.graph.setStyleSheet(f"background-color: {PANE_BG}; border: 1px solid {BORDER_COLOR}; border-radius: 6px;")
        self.content_layout.addWidget(self.graph, 1)

    def update_from_code(self, code):
        functions, edges, external_calls, modules = _extract_cpp_call_graph(code)
        self.graph.update_graph(functions, edges, external_calls, modules)
        self.summary.setText(
            f"Functions: {len(functions)} | Internal calls: {len(edges)} | "
            f"External calls: {len(external_calls)} | Modules/includes: {len(modules)}"
        )

    def apply_theme(self, theme):
        super().apply_theme(theme)
        if hasattr(self, "summary"):
            self.summary.setStyleSheet(f"color: {theme['TEXT_DIM']}; font-family: {FONT_FAMILY};")
        if hasattr(self, "graph"):
            self.graph.setStyleSheet(f"background-color: {theme['PANE_BG']}; border: 1px solid {theme['BORDER_COLOR']}; border-radius: 6px;")
            self.graph.scene.setBackgroundBrush(QColor(theme['PANE_BG']))


class CFGWidget(QGraphicsView):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(420)
        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setBackgroundBrush(QColor(PANE_BG))

    def update_graph(self, functions_data):
        self.scene.clear()
        if not functions_data:
            t = self.scene.addText("No functions found for CFG analysis.")
            t.setDefaultTextColor(QColor(TEXT_DIM))
            t.setFont(QFont(FONT_FAMILY, 12))
            return

        # Simple vertical layout for demo
        y_offset = 50
        margin_x = 100
        
        for func in functions_data:
            nodes_data = func["nodes"]
            edges_data = func["edges"]
            
            node_map = {}
            node_w, node_h = 180, 50
            
            # Label for function
            f_lbl = self.scene.addText(f"FUNCTION: {func['name']}")
            f_lbl.setFont(QFont(FONT_FAMILY, 10, QFont.Weight.Bold))
            f_lbl.setDefaultTextColor(QColor(PINK))
            f_lbl.setPos(margin_x, y_offset - 30)
            
            # Simple linear vertical layout for nodes
            for i, n in enumerate(nodes_data):
                color = {
                    "entry": QColor("#e1f5fe"),
                    "exit": QColor("#fce4ec"),
                    "branch": QColor("#fff9c4"),
                    "stmt": QColor("#ffffff")
                }.get(n["type"], QColor("#ffffff"))
                
                border = {
                    "entry": QColor("#03a9f4"),
                    "exit": QColor("#f06292"),
                    "branch": QColor("#fbc02d"),
                    "stmt": QColor(BORDER_COLOR)
                }.get(n["type"], QColor(BORDER_COLOR))
                
                # if branch type, make it diamond-ish or just distinct
                node = GraphNode(n["label"], margin_x, y_offset, node_w, node_h, border, color)
                self.scene.addItem(node)
                node_map[n["id"]] = node
                y_offset += 80
            
            for start_id, end_id in edges_data:
                if start_id in node_map and end_id in node_map:
                    edge = GraphEdge(node_map[start_id], node_map[end_id], QColor(TEXT_DIM))
                    self.scene.addItem(edge)
            
            y_offset += 50 # gap between functions


class CFGPage(CustomFrame):
    def __init__(self, parent=None):
        super().__init__("CONTROL FLOW GRAPH :: EXECUTION PATHS", left_padding=True)
        self.summary = QLabel("Visualizing the logical structure and execution paths of your C++ code.")
        self.summary.setStyleSheet(f"color: {TEXT_DIM}; font-family: {FONT_FAMILY};")
        self.content_layout.addWidget(self.summary)
        
        self.graph = CFGWidget()
        self.graph.setStyleSheet(f"background-color: {PANE_BG}; border: 1px solid {BORDER_COLOR}; border-radius: 6px;")
        self.content_layout.addWidget(self.graph, 1)

    def update_from_code(self, code):
        data = _extract_cpp_cfg(code)
        self.graph.update_graph(data)
        self.summary.setText(f"Functions Analyzed: {len(data)} | Total Nodes: {sum(len(f['nodes']) for f in data)}")

    def apply_theme(self, theme):
        super().apply_theme(theme)
        if hasattr(self, "summary"):
            self.summary.setStyleSheet(f"color: {theme['TEXT_DIM']}; font-family: {FONT_FAMILY};")
        if hasattr(self, "graph"):
            self.graph.setStyleSheet(f"background-color: {theme['PANE_BG']}; border: 1px solid {theme['BORDER_COLOR']}; border-radius: 6px;")
            self.graph.setBackgroundBrush(QColor(theme['PANE_BG']))


class FilterTabButton(QPushButton):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(34)
        self.setFont(QFont(FONT_FAMILY, 10, QFont.Weight.Bold))
        self._active = False
        self._apply_style(False)

    def setActive(self, active: bool):
        self._active = active
        self.setChecked(active)
        self._apply_style(active)

    def _apply_style(self, active: bool):
        if active:
            self.setStyleSheet("""
                QPushButton {
                    background-color: #6C5CE7;
                    color: white;
                    border: none;
                    border-radius: 16px;
                    padding: 8px 14px;
                }
                QPushButton:hover {
                    background-color: #7B6BEE;
                }
            """)
        else:
            self.setStyleSheet("""
                QPushButton {
                    background-color: #F7F5FF;
                    color: #4F46E5;
                    border: 1px solid #E1DAFF;
                    border-radius: 16px;
                    padding: 8px 14px;
                }
                QPushButton:hover {
                    background-color: #EEE9FF;
                    border: 1px solid #C7B9FF;
                }
            """)


class SecurityCard(QFrame):
    def __init__(self, finding: dict, severity_color: str, parent=None):
        super().__init__(parent)
        self.finding = finding
        self.severity_color = severity_color
        self.expanded = True

        self.setObjectName("SecurityCard")
        self.setMouseTracking(True)
        self.setStyleSheet("""
            QFrame#SecurityCard {
                background-color: #ffffff;
                border: 1px solid #EEF0FF;
                border-radius: 14px;
            }
        """)

        self.shadow = QGraphicsDropShadowEffect(self)
        self.shadow.setBlurRadius(18)
        self.shadow.setOffset(0, 3)
        self.shadow.setColor(QColor(0, 0, 0, 18))
        self.setGraphicsEffect(self.shadow)
        self.shadow_anim = QPropertyAnimation(self.shadow, b"blurRadius", self)
        self.shadow_anim.setDuration(200)

        outer = QHBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self.strip = QFrame()
        self.strip.setFixedWidth(6)
        self.strip.setStyleSheet(f"background-color: {severity_color}; border: none; border-top-left-radius: 14px; border-bottom-left-radius: 14px;")
        outer.addWidget(self.strip)

        body = QWidget()
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(16, 14, 16, 14)
        body_layout.setSpacing(10)
        outer.addWidget(body, 1)

        top_row = QHBoxLayout()
        top_row.setSpacing(10)

        title_box = QVBoxLayout()
        title_box.setSpacing(3)
        vuln = finding.get("vulnerability_type", "Security Issue")
        self.title_label = QLabel(f"⚠️ {html.escape(vuln)}")
        self.title_label.setStyleSheet("color: #1F163A; font-size: 14px; font-weight: 700;")
        self.title_label.setWordWrap(True)
        self.title_label.setTextFormat(Qt.TextFormat.RichText)
        title_box.addWidget(self.title_label)

        loc = self._location_text(finding)
        self.meta_label = QLabel(f"📄 {html.escape(loc)}")
        self.meta_label.setStyleSheet("color: #8B90A6; font-size: 11px;")
        self.meta_label.setWordWrap(True)
        self.meta_label.setTextFormat(Qt.TextFormat.RichText)
        title_box.addWidget(self.meta_label)
        top_row.addLayout(title_box, 1)

        badge = QLabel(finding.get("severity", "Low").upper())
        badge_color = self.severity_color
        badge.setStyleSheet(f"""
            QLabel {{
                background-color: {badge_color};
                color: white;
                border-radius: 999px;
                padding: 5px 10px;
                font-size: 10px;
                font-weight: 700;
                letter-spacing: 0px;
            }}
        """)
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        top_row.addWidget(badge, 0, Qt.AlignmentFlag.AlignTop)

        body_layout.addLayout(top_row)

        desc_label = QLabel("DESCRIPTION")
        desc_label.setStyleSheet("color: #8B90A6; font-size: 10px; font-weight: 700; letter-spacing: 0px;")
        body_layout.addWidget(desc_label)

        self.description = QLabel(html.escape(finding.get("description", "")))
        self.description.setWordWrap(True)
        self.description.setStyleSheet("color: #1F163A; font-size: 12px;")
        self.description.setTextFormat(Qt.TextFormat.RichText)
        body_layout.addWidget(self.description)

        rec_label = QLabel("RECOMMENDATION")
        rec_label.setStyleSheet("color: #8B90A6; font-size: 10px; font-weight: 700;")
        body_layout.addWidget(rec_label)

        self.recommendation_box = QFrame()
        self.recommendation_box.setStyleSheet("""
            QFrame {
                background-color: #F6F1FF;
                border: 1px solid #E8DBFF;
                border-radius: 12px;
            }
        """)
        rec_layout = QVBoxLayout(self.recommendation_box)
        rec_layout.setContentsMargins(12, 10, 12, 10)
        rec_layout.setSpacing(4)
        self.recommendation = QLabel(f"🛡 {html.escape(finding.get('recommendation', ''))}")
        self.recommendation.setWordWrap(True)
        self.recommendation.setTextFormat(Qt.TextFormat.RichText)
        self.recommendation.setStyleSheet("color: #3F2CA1; font-size: 12px; font-weight: 600;")
        rec_layout.addWidget(self.recommendation)
        body_layout.addWidget(self.recommendation_box)

        self.details_row = QHBoxLayout()
        self.details_row.setSpacing(12)
        self.file_chip = QLabel(f"📄 {html.escape(self._file_only(finding))}")
        self.file_chip.setStyleSheet("color: #6F7591; font-size: 11px;")
        self.file_chip.setWordWrap(True)
        self.file_chip.setTextFormat(Qt.TextFormat.RichText)
        self.line_chip = QLabel(f"Line {finding.get('line', '—')}")
        self.line_chip.setStyleSheet("color: #6F7591; font-size: 11px;")
        self.source_chip = QLabel(f"Source: {str(finding.get('source', 'static_scan')).replace('_', ' ')}")
        self.source_chip.setStyleSheet("color: #6F7591; font-size: 11px;")
        self.details_row.addWidget(self.file_chip, 1)
        self.details_row.addWidget(self.line_chip, 0)
        self.details_row.addWidget(self.source_chip, 0)
        body_layout.addLayout(self.details_row)

        self.toggle_btn = QPushButton("Details")
        self.toggle_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.toggle_btn.setCheckable(True)
        self.toggle_btn.setChecked(True)
        self.toggle_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #6C5CE7;
                border: none;
                padding: 0;
                font-size: 11px;
                font-weight: 700;
            }
            QPushButton:hover {
                color: #4F46E5;
            }
        """)
        self.toggle_btn.toggled.connect(self._toggle_details)
        body_layout.addWidget(self.toggle_btn, 0, Qt.AlignmentFlag.AlignRight)

    def _file_only(self, finding):
        path = finding.get("file", "unknown")
        return os.path.basename(path) if path else "unknown"

    def _location_text(self, finding):
        path = finding.get("file", "unknown")
        line = finding.get("line")
        column = finding.get("column")
        if line is not None:
            if column is not None:
                return f"{path}:{line}:{column}"
            return f"{path}:{line}"
        return path

    def _toggle_details(self, checked):
        self.description.setVisible(checked)
        self.recommendation_box.setVisible(checked)
        self.details_row_widget_set_visible(checked)
        self.toggle_btn.setText("Hide" if checked else "Details")

    def details_row_widget_set_visible(self, visible):
        for i in range(self.details_row.count()):
            item = self.details_row.itemAt(i)
            widget = item.widget()
            if widget:
                widget.setVisible(visible)

    def enterEvent(self, event):
        self.shadow_anim.stop()
        self.shadow_anim.setStartValue(self.shadow.blurRadius())
        self.shadow_anim.setEndValue(30)
        self.shadow_anim.start()
        self.shadow.setColor(QColor(108, 92, 231, 42))
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.shadow_anim.stop()
        self.shadow_anim.setStartValue(self.shadow.blurRadius())
        self.shadow_anim.setEndValue(18)
        self.shadow_anim.start()
        self.shadow.setColor(QColor(0, 0, 0, 18))
        super().leaveEvent(event)


class SecurityPage(CustomFrame):
    def __init__(self, parent=None):
        super().__init__("SECURITY ANALYZER :: VULNERABILITY REPORT", left_padding=True)
        self.setStyleSheet("""
            QFrame {
                background-color: #ffffff;
                border: 1px solid #E8DBFF;
                border-radius: 16px;
            }
        """)
        self.header.setStyleSheet("""
            QLabel {
                background-color: #ffffff;
                color: #6C5CE7;
                border: none;
                border-bottom: 1px solid #F0E9FF;
                padding: 10px 16px;
                border-top-left-radius: 15px;
                border-top-right-radius: 15px;
            }
        """)
        self.content_widget.setStyleSheet("QWidget { background-color: #ffffff; }")
        self.content_layout.setContentsMargins(18, 18, 18, 18)
        self.content_layout.setSpacing(14)

        self.findings = []
        self.current_filter = "All"
        self._cards = []

        self.header_row = QHBoxLayout()
        self.header_row.setSpacing(12)

        title_box = QVBoxLayout()
        title_box.setSpacing(4)
        self.summary = QLabel("0 critical, 0 high, 0 medium, 0 low findings")
        self.summary.setStyleSheet("color: #1F163A; font-size: 18px; font-weight: 800;")
        self.summary.setWordWrap(True)
        title_box.addWidget(self.summary)

        self.subsummary = QLabel("Grouped security findings with exact source lines and fix guidance.")
        self.subsummary.setStyleSheet("color: #8B90A6; font-size: 12px;")
        self.subsummary.setWordWrap(True)
        title_box.addWidget(self.subsummary)
        self.header_row.addLayout(title_box, 1)

        self.risk_badge = QLabel("Risk Score: 0")
        self.risk_badge.setStyleSheet("""
            QLabel {
                background-color: #F6F1FF;
                color: #6C5CE7;
                border: 1px solid #E8DBFF;
                border-radius: 14px;
                padding: 8px 12px;
                font-weight: 700;
            }
        """)
        self.header_row.addWidget(self.risk_badge, 0, Qt.AlignmentFlag.AlignTop)
        self.content_layout.addLayout(self.header_row)

        self.permissions_box = QFrame()
        self.permissions_box.setStyleSheet("background-color: #F8F9FA; border-radius: 8px; border: 1px solid #E8DBFF;")
        pbox_layout = QHBoxLayout(self.permissions_box)
        pbox_layout.setContentsMargins(15, 10, 15, 10)
        pbox_label = QLabel("Sanitizer Policy:")
        pbox_label.setStyleSheet("font-weight: bold; color: #1F163A;")
        pbox_layout.addWidget(pbox_label)
        
        self.perm_system_calls = StyledCheckBox("Allow System Calls")
        self.perm_assembly = StyledCheckBox("Allow Inline Assembly")
        self.perm_sys_includes = StyledCheckBox("Allow <sys/*>")
        
        for chk in [self.perm_system_calls, self.perm_assembly, self.perm_sys_includes]:
            pbox_layout.addWidget(chk)
            chk.stateChanged.connect(self._update_permissions)
            
        pbox_layout.addStretch()
        self.content_layout.addWidget(self.permissions_box)
        self._update_permissions()

        self.risk_bar = QProgressBar()
        self.risk_bar.setRange(0, 100)
        self.risk_bar.setTextVisible(False)
        self.risk_bar.setFixedHeight(10)
        self.risk_bar.setStyleSheet("""
            QProgressBar {
                background-color: #F1ECFF;
                border: none;
                border-radius: 5px;
            }
            QProgressBar::chunk {
                background-color: #6C5CE7;
                border-radius: 5px;
            }
        """)
        self.content_layout.addWidget(self.risk_bar)

        self.filter_row = QHBoxLayout()
        self.filter_row.setSpacing(8)
        self.filter_buttons = {}
        for label in ["All", "High", "Medium", "Low"]:
            btn = FilterTabButton(label)
            btn.clicked.connect(lambda _checked=False, value=label: self.set_filter(value))
            self.filter_buttons[label] = btn
            self.filter_row.addWidget(btn)
        self.filter_row.addStretch()
        self.content_layout.addLayout(self.filter_row)
        self.filter_buttons["All"].setActive(True)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        self.report_host = QWidget()
        self.report_host.setStyleSheet("QWidget { background: transparent; }")
        self.report_layout = QVBoxLayout(self.report_host)
        self.report_layout.setContentsMargins(0, 0, 0, 0)
        self.report_layout.setSpacing(14)
        self.report_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.scroll.setWidget(self.report_host)
        self.content_layout.addWidget(self.scroll, 1)

        self.update_report([])

    def _normalize_findings(self, findings):
        normalized = []
        for finding in findings or []:
            if hasattr(finding, "to_dict"):
                normalized.append(finding.to_dict())
            elif isinstance(finding, dict):
                normalized.append(finding)
        return normalized

    def _badge_color(self, severity):
        return {
            "Critical": "#FF4D4D",
            "High": "#FF4D4D",
            "Medium": "#FFA500",
            "Low": "#2ECC71",
        }.get(severity, "#2ECC71")

    def _group_counts(self, findings):
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for finding in findings:
            sev = finding.get("severity", "Low")
            if sev == "Critical":
                counts["Critical"] += 1
            elif sev in counts:
                counts[sev] += 1
        return counts

    def _risk_score(self, findings):
        weights = {"Critical": 10, "High": 5, "Medium": 2, "Low": 1}
        return sum(weights.get(f.get("severity", "Low"), 1) for f in findings)

    def _risk_label(self, score):
        if score == 0:
            return "Clean"
        if score <= 10:
            return "Low Risk"
        if score <= 30:
            return "Moderate"
        return "High Risk"

    def _clear_cards(self):
        while self.report_layout.count():
            item = self.report_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        self._cards = []

    def _display_filter(self, severity):
        if self.current_filter == "All":
            return True
        if self.current_filter == "High":
            return severity in ("Critical", "High")
        return severity == self.current_filter

    def _match_sections(self, findings):
        sections = []
        for severity in ("Critical", "High", "Medium", "Low"):
            group = [f for f in findings if f.get("severity", "Low") == severity]
            if not group:
                continue
            if not any(self._display_filter(severity) for _ in group):
                continue
            sections.append((severity, group))
        return sections

    def _make_empty_state(self):
        card = QFrame()
        card.setStyleSheet("""
            QFrame {
                background-color: #ffffff;
                border: 1px solid #EEF0FF;
                border-radius: 14px;
            }
        """)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 16, 16, 16)
        label = QLabel("No security findings detected.")
        label.setStyleSheet("color: #1F163A; font-size: 13px; font-weight: 600;")
        layout.addWidget(label)
        return card

    def set_filter(self, value):
        self.current_filter = value
        for label, btn in self.filter_buttons.items():
            btn.setActive(label == value)
        self._render()

    def update_report(self, findings):
        self.findings = self._normalize_findings(findings)
        self._render()

    def _render(self):
        counts = self._group_counts(self.findings)
        score = self._risk_score(self.findings)
        self.summary.setText(
            f"{counts['Critical']} critical, {counts['High']} high, {counts['Medium']} medium, {counts['Low']} low findings"
        )
        self.risk_badge.setText(f"Risk Score: {score} • {self._risk_label(score)}")
        self.risk_bar.setValue(min(100, score * 3))

        self._clear_cards()

        filtered = [f for f in self.findings if self._display_filter(f.get("severity", "Low"))]
        if not filtered:
            self.report_layout.addWidget(self._make_empty_state())
            return

        for severity, group in self._match_sections(filtered):
            section = QLabel(f"{severity.upper()}  •  {len(group)}")
            section.setStyleSheet("color: #6C5CE7; font-size: 11px; font-weight: 800; letter-spacing: 0px;")
            self.report_layout.addWidget(section)
            for finding in group:
                self.report_layout.addWidget(SecurityCard(finding, self._badge_color(severity)))

    def _update_permissions(self):
        import os
        os.environ["ALLOW_SYSTEM_CALLS"] = "1" if self.perm_system_calls.isChecked() else "0"
        os.environ["ALLOW_ASSEMBLY"] = "1" if self.perm_assembly.isChecked() else "0"
        os.environ["ALLOW_SYS_INCLUDES"] = "1" if self.perm_sys_includes.isChecked() else "0"

    def apply_theme(self, theme):
        super().apply_theme(theme)
        card_bg = theme["PANE_BG"]
        text_color = theme["TEXT_MAIN"]
        dim_color = theme["TEXT_DIM"]
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {card_bg};
                border: 1px solid {theme['BORDER_COLOR']};
                border-radius: 16px;
            }}
        """)
        self.content_widget.setStyleSheet(f"QWidget {{ background-color: {card_bg}; }}")
        if hasattr(self, "summary"):
            self.summary.setStyleSheet(f"color: {text_color}; font-size: 18px; font-weight: 800;")
        if hasattr(self, "subsummary"):
            self.subsummary.setStyleSheet(f"color: {dim_color}; font-size: 12px;")
        if hasattr(self, "permissions_box"):
            self.permissions_box.setStyleSheet(f"background-color: {theme['BG_COLOR']}; border-radius: 8px; border: 1px solid {theme['BORDER_COLOR']};")


# ── Import new page classes (Feature 2 & 4) ───────────────────────────────────
try:
    from gui_new_pages import SecondOpinionPage, BenchmarkPage
    NEW_PAGES_AVAILABLE = True
except ImportError:
    NEW_PAGES_AVAILABLE = False
    SecondOpinionPage = None
    BenchmarkPage = None


class AppGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CppCheck Error Explainer")
        self.resize(1400, 850)


        self.file_name = "file.cpp"
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
        
        self.setStyleSheet(f"QMainWindow {{ background-color: {BG_COLOR}; }}")

        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(15)

        header_layout = QHBoxLayout()
        logo = QLabel("CppCheck Error Explainer")
        logo.setFont(QFont(FONT_FAMILY, 12, QFont.Weight.Bold))
        logo.setStyleSheet(f"color: {PINK}; letter-spacing:1px;")
        header_layout.addWidget(logo)
        header_layout.addStretch()
        
        if CODECARBON_AVAILABLE:
            header_layout.addSpacing(15)
            self.energy_container = QWidget()
            energy_hbox = QHBoxLayout(self.energy_container)
            energy_hbox.setContentsMargins(5, 0, 5, 0)
            energy_hbox.setSpacing(10)
            
            cpu_text = "CPU utilization" if HAS_PSUTIL else "CPU utilization (simulated)"
            cpu_label = QLabel(cpu_text)
            cpu_label.setFont(QFont(FONT_FAMILY, 10, QFont.Weight.Bold))
            cpu_label.setStyleSheet(f"color: {TEXT_DIM};")
            energy_hbox.addWidget(cpu_label)
            
            self.sparkline = SparklineGraph()
            self.sparkline.setFixedWidth(120)
            self.sparkline.setFixedHeight(30)
            energy_hbox.addWidget(self.sparkline)
            
            header_layout.addWidget(self.energy_container)
            
            try:

                if platform.system() == "Darwin":
                    try:
                        import codecarbon.core.powermetrics as powermetrics
                        powermetrics.is_powermetrics_available = lambda: False
                    except Exception:
                        pass
                
                self.tracker = EmissionsTracker(
                    save_to_file=False,
                    log_level="error",
                    force_cpu_power=12,
                    force_ram_power=3,
                    force_mode_cpu_load=True,
                    allow_multiple_runs=True,
                )
                self.tracker.start()
                
                self.energy_timer = QTimer(self)
                self.energy_timer.timeout.connect(self.update_energy_dashboard)
                self.energy_timer.start(600) 
                
                # Force immediate update
                self.update_energy_dashboard()
            except Exception as e:
                print(f"CodeCarbon Error: {e}")
                pass
        
        main_layout.addLayout(header_layout)

        toolbar_layout = QHBoxLayout()
        toolbar_layout.setSpacing(10)

        btn_load = StyledButton(" LOAD C++ FILE", "outline_dim")
        btn_load.clicked.connect(self.load_file)
        toolbar_layout.addWidget(btn_load)

        btn_compile = StyledButton(" COMPILE", "solid_pink")
        btn_compile.clicked.connect(self.analyze)
        toolbar_layout.addWidget(btn_compile)

        btn_run = StyledButton(" RUN CODE", "outline_dim")
        btn_run.clicked.connect(self.run_code)
        toolbar_layout.addWidget(btn_run)

        self.btn_heal = StyledButton("⚕ AUTO-HEAL", "outline_dim")
        self.btn_heal.clicked.connect(self.start_heal)
        self.btn_heal.setToolTip("Auto-detect + fix errors (up to 10 attempts)")
        toolbar_layout.addWidget(self.btn_heal)

        self.btn_undo_heal = StyledButton("↺ UNDO HEAL", "outline_dim")
        self.btn_undo_heal.setToolTip("Restore the file to its state before auto-heal")
        self.btn_undo_heal.clicked.connect(self.undo_heal)
        self.btn_undo_heal.setEnabled(False)
        toolbar_layout.addWidget(self.btn_undo_heal)

        self.btn_theme_toggle = StyledButton("🌙 DARK MODE", "outline_dim")
        self.btn_theme_toggle.setToolTip("Toggle between Light and Dark mode")
        self.btn_theme_toggle.clicked.connect(self.toggle_dark_mode)
        toolbar_layout.addWidget(self.btn_theme_toggle)

        self.is_dark_mode = False
        self.last_heal_backup = None

        try:
            import llm_client
            has_llm_keys = bool(llm_client.get_gemini_key() or llm_client.get_groq_key())
            ai_status_text = llm_client.status()
            trail_tooltip = llm_client.get_status_trail() if hasattr(llm_client, "get_status_trail") else ai_status_text
        except ImportError:
            has_llm_keys = False
            ai_status_text = "AI: offline"
            trail_tooltip = "AI: offline"

        toolbar_layout.addSpacing(15)
        self.cb_ai_assist = StyledCheckBox("AI assist")
        self.cb_ai_assist.setChecked(has_llm_keys)
        self.cb_ai_assist.setEnabled(has_llm_keys)
        self.cb_ai_assist.setToolTip("Sends your error messages and code to Gemini/Groq")
        self.cb_ai_assist.stateChanged.connect(lambda: self.update_ai_status())
        toolbar_layout.addWidget(self.cb_ai_assist)

        toolbar_layout.addSpacing(8)
        self.ai_status_label = QLabel(self._format_ai_status(ai_status_text))
        self.ai_status_label.setToolTip(trail_tooltip)
        self.ai_status_label.setMaximumWidth(280)
        self.ai_status_label.setStyleSheet(f"color: {PINK}; font-size: 10px; font-family: {FONT_FAMILY}; font-weight: bold;")
        toolbar_layout.addWidget(self.ai_status_label)

        self.cb_output_toggle = StyledCheckBox("Compile Output")
        self.cb_output_toggle.setChecked(True)
        self.cb_output_toggle.stateChanged.connect(self.toggle_output_pane)
        # Hidden to reduce visual noise
        # toolbar_layout.addWidget(self.cb_output_toggle)

        self.cb_dataset_toggle = StyledCheckBox("Dataset Collector")
        # Hidden to reduce visual noise
        # toolbar_layout.addWidget(self.cb_dataset_toggle)
        
        toolbar_layout.addSpacing(10)
        self.status_label = QLabel("STATUS: ● READY TO ANALYZE")
        self.status_label.setFont(QFont(FONT_FAMILY, 10, QFont.Weight.Bold))
        self.status_label.setStyleSheet(f"color: {PINK};")
        toolbar_layout.addWidget(self.status_label)
        
        toolbar_layout.addStretch()
        main_layout.addLayout(toolbar_layout)

        # Classifier — used by the auto-healer
        self.error_classifier = None
        if ErrorClassifier is not None:
            try:
                clf = ErrorClassifier()
                clf.load()   # load pre-trained model if available; trains lazily on first predict
                self.error_classifier = clf
            except Exception:
                self.error_classifier = None

        # Main horizontal layout for sidebar + content
        self.content_h_layout = QHBoxLayout()
        self.content_h_layout.setContentsMargins(0, 0, 0, 0)
        self.content_h_layout.setSpacing(0)
        main_layout.addLayout(self.content_h_layout, 1)

        self.sidebar = Sidebar()
        self.content_h_layout.addWidget(self.sidebar)

        self.stack = QStackedWidget()
        self.content_h_layout.addWidget(self.stack, 1)

        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.splitter.setStyleSheet(f"QSplitter::handle {{ background-color: {BG_COLOR}; }}")
        self.stack.addWidget(self.splitter) # Index 0

        self.ast_page = ASTPage()
        if hasattr(self.ast_page, "btn_reload"):
            self.ast_page.btn_reload.clicked.connect(self.switch_to_ast)
        self.stack.addWidget(self.ast_page) # Index 1

        self.energy_page = EnergyPage()
        self.stack.addWidget(self.energy_page) # Index 2

        self.call_graph_page = CallGraphPage()
        self.stack.addWidget(self.call_graph_page) # Index 3

        self.security_page = SecurityPage()
        self.stack.addWidget(self.security_page) # Index 4

        self.cfg_page = CFGPage()
        self.stack.addWidget(self.cfg_page) # Index 5

        # ── Feature 2: Second Opinion page (Index 6) ─────────────────────────
        if NEW_PAGES_AVAILABLE and SecondOpinionPage is not None:
            self.second_opinion_page = SecondOpinionPage()
        else:
            self.second_opinion_page = QWidget()  # blank fallback
        self.stack.addWidget(self.second_opinion_page)  # Index 6

        # ── Feature 4: Benchmark page (Index 7) ──────────────────────────────
        if NEW_PAGES_AVAILABLE and BenchmarkPage is not None:
            self.benchmark_page = BenchmarkPage()
        else:
            self.benchmark_page = QWidget()  # blank fallback
        self.stack.addWidget(self.benchmark_page)  # Index 7

        # Sidebar navigation connections
        self.sidebar.btn1.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        self.sidebar.btn2.clicked.connect(self.switch_to_ast)
        self.sidebar.btn3.clicked.connect(lambda: self.stack.setCurrentIndex(2))
        self.sidebar.btn4.clicked.connect(self.switch_to_call_graph)
        self.sidebar.btn5.clicked.connect(self.switch_to_security)
        self.sidebar.btn6.clicked.connect(self.switch_to_cfg)
        self.sidebar.btn7.clicked.connect(lambda: self.stack.setCurrentIndex(6))
        self.sidebar.btn8.clicked.connect(lambda: self.stack.setCurrentIndex(7))

        self._btn_second_opinion = self.sidebar.btn7
        self._btn_benchmark = self.sidebar.btn8

        self.stack.currentChanged.connect(self.sidebar.set_active)


        if not hasattr(self, "energy_timer"):
            self.energy_timer = QTimer(self)
            self.energy_timer.timeout.connect(self.update_energy_dashboard)
            self.energy_timer.start(600)

        self.pane_left = CustomFrame("<> " + self.file_name.upper())
        self.pane_left.content_layout.setContentsMargins(0, 0, 0, 0)
        
        self.editor = CodeEditor()
        self.highlighter = CppSyntaxHighlighter(self.editor.document())
        
        # Editor layout within pane_left
        self.pane_left.content_layout.addWidget(self.editor)
        self.splitter.addWidget(self.pane_left)
        
        self.editor.textChanged.connect(self.on_code_changed)

        self.v_splitter = QSplitter(Qt.Orientation.Vertical)
        self.v_splitter.setStyleSheet(f"QSplitter::handle {{ background-color: {BG_COLOR}; }}")
        self.splitter.addWidget(self.v_splitter)

        self.pane_right_top = CustomFrame("MESSAGE LOG :: FIX SUGGESTION", left_padding=True)
        self.error_cards_scroll = QScrollArea()
        self.error_cards_scroll.setWidgetResizable(True)
        self.error_cards_scroll.setStyleSheet(f"QScrollArea {{ border: none; background-color: transparent; }}")
        
        self.error_cards_widget = QWidget()
        self.error_cards_widget.setStyleSheet(f"QWidget {{ background-color: transparent; }}")
        self.error_cards_layout = QVBoxLayout(self.error_cards_widget)
        self.error_cards_layout.setContentsMargins(0, 0, 0, 0)
        self.error_cards_layout.setSpacing(8)
        self.error_cards_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        
        self.error_cards_scroll.setWidget(self.error_cards_widget)
        self.pane_right_top.content_layout.addWidget(self.error_cards_scroll)
        
        self.v_splitter.addWidget(self.pane_right_top)

        self.pane_right_bottom = CustomFrame("RUNNER CONSOLE :: I/O INTERFACE", left_padding=True)
        
        console_split_layout = QVBoxLayout()
        console_split_layout.setSpacing(0)
        
        self.runner_splitter = QSplitter(Qt.Orientation.Vertical)
        self.runner_splitter.setStyleSheet(f"QSplitter::handle {{ background-color: {BG_COLOR}; height: 4px; }}")

        # Input Screen
        input_container = QWidget()
        input_layout = QVBoxLayout(input_container)
        input_layout.setContentsMargins(0, 0, 0, 10)
        
        input_header_layout = QHBoxLayout()
        input_label = QLabel("INPUT SCREEN (stdin)")
        input_label.setFont(QFont(FONT_FAMILY, 8, QFont.Weight.Bold))
        input_label.setStyleSheet(f"color: {TEXT_DIM}; margin-bottom: 4px;")
        input_header_layout.addWidget(input_label)
        input_header_layout.addStretch()

        self.btn_send_input = StyledButton("SEND TO STDIN", "outline_dim")
        self.btn_send_input.setFixedHeight(24)
        self.btn_send_input.setFont(QFont(FONT_FAMILY, 8, QFont.Weight.Bold))
        self.btn_send_input.setToolTip("Send text to running program stdin")
        self.btn_send_input.clicked.connect(self.send_stdin_input)
        input_header_layout.addWidget(self.btn_send_input)

        input_layout.addLayout(input_header_layout)
        
        self.input_area = QTextEdit()
        self.input_area.setPlaceholderText("Paste your test cases here...")
        self.input_area.setFont(QFont(FONT_FAMILY, 11))
        self.input_area.setStyleSheet(f"""
            QTextEdit {{
                background-color: {BG_COLOR};
                border: 1px solid {BORDER_COLOR};
                color: {GREEN};
                border-radius: 4px;
            }}
        """)
        input_layout.addWidget(self.input_area)
        self.runner_splitter.addWidget(input_container)

        # Output Screen
        output_container = QWidget()
        output_layout = QVBoxLayout(output_container)
        output_layout.setContentsMargins(0, 10, 0, 0)

        output_label = QLabel("OUTPUT SCREEN (stdout/stderr)")
        output_label.setFont(QFont(FONT_FAMILY, 8, QFont.Weight.Bold))
        output_label.setStyleSheet(f"color: {TEXT_DIM}; margin-bottom: 4px;")
        output_layout.addWidget(output_label)

        self.terminal = TerminalDisplay()
        output_layout.addWidget(self.terminal)
        self.runner_splitter.addWidget(output_container)
        
        self.runner_splitter.setSizes([300, 500])
        console_split_layout.addWidget(self.runner_splitter)
        
        self.pane_right_bottom.content_layout.addLayout(console_split_layout)
        self.v_splitter.addWidget(self.pane_right_bottom)

        self.splitter.setSizes([700, 650])
        self.v_splitter.setSizes([500, 250])

        footer_layout = QHBoxLayout()
        gcc_ver = getattr(self, "gcc_version", "GCC 11.4")
        self.status_bar_left = QLabel(f"Compiler: {gcc_ver} | Language: C++17 | Errors: 1 | Warnings: 0 | File Name: file.cpp")
        self.status_bar_left.setFont(QFont(FONT_FAMILY, 10, QFont.Weight.Bold))
        self.status_bar_left.setStyleSheet(f"color: {TEXT_DIM};")
        footer_layout.addWidget(self.status_bar_left)
        
        footer_layout.addStretch()
        
        t2 = QLabel("● REC    ")
        t2.setFont(QFont(FONT_FAMILY, 10, QFont.Weight.Bold))
        t2.setStyleSheet(f"color: {TEXT_DIM};")
        footer_layout.addWidget(t2)
        main_layout.addLayout(footer_layout)

        self.syntax_timer = QTimer(self)
        self.syntax_timer.setSingleShot(True)
        self.syntax_timer.timeout.connect(self._run_syntax_check)

        init_code = """// Enter your C++ code here\n"""
        self.editor.setPlainText(init_code)
        self.editor.set_errors([])
        self._update_footer()

        self.loading_prefix = ""
        self.loading_timer = QTimer(self)
        self.loading_timer.timeout.connect(self._animate_loading)
        self.loading_dots = 0
        self.is_loading = False

        # Internet Status Check
        self.net_checker = QTimer(self)
        self.net_checker.timeout.connect(self.update_net_status)
        self.net_checker.start(5000) # Check every 5 seconds
        self.update_net_status() # Initial check

    def update_net_status(self):
        # Background check to avoid UI lag
        class CheckerThread(QThread):
            status = pyqtSignal(bool)
            def run(self):
                try:
                    socket.create_connection(("8.8.8.8", 53), timeout=2)
                    self.status.emit(True)
                except OSError:
                    self.status.emit(False)
        
        self.checker = CheckerThread()
        self.checker.status.connect(self._apply_net_status)
        self.checker.start()

    def _apply_net_status(self, available):
        pass

    # ── Auto-Heal ─────────────────────────────────────────────────────────────


    def _format_ai_status(self, text: str) -> str:
        if not text:
            return "AI: offline"
        if len(text) > 30:
            return text[:27] + "..."
        return text

    def toggle_dark_mode(self):
        self.is_dark_mode = not getattr(self, "is_dark_mode", False)
        if hasattr(self, "btn_theme_toggle"):
            self.btn_theme_toggle.setText("☀️ LIGHT MODE" if self.is_dark_mode else "🌙 DARK MODE")
        self.apply_theme(self.is_dark_mode)

    def apply_theme(self, is_dark: bool):
        theme = DARK_THEME if is_dark else LIGHT_THEME
        set_global_theme(theme)
        
        # Main window & splitters
        self.setStyleSheet(f"QMainWindow {{ background-color: {theme['BG_COLOR']}; }}")
        if hasattr(self, "splitter"):
            self.splitter.setStyleSheet(f"QSplitter::handle {{ background-color: {theme['BG_COLOR']}; }}")
        if hasattr(self, "v_splitter"):
            self.v_splitter.setStyleSheet(f"QSplitter::handle {{ background-color: {theme['BG_COLOR']}; }}")
        if hasattr(self, "runner_splitter"):
            self.runner_splitter.setStyleSheet(f"QSplitter::handle {{ background-color: {theme['BG_COLOR']}; height: 4px; }}")

        # Labels
        if hasattr(self, "status_label"):
            self.status_label.setStyleSheet(f"color: {theme['PINK']};")
        if hasattr(self, "ai_status_label"):
            self.ai_status_label.setStyleSheet(f"color: {theme['PINK']}; font-size: 10px; font-family: {FONT_FAMILY}; font-weight: bold;")
        if hasattr(self, "status_bar_left"):
            self.status_bar_left.setStyleSheet(f"color: {theme['TEXT_DIM']};")

        # Editor
        if hasattr(self, "editor"):
            self.editor.setStyleSheet(f"QPlainTextEdit {{ background-color: {theme['CODE_BG']}; color: {theme['TEXT_MAIN']}; border: none; }}")
            self.editor.line_number_area.update()
        if hasattr(self, "highlighter"):
            self.highlighter.apply_theme(theme)

        # Terminal & Input
        if hasattr(self, "terminal"):
            self.terminal.setStyleSheet(f"QTextEdit {{ background-color: {theme['TERMINAL_BG']}; border: 1px solid {theme['BORDER_COLOR']}; border-radius: 4px; color: {theme['TEXT_MAIN']}; line-height: 1.5; }}")
        if hasattr(self, "input_area"):
            self.input_area.setStyleSheet(f"QTextEdit {{ background-color: {theme['BG_COLOR']}; border: 1px solid {theme['BORDER_COLOR']}; color: {theme['GREEN']}; border-radius: 4px; }}")

        # Sidebar
        if hasattr(self, "sidebar"):
            self.sidebar.apply_theme(theme)

        # Frames
        if hasattr(self, "pane_left"):
            self.pane_left.apply_theme(theme)
        if hasattr(self, "pane_right_top"):
            self.pane_right_top.apply_theme(theme)
        if hasattr(self, "pane_right_bottom"):
            self.pane_right_bottom.apply_theme(theme)

        # Pages
        if hasattr(self, "ast_page") and hasattr(self.ast_page, "apply_theme"):
            self.ast_page.apply_theme(theme)
        if hasattr(self, "energy_page") and hasattr(self.energy_page, "apply_theme"):
            self.energy_page.apply_theme(theme)
        if hasattr(self, "call_graph_page") and hasattr(self.call_graph_page, "apply_theme"):
            self.call_graph_page.apply_theme(theme)
        if hasattr(self, "security_page") and hasattr(self.security_page, "apply_theme"):
            self.security_page.apply_theme(theme)
        if hasattr(self, "cfg_page") and hasattr(self.cfg_page, "apply_theme"):
            self.cfg_page.apply_theme(theme)
        if hasattr(self, "second_opinion_page") and hasattr(self.second_opinion_page, "apply_theme"):
            self.second_opinion_page.apply_theme(theme)
        if hasattr(self, "benchmark_page") and hasattr(self.benchmark_page, "apply_theme"):
            self.benchmark_page.apply_theme(theme)

        # Buttons
        for btn in [getattr(self, "btn_heal", None), getattr(self, "btn_undo_heal", None), getattr(self, "btn_theme_toggle", None), getattr(self, "btn_send_input", None)]:
            if btn and hasattr(btn, "_update_style"):
                btn._update_style(0)

    def switch_to_ast(self):
        code = self.editor.toPlainText() if hasattr(self, "editor") else ""
        self.status_label.setText("STATUS: ● LOADING AST... 🕒")
        self.ast_worker = ASTWorker(self.file_path, code=code)
        self.ast_worker.finished.connect(self._on_ast_ready)
        self.ast_worker.start()
        
        self.stack.setCurrentIndex(1)

    def _on_ast_ready(self, ast_tree):
        self.ast_page.update_tree(ast_tree)
        self.status_label.setText("STATUS: ● AST EXPLORER ACTIVE")

    def switch_to_call_graph(self):
        if hasattr(self, "call_graph_page"):
            self.call_graph_page.update_from_code(self.editor.toPlainText())
        self.stack.setCurrentIndex(3)

    def switch_to_security(self):
        findings = self.latest_security_findings
        if not findings and self.file_path and os.path.exists(self.file_path):
            try:
                findings = analyze_security(self.file_path, [])
            except Exception:
                findings = []
        self.security_page.update_report(findings)
        self.stack.setCurrentIndex(4)

    def switch_to_cfg(self):
        if hasattr(self, "cfg_page"):
            self.cfg_page.update_from_code(self.editor.toPlainText())
        self.stack.setCurrentIndex(5)

    def update_ai_status(self):
        try:
            import llm_client
            has_keys = bool(llm_client.get_gemini_key() or llm_client.get_groq_key())
            self.cb_ai_assist.setEnabled(has_keys)
            raw = llm_client.status()
            self.ai_status_label.setText(self._format_ai_status(raw))
            self.ai_status_label.setToolTip(raw)
        except Exception:
            pass

    def is_ai_enabled(self) -> bool:
        if not hasattr(self, 'cb_ai_assist'):
            return False
        try:
            import llm_client
            has_keys = bool(llm_client.get_gemini_key() or llm_client.get_groq_key())
            return has_keys and self.cb_ai_assist.isChecked()
        except Exception:
            return False


    def start_heal(self):
        """Launch the auto-heal loop in a background thread."""
        if not HEALER_AVAILABLE:
            QMessageBox.warning(self, "Auto-Heal", "heal_loop.py not found.")
            return
        if getattr(self, "heal_worker", None) is not None and self.heal_worker.isRunning():
            QMessageBox.warning(self, "Auto-Heal", "Auto-heal is already in progress.")
            return
        if not self.save_file():
            return

        # If the ML classifier isn't loaded, use a lightweight keyword-based stub
        classifier = self.error_classifier
        if classifier is None:
            classifier = _KeywordClassifier()

        # Clear the cards pane and show initial errors with offline explanation
        current_errors = list(getattr(self.editor, "errors", []))

        for i in reversed(range(self.error_cards_layout.count())):
            w = self.error_cards_layout.itemAt(i).widget()
            if w:
                w.setParent(None)
        
        self.editor.clear_fixed_lines()

        self.heal_header = QLabel("⚕ AUTO-HEAL IN PROGRESS…")
        self.heal_header.setStyleSheet(f"color: {YELLOW}; font-size: 13px; font-family: {FONT_FAMILY}; font-weight: bold;")
        self.error_cards_layout.addWidget(self.heal_header)

        if current_errors:
            lbl_init = QLabel("INITIAL COMPILER ERRORS (before healing):")
            lbl_init.setStyleSheet(f"color: {PINK}; font-size: 11px; font-weight: bold; font-family: {FONT_FAMILY}; margin-top: 4px;")
            self.error_cards_layout.addWidget(lbl_init)
            for err in current_errors:
                self.error_cards_layout.addWidget(self._create_error_card(err))

        self.btn_heal.setEnabled(False)
        self.status_label.setText("STATUS: ● HEALING…")

        enable_ai = self.is_ai_enabled()
        self.heal_worker = HealWorker(self.file_path, classifier, enable_ai=enable_ai)
        self.heal_worker.finished.connect(lambda: self.btn_heal.setEnabled(True))
        self.heal_worker.attempt_started.connect(self._on_heal_attempt)
        self.heal_worker.diff_ready.connect(self._on_heal_diff)
        self.heal_worker.compile_clean.connect(self._on_heal_success)
        self.heal_worker.heal_summary.connect(self._on_heal_summary)
        self.heal_worker.give_up.connect(self._on_heal_give_up)
        self.heal_worker.error_signal.connect(self._on_heal_error)
        self.heal_worker.lines_fixed.connect(self.editor.set_fixed_lines)
        self.heal_worker.backup_created.connect(self._on_heal_backup_created)
        self.heal_worker.telemetry_ready.connect(self._on_telemetry_ready)
        self.heal_worker.status_update.connect(self.status_label.setText)
        self.heal_worker.info_message.connect(self._on_heal_info)
        self.heal_worker.start()

    def _on_heal_backup_created(self, backup_path: str):
        self.last_heal_backup = backup_path
        self.btn_undo_heal.setEnabled(True)

    def _on_heal_info(self, msg: str):
        lbl = QLabel(f"ℹ️ {msg}")
        lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px; font-family: {FONT_FAMILY};")
        lbl.setWordWrap(True)
        self.error_cards_layout.addWidget(lbl)

    def undo_heal(self):
        """Restore file from the latest heal backup."""
        if not self.last_heal_backup or not os.path.exists(self.last_heal_backup):
            QMessageBox.information(self, "Undo Heal", "No backup available to restore.")
            return
        try:
            with open(self.last_heal_backup, "r", encoding="utf-8") as f:
                content = f.read()
            with open(self.file_path, "w", encoding="utf-8") as f:
                content = f.write(content)
            self.editor.blockSignals(True)
            self.editor.setPlainText(content)
            self.editor.blockSignals(False)
            self.editor.clear_fixed_lines()
            self.btn_undo_heal.setEnabled(False)
            self.status_label.setText("STATUS: ● RESTORED")
            lbl = QLabel(f"↺ Restored original code from {os.path.basename(self.last_heal_backup)}")
            lbl.setStyleSheet(f"color: {YELLOW}; font-size: 11px; font-family: {FONT_FAMILY};")
            self.error_cards_layout.addWidget(lbl)
        except Exception as e:
            QMessageBox.critical(self, "Undo Heal Error", f"Failed to restore backup: {e}")

    def _on_telemetry_ready(self, telemetry: list):
        for entry in telemetry:
            self.cumulative_compilation_co2 += entry.get("emissions", 0.0)

    def _on_heal_attempt(self, attempt_no: int, error: dict):
        msg = error.get("message", "?")
        cat = error.get("category", "?")
        lbl = QLabel(f"<b>Attempt {attempt_no}/10</b> — [{cat.upper()}] {msg}")
        lbl.setStyleSheet(f"color: {YELLOW}; font-size: 11px; font-family: {FONT_FAMILY};")
        lbl.setWordWrap(True)
        self.error_cards_layout.addWidget(lbl)

    def _on_heal_diff(self, attempt_no: int, diff_html: str, label: str = ""):
        title_text = f"<b>Diff — {label}</b>" if label else f"<b>Diff — Attempt {attempt_no}</b>"
        title = QLabel(title_text)
        title.setStyleSheet(f"color: {TEXT_DIM}; font-size: 10px; font-family: {FONT_FAMILY};")
        self.error_cards_layout.addWidget(title)

        diff_box = QTextBrowser()
        diff_box.setOpenLinks(False)
        diff_box.setHtml(diff_html)
        diff_box.setStyleSheet(f"""
            QTextBrowser {{
                background-color: {BG_COLOR};
                border: 1px solid {BORDER_COLOR};
                border-radius: 4px;
                padding: 4px;
                font-family: {FONT_FAMILY};
            }}
        """)
        diff_box.setMaximumHeight(160)
        diff_box.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self.error_cards_layout.addWidget(diff_box)

        # Reload the editor with the patched file
        try:
            self.editor.blockSignals(True)
            with open(self.file_path, "r", encoding="utf-8") as f:
                self.editor.setPlainText(f.read())
            self.editor.blockSignals(False)
        except Exception:
            self.editor.blockSignals(False)
            pass

    def _on_heal_summary(self, summary: dict):
        clean = summary.get("clean", False)
        rounds = summary.get("rounds", [])
        total_sec = summary.get("total_duration", 0.0)
        status_msg = summary.get("message", "Compiles OK")

        # Replace heal progress header
        if hasattr(self, "heal_header") and self.heal_header:
            if clean:
                self.heal_header.setText("✅ AUTO-HEAL: COMPILES OK")
                self.heal_header.setStyleSheet(f"color: {GREEN}; font-size: 14px; font-family: {FONT_FAMILY}; font-weight: bold;")
            else:
                self.heal_header.setText(f"⚠️ AUTO-HEAL: {summary.get('status', 'finished').upper()}")
                self.heal_header.setStyleSheet(f"color: {YELLOW}; font-size: 14px; font-family: {FONT_FAMILY}; font-weight: bold;")

        # Summary Card
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background-color: {PANEL_BG};
                border: 1px solid {GREEN if clean else YELLOW};
                border-radius: 6px;
                padding: 10px;
                margin-top: 6px;
            }}
        """)
        c_layout = QVBoxLayout(card)

        hdr_text = f"<b>HEAL SUMMARY:</b> {len(rounds)} round(s) in {total_sec:.2f}s — {'Compiles OK' if clean else status_msg}"
        lbl_h = QLabel(hdr_text)
        lbl_h.setStyleSheet(f"color: {GREEN if clean else YELLOW}; font-size: 12px; font-family: {FONT_FAMILY};")
        c_layout.addWidget(lbl_h)

        # Method per round breakdown
        for r in rounds:
            r_no = r.get("round_no", 1)
            r_method = r.get("method", "offline rules")
            r_sec = r.get("seconds", 0.0)
            r_lbl = QLabel(f"• Round {r_no}: {r_method} ({r_sec:.2f}s)")
            r_lbl.setStyleSheet(f"color: {TEXT_MAIN}; font-size: 11px; font-family: {FONT_FAMILY};")
            c_layout.addWidget(r_lbl)

        # Diff of changed lines if available
        last_diff = None
        for r in reversed(rounds):
            if r.get("diff_html"):
                last_diff = r.get("diff_html")
                break
        if last_diff:
            diff_lbl = QLabel("<b>Changed Lines:</b>")
            diff_lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 10px; font-family: {FONT_FAMILY}; margin-top: 4px;")
            c_layout.addWidget(diff_lbl)
            diff_box = QTextBrowser()
            diff_box.setOpenLinks(False)
            diff_box.setHtml(last_diff)
            diff_box.setStyleSheet(f"""
                QTextBrowser {{
                    background-color: {BG_COLOR};
                    border: 1px solid {BORDER_COLOR};
                    border-radius: 4px;
                    padding: 4px;
                    font-family: {FONT_FAMILY};
                }}
            """)
            diff_box.setMaximumHeight(140)
            c_layout.addWidget(diff_box)

        # Silent re-analysis for footer agreement and remaining security check
        self._silent_reanalysis_after_heal(summary, c_layout)

        self.error_cards_layout.addWidget(card)

    def _silent_reanalysis_after_heal(self, summary: dict, card_layout=None):
        """Silently re-analyzes code to ensure footer, error counts, and security findings agree."""
        try:
            # 1. Reload file in editor
            with open(self.file_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.editor.blockSignals(True)
            self.editor.setPlainText(content)
            self.editor.blockSignals(False)

            # 2. Check compiler status silently
            from heal_engine import compile_source
            errors, warnings, _ = compile_source(content, syntax_only=False)
            self.errors_count = len(errors)
            self.warnings_count = len(warnings)
            self.editor.set_errors(errors)
            self._update_footer()

            # 3. Check security findings
            from security_analyzer import analyze as analyze_security, format_security_report
            findings = analyze_security(self.file_path, errors)
            self.latest_security_findings = findings
            self.latest_security_report = format_security_report(findings)
            self.security_page.update_report(findings)

            if findings and card_layout:
                sec_lbl = QLabel(f"⚠️ <b>Security Notice:</b> {len(findings)} security finding(s) detected in healed code (see Security tab)")
                sec_lbl.setStyleSheet(f"color: {YELLOW}; font-size: 11px; font-family: {FONT_FAMILY}; margin-top: 4px;")
                sec_lbl.setWordWrap(True)
                card_layout.addWidget(sec_lbl)
            elif warnings and card_layout:
                warn_lbl = QLabel(f"ℹ️ Code compiles with {len(warnings)} warning(s).")
                warn_lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px; font-family: {FONT_FAMILY};")
                card_layout.addWidget(warn_lbl)
        except Exception:
            pass

    def _on_heal_success(self, method: str = "Healed by offline rules"):
        self.btn_heal.setEnabled(True)
        self.status_label.setText("STATUS: ● HEALED ✅")
        lbl = QLabel(f"✅ {method} — Compiles OK - please review the changes.")
        lbl.setStyleSheet(f"color: {GREEN}; font-size: 13px; font-weight: bold; font-family: {FONT_FAMILY};")
        self.error_cards_layout.addWidget(lbl)

        # Note: We no longer auto-trigger self.analyze() here to allow the user 
        # to review the heal history before manually recompiling.
        # self.analyze()

    def _on_heal_error(self, msg: str):
        self.btn_heal.setEnabled(True)
        self.status_label.setText("STATUS: ● HEAL ERROR")
        lbl = QLabel(f"⚠️ Internal error: {msg}")
        lbl.setStyleSheet(f"color: {RED}; font-size: 11px; font-family: {FONT_FAMILY};")
        lbl.setWordWrap(True)
        self.error_cards_layout.addWidget(lbl)

    def _on_heal_give_up(self, history: list):
        self.btn_heal.setEnabled(True)
        self.status_label.setText("STATUS: ● HEAL FAILED")
        dlg = UserGuidanceDialog(history, self)
        result = dlg.exec()
        if result == UserGuidanceDialog.EDIT_MANUALLY:
            # Focus editor on the last error line
            last_err = next((h.get("error") for h in reversed(history) if h.get("error")), None)
            if last_err and last_err.get("line"):
                cursor = self.editor.textCursor()
                block = self.editor.document().findBlockByLineNumber(int(last_err["line"]) - 1)
                cursor.setPosition(block.position())
                self.editor.setTextCursor(cursor)
        elif result == UserGuidanceDialog.GIVE_HINT:
            hint = dlg.hint_text()
            if hint:
                if not self.is_ai_enabled():
                    QMessageBox.information(self, "AI Assist Required", "hints need AI assist")
                    return
                classifier = self.error_classifier
                if classifier is None:
                    classifier = _KeywordClassifier()
                self.heal_worker = HealWorker(self.file_path, classifier, hint=hint, enable_ai=self.is_ai_enabled())
                self.heal_worker.finished.connect(lambda: self.btn_heal.setEnabled(True))
                self.heal_worker.attempt_started.connect(self._on_heal_attempt)
                self.heal_worker.diff_ready.connect(self._on_heal_diff)
                self.heal_worker.compile_clean.connect(self._on_heal_success)
                self.heal_worker.give_up.connect(self._on_heal_give_up)
                self.heal_worker.error_signal.connect(self._on_heal_error)
                self.heal_worker.lines_fixed.connect(self.editor.set_fixed_lines)
                self.heal_worker.backup_created.connect(self._on_heal_backup_created)
                self.heal_worker.telemetry_ready.connect(self._on_telemetry_ready)
                self.heal_worker.status_update.connect(self.status_label.setText)
                self.heal_worker.info_message.connect(self._on_heal_info)
                self.btn_heal.setEnabled(False)
                self.heal_worker.start()

        # SKIP THIS ERROR — do nothing (fall through)

    def _record_execution(self):
        self.execution_count += 1
        if hasattr(self, 'sparkline'):
            self.sparkline.trigger_spike()
        if self.execution_count % 5 == 0:
            self.manual_co2_offset += 0.000005

    def _create_error_card(self, error):
        # Extract needed fields with safe defaults
        cpu = "2.5" # Now in mWh
        mem = "12 MB"
        hotspot = error.get('hotspot', f"Line {error.get('line', '?')}")
        co2 = f"{(self.manual_co2_offset * 1e6):.2f}"
        risk = error.get('security_risk', 'LOW')
        severity = error.get('severity', 'HIGH')
        etype = error.get('error_type', 'error').upper()
        msg = error.get('message', 'Unknown Issue')
        expl = error.get('explanation', '')
        sugg = error.get('suggestion', '')
        
        # Color mapping
        severity_color = {
            'HIGH': RED,
            'MEDIUM': YELLOW,
            'LOW': GREEN,
        }.get(severity.upper(), RED)
        
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background-color: {PANE_BG};
                border: 1px solid {severity_color};
                border-radius: 4px;
                padding: 4px;
                margin-bottom: 4px;
            }}
        """)
        layout = QVBoxLayout(card)
        layout.setSpacing(3)
        layout.setContentsMargins(4, 4, 4, 4)
        
        # Header (Type + Message)
        header_lbl = QLabel(f"<b>[{etype}]</b> {msg}")
        header_lbl.setStyleSheet(f"color: {severity_color}; font-size: 11px; font-family: {FONT_FAMILY};")
        header_lbl.setWordWrap(True)
        layout.addWidget(header_lbl)
        
        # Stats row (Horizontal)
        stats_widget = QWidget()
        stats_widget.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Maximum)
        stats_layout = QHBoxLayout(stats_widget)
        stats_layout.setContentsMargins(0, 0, 0, 0)
        stats_layout.setSpacing(4)
        
        def create_stat(emoji, text, color):
            lbl = QLabel(f"<b>{emoji} {text}</b>")
            lbl.setStyleSheet(f"color: {color}; font-size: 9px; font-family: {FONT_FAMILY}; padding: 1px 4px; border: 1px solid {BORDER_COLOR}; border-radius: 3px; background-color: {BG_COLOR};")
            return lbl

        stats_layout.addWidget(create_stat('⚡', f"{cpu} mWh", PINK))
        stats_layout.addWidget(create_stat('🧠', f"{mem}", PINK))
        stats_layout.addWidget(create_stat('🔥', f"{hotspot}", YELLOW))
        stats_layout.addWidget(create_stat('🌍', f"{co2} mg", GREEN))
        stats_layout.addWidget(create_stat('🛡️', f"{risk.upper()}", RED if risk.upper() == 'HIGH' else YELLOW))
        stats_layout.addStretch()
        layout.addWidget(stats_widget)
        
        # Details text
        if expl:
            expl_lbl = QLabel(expl)
            expl_lbl.setStyleSheet(f"color: {TEXT_MAIN}; font-size: 10px; font-family: {FONT_FAMILY};")
            expl_lbl.setWordWrap(True)
            layout.addWidget(expl_lbl)
        if sugg:
            sugg_lbl = QLabel(f"<b>SUGGESTION:</b> {sugg}")
            sugg_lbl.setStyleSheet(f"color: {GREEN}; font-size: 10px; font-family: {FONT_FAMILY};")
            sugg_lbl.setWordWrap(True)
            layout.addWidget(sugg_lbl)

        # AI Explanation section
        def add_ai_explanation(ai_data: dict):
            provider_name = (ai_data.get('provider') or 'AI').capitalize()
            ai_box = QFrame()
            ai_box.setStyleSheet(f"background-color: {BG_COLOR}; border: 1px solid {BORDER_COLOR}; border-radius: 4px; padding: 4px; margin-top: 4px;")
            ai_layout = QVBoxLayout(ai_box)
            ai_layout.setContentsMargins(4, 4, 4, 4)
            ai_layout.setSpacing(2)

            ai_title = QLabel(f"<b>AI explanation ({provider_name})</b>")
            ai_title.setStyleSheet(f"color: {PINK}; font-size: 10px; font-family: {FONT_FAMILY}; font-weight: bold;")
            ai_layout.addWidget(ai_title)

            if ai_data.get("explanation"):
                ai_expl_lbl = QLabel(ai_data["explanation"])
                ai_expl_lbl.setStyleSheet(f"color: {TEXT_MAIN}; font-size: 10px; font-family: {FONT_FAMILY};")
                ai_expl_lbl.setWordWrap(True)
                ai_layout.addWidget(ai_expl_lbl)

            if ai_data.get("fix"):
                ai_fix_lbl = QLabel(f"<b>Suggested Fix:</b> <code>{html.escape(ai_data['fix'])}</code>")
                ai_fix_lbl.setStyleSheet(f"color: {GREEN}; font-size: 10px; font-family: {FONT_FAMILY};")
                ai_fix_lbl.setWordWrap(True)
                ai_layout.addWidget(ai_fix_lbl)

            if ai_data.get("why"):
                ai_why_lbl = QLabel(f"<b>Why:</b> {ai_data['why']}")
                ai_why_lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 9px; font-family: {FONT_FAMILY};")
                ai_why_lbl.setWordWrap(True)
                ai_layout.addWidget(ai_why_lbl)

            layout.addWidget(ai_box)

        card.add_ai_explanation = add_ai_explanation
        ai = error.get('ai_explanation')
        if ai and isinstance(ai, dict):
            add_ai_explanation(ai)

        # Pulse animation (opacity)
        effect = QGraphicsOpacityEffect(card)
        card.setGraphicsEffect(effect)
        anim = QPropertyAnimation(effect, b"opacity")
        anim.setDuration(1500)
        anim.setStartValue(0.7)
        anim.setEndValue(1.0)
        anim.setLoopCount(-1)
        anim.start()
        
        return card


    def _get_hotspots(self):
        """Simple static analysis to find potential energy hotspots (loops/recursion)"""
        code = self.editor.toPlainText()
        hotspot = "NONE"
        lines = code.split('\n')
        
        # Heuristic: Find nested loops or many loops
        for i, line in enumerate(lines):
            if any(k in line for k in ["for", "while"]):
                hotspot = f"LINE {i+1}"
                if 'for' in line and 'for' in code.split('\n')[i+1:i+3]: # very simple nesting check
                    hotspot = f"NESTED @ L{i+1}"
                    break
        return hotspot

    def update_energy_dashboard(self):
        try:
            elapsed = max(0.0, time.monotonic() - getattr(self, "energy_started_at", time.monotonic()))
            tracker = getattr(self, "tracker", None)
            codecarbon_active = CODECARBON_AVAILABLE and tracker is not None

            cpu_kwh = (getattr(tracker, "_cpu_energy", 0) or 0) if codecarbon_active else 0
            ram_kwh = (getattr(tracker, "_ram_energy", 0) or 0) if codecarbon_active else 0
            total_energy_kwh = (getattr(tracker, "_total_energy", 0) or 0) if codecarbon_active else 0
            emissions_kg = (getattr(tracker, "_emissions", 0) or 0) if codecarbon_active else 0

            total_mwh = total_energy_kwh * 1e6
            cpu_mwh = cpu_kwh * 1e6
            ram_mwh = ram_kwh * 1e6
            emissions_mg = (emissions_kg + self.manual_co2_offset) * 1e6
            power_w = (total_energy_kwh * 1000 * 3600 / elapsed) if elapsed > 0 else 0
            carbon_g_per_kwh = (emissions_kg * 1000 / total_energy_kwh) if total_energy_kwh > 0 else 0

            # If CodeCarbon hasn't produced a usable sample yet (or is unavailable),
            # show a smooth dummy signal so the UI isn't blank.
            has_sample = (
                codecarbon_active
                and elapsed > 2.0
                and total_energy_kwh > 1e-8
                and (cpu_kwh > 0 or ram_kwh > 0 or emissions_kg > 0)
            )
            if not has_sample:
                t = time.monotonic()
                base_mw = 900.0
                wave = 120.0 * math.sin(t / 2.5) + 45.0 * math.sin(t / 0.9)
                jitter = random.uniform(-18.0, 18.0)
                power_mw = max(50.0, base_mw + wave + jitter)
                carbon_mg_per_wh = max(0.05, 0.42 + 0.04 * math.sin(t / 4.0))
                note = "Placeholder telemetry (CodeCarbon has not produced a sample yet)."
            else:
                power_mw = max(0.0, power_w * 1000.0)
                carbon_mg_per_wh = max(0.0, carbon_g_per_kwh / 1000.0)
                note = "CodeCarbon live tracker is active."

            rapl_now = _read_rapl_energy_joules()
            rapl_start = getattr(self, "rapl_start_j", None)
            if rapl_now is not None and rapl_start is not None:
                rapl_delta = max(0.0, rapl_now - rapl_start)
                rapl_text = f"{rapl_delta:.3f} J"
            else:
                rapl_text = "Unavailable"

            hotspot = self._get_hotspots() if hasattr(self, "editor") else "CALIBRATING"
            if not codecarbon_active:
                note = "CodeCarbon is not installed or failed to start."
            
            cumulative_co2_mg = self.cumulative_compilation_co2 * 1e6
            
            if hasattr(self, "energy_panel"):
                # Panel removed to focus on graph
                pass
            if hasattr(self, 'energy_page'):
                self.energy_page.update_metrics(power_mw, carbon_mg_per_wh, elapsed, rapl_text, note)

        except Exception as e:
            # print(f"Dashboard Error: {e}")
            pass

    def _update_footer(self):
        gcc_ver = getattr(self, "gcc_version", "GCC 11.4")
        text = f"Compiler: {gcc_ver} | Language: C++17 | Errors: {self.errors_count} | Warnings: {self.warnings_count} | File Name: {self.file_name}"
        self.status_bar_left.setText(text)

    def _animate_loading(self):
        frames = ["🍓      ", " 🍓     ", "  🍓    ", "   🍓   ", "    🍓  ", "     🍓 ", "      🍓", "     🍓 ", "    🍓  ", "   🍓   ", "  🍓    ", " 🍓     "]
        self.loading_dots = (self.loading_dots + 1) % len(frames)
        frame = frames[self.loading_dots]
        
        self.status_label.setText(f"{self.loading_prefix} {frame}")

    def toggle_output_pane(self, state):
        should_show = (state == Qt.CheckState.Checked.value)
        self.pane_right_bottom.setVisible(should_show)

    def _find_executable(self) -> Optional[str]:
        names = ["a.exe", "a.out"] if (os.name == "nt" or sys.platform == "win32") else ["a.out", "a.exe"]
        for name in names:
            for candidate in [name, os.path.join(".", name), os.path.join(os.getcwd(), name)]:
                if os.path.exists(candidate) and os.path.isfile(candidate):
                    return os.path.abspath(candidate)
        return None

    def send_stdin_input(self):
        text = self.input_area.toPlainText()
        if hasattr(self, 'process') and self.process.state() == QProcess.ProcessState.Running:
            if text:
                if not text.endswith('\n'):
                    text += '\n'
                self.process.write(text.encode('utf-8'))
                self.terminal.append_output(f"<span style='color:{TEXT_DIM}'><i>[sent to stdin]: {text.strip()}</i></span><br>", is_html=True)
        else:
            self.run_code()

    def run_code(self):
        self.terminal.clear()
        self.editor.clear_fixed_lines()
        self._record_execution()

        # Find or compile executable
        target_exe = self._find_executable()
        needs_compile = False
        if not target_exe:
            needs_compile = True
        elif os.path.exists(self.file_path):
            try:
                if os.path.getmtime(self.file_path) > os.path.getmtime(target_exe):
                    needs_compile = True
            except OSError:
                pass

        if needs_compile:
            if not self.save_file():
                self.terminal.append_output(f"<div style='color:{PINK};'>ERROR: Could not save file before compiling.</div>", is_html=True)
                return
            exe_target = "a.exe" if (os.name == "nt" or sys.platform == "win32") else "a.out"
            res = subprocess.run(["g++", "-std=c++17", self.file_path, "-o", exe_target], capture_output=True, text=True)
            if res.returncode != 0:
                self.terminal.append_output(f"<div style='color:{PINK}; white-space:pre-wrap;'><b>Compilation failed:</b>\n{res.stderr}</div>", is_html=True)
                self.status_label.setText("STATUS: ● COMPILE FAILED")
                return
            target_exe = os.path.abspath(exe_target)

        if not target_exe or not os.path.exists(target_exe):
            exe_name = "a.exe" if (os.name == "nt" or sys.platform == "win32") else "a.out"
            self.terminal.append_output(f"<span style='color:{PINK}'>File '{exe_name}' not found. Please compile first.</span>", is_html=True)
            return

        self.is_loading = True
        self.loading_prefix = "STATUS: ● EXECUTING BINARY "
        self.loading_timer.start(300)

        self.terminal.setReadOnly(False)
        self.terminal.setFocus()

        if hasattr(self, 'process') and self.process.state() == QProcess.ProcessState.Running:
            self.process.kill()
            self.process.waitForFinished(1000)

        self.process = QProcess(self)
        self.terminal.process = self.process # Link process to terminal for input
        self.process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self.process.readyReadStandardOutput.connect(self._read_process_output)
        self.process.finished.connect(self._on_process_finished)
        self.process.errorOccurred.connect(self._on_process_error)
        
        # Start the process
        self.process.start(target_exe)
        
        # Wait for started and feed input from input_area if available
        if self.process.waitForStarted(1500):
            input_text = self.input_area.toPlainText()
            if input_text:
                if not input_text.endswith('\n'):
                    input_text += '\n'
                self.process.write(input_text.encode('utf-8'))
        else:
            self.loading_timer.stop()
            self.is_loading = False
            self.status_label.setText("STATUS: ● PROCESS START FAILED")
            self.terminal.append_output(f"<span style='color:{PINK}'>Failed to start '{os.path.basename(target_exe)}'.</span>", is_html=True)

    def _read_process_output(self):
        raw = self.process.readAllStandardOutput().data()
        data = raw.decode('utf-8', errors='replace')
        if data:
            self.terminal.append_output(data)

    def _on_process_finished(self, exit_code, exit_status):
        self.loading_timer.stop()
        self.is_loading = False
        
        status_msg = f"STATUS: ● PROGRAM FINISHED (EXIT: {exit_code})"
        if exit_status == QProcess.ExitStatus.CrashExit:
            status_msg = f"STATUS: ● PROGRAM CRASHED (EXIT: {exit_code})"
            
        self.status_label.setText(status_msg)
        self.terminal.setReadOnly(True)
        if not self.terminal.toPlainText().strip():
            self.terminal.append_output(f"<span style='color:{TEXT_DIM}'><i>(Program finished with exit code {exit_code} - no output)</i></span>", is_html=True)

    def _on_process_error(self, error):
        self.loading_timer.stop()
        self.is_loading = False
        self.status_label.setText("STATUS: ● PROCESS ERROR")

    def view_ast(self):
        # Save first
        if not self.save_file():
            return
        self.status_label.setText("STATUS: ● EXTRACTING AST...")
        self.loading_prefix = "STATUS: ● PARSING AST "
        self.loading_timer.start(300)
        
        ast_text = extract_ast(self.file_path)
        self.loading_timer.stop()
        
        if not ast_text:
            lbl = QLabel("Failed to extract AST. Make sure clang++ is installed and code is syntactically valid.")
            lbl.setStyleSheet(f"color: {PINK}; font-family: {FONT_FAMILY};")
            lbl.setWordWrap(True)
            self.error_cards_layout.addWidget(lbl)
            self.status_label.setText("STATUS: ● AST FAILED")
            return
            
        self.status_label.setText("STATUS: ● READY")
        tree_data = parse_ast_to_tree(ast_text, self.file_path)
        
        dialog = ASTViewerDialog(tree_data, self)
        dialog.exec()

    def load_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Open C++ Source File", "", "C/C++ Files (*.cpp *.cc *.c *.h *.hpp);;All Files (*)")
        if filename:
            self.file_path = filename
            self.file_name = os.path.basename(filename)
            self.pane_left.set_title(f"<> {self.file_name.upper()}")
            self._update_footer()
            self.latest_security_findings = []
            self.latest_security_report = ""
            
            try:
                self.editor.blockSignals(True)
                with open(filename, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.editor.setPlainText(content)
                self.editor.set_errors([]) 
                self.editor.blockSignals(False)
            except Exception:
                self.editor.blockSignals(False)
                pass 

    def save_file(self):
        if not self.file_path:
            self.file_path = os.path.join(os.getcwd(), self.file_name)
        try:
            content = self.editor.toPlainText()
            with open(self.file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        except Exception:
            return False

    def analyze(self):
        if self.is_loading:
            return

        if not self.save_file():
            self.terminal.append_output(f"<div style='color:{PINK};'>ERROR: Could not save file before compiling.</div>", is_html=True)
            return
        self.terminal.clear()
        self.editor.clear_fixed_lines()
        self._record_execution()
        
        # Reset error cards container for fresh run
        for i in reversed(range(self.error_cards_layout.count())):
            widget = self.error_cards_layout.itemAt(i).widget()
            if widget:
                widget.setParent(None)
        
        self.is_loading = True
        self.loading_prefix = "STATUS: ● ANALYZING "
        self.loading_timer.start(300)

        script_dir = os.path.dirname(os.path.abspath(__file__))
        main_script = os.path.join(script_dir, "main.py")
        cmd = [sys.executable, main_script, self.file_path, "-j", "-v"]

        self.compiler_thread = CompilerWorker(cmd)
        self.compiler_thread.finished.connect(self._on_analysis_finished)
        self.compiler_thread.start()

    def on_code_changed(self):
        self.editor.clear_fixed_lines()
        if self.errors_count > 0 or self.warnings_count > 0:
            self.editor.set_errors([])
            self.errors_count = 0
            self.warnings_count = 0
            self.status_label.setText("STATUS: ● WAITING FOR COMPILE")
            self._update_footer()
        self.latest_security_findings = []
        self.latest_security_report = ""
        self.syntax_timer.start(2000)

    def _run_syntax_check(self):
        code = self.editor.toPlainText()
        self.syntax_worker = SyntaxWorker(code, self.file_path)
        self.syntax_worker.finished.connect(self._on_syntax_finished)
        self.syntax_worker.start()

    def _on_syntax_finished(self, errors):
        if self.errors_count == 0 and self.warnings_count == 0:
            self.editor.set_errors(errors)

    def _on_analysis_finished(self, stdout, stderr, returncode):
        self.loading_timer.stop()
        self.is_loading = False
        
        try:
            data = json.loads(stdout)
            self.render_json(data, stderr)
            if hasattr(self, "call_graph_page"):
                self.call_graph_page.update_from_code(self.editor.toPlainText())
            
            # Auto-generate the AST for the just-compiled source without changing pages.
            code = self.editor.toPlainText() if hasattr(self, "editor") else ""
            self.status_label.setText("STATUS: ● BUILDING AST...")
            self.ast_worker = ASTWorker(self.file_path, code=code)
            self.ast_worker.finished.connect(self._on_compile_ast_ready)
            self.ast_worker.start()
                
        except json.JSONDecodeError:
            err_block = f"<span style='color:{PINK};'>COMPILE ERRORS OR JSON DECODE ERROR:</span><br>{stdout}<br>{stderr}"
            self.terminal.append_output(f"<div style='white-space:pre-wrap; font-family:{FONT_FAMILY};'>{err_block}</div>", is_html=True)
            self.status_label.setText("STATUS: ● ERROR")

    def _on_compile_ast_ready(self, ast_tree):
        self.ast_page.update_tree(ast_tree)
        if ast_tree:
            self.status_label.setText("STATUS: ● AST READY")
        else:
            self.status_label.setText("STATUS: ● AST UNAVAILABLE")

    def render_json(self, data, raw_stderr):
        self.terminal.clear()
        status = data.get("status", "")
        findings = data.get("security_findings", [])
        report_text = data.get("security_report", "")
        if status == "success":
            self.status_label.setText("STATUS: ● SUCCESSFUL")
            if findings:
                card = QFrame()
                card.setStyleSheet(f"""
                    QFrame {{
                        background-color: {PANEL_BG};
                        border: 1px solid {YELLOW};
                        border-radius: 6px;
                        padding: 10px;
                        margin-bottom: 8px;
                    }}
                """)
                c_layout = QVBoxLayout(card)
                title = QLabel(f"COMPILES OK — {len(findings)} security finding(s)")
                title.setStyleSheet(f"color: {YELLOW}; font-weight: bold; font-family: {FONT_FAMILY}; font-size: 13px;")
                c_layout.addWidget(title)

                for f in findings[:3]:
                    sev = f.get("severity", "MEDIUM").upper() if isinstance(f, dict) else getattr(f, "severity", "MEDIUM").upper()
                    ftype = f.get("type", "Security Finding") if isinstance(f, dict) else getattr(f, "type", "Security Finding")
                    fline = f.get("line", "?") if isinstance(f, dict) else getattr(f, "line", "?")
                    fdesc = f.get("description", "") if isinstance(f, dict) else getattr(f, "description", "")
                    lbl_f = QLabel(f"• <b>[{sev}] {ftype}</b> (line {fline}): {fdesc}")
                    lbl_f.setStyleSheet(f"color: {TEXT_MAIN}; font-size: 11px; font-family: {FONT_FAMILY};")
                    lbl_f.setWordWrap(True)
                    c_layout.addWidget(lbl_f)

                self.error_cards_layout.addWidget(card)
            else:
                lbl = QLabel("NO ISSUES DETECTED.")
                lbl.setStyleSheet(f"color: {PINK}; font-weight: bold; font-family: {FONT_FAMILY}; font-size: 14px;")
                self.error_cards_layout.addWidget(lbl)

            self.terminal.append_output(f"<span style='color:{TEXT_MAIN};'>Compilation finished successfully. Click 'RUN CODE' to execute.</span><br>", is_html=True)
            self.editor.set_errors([])
            self.errors_count = 0
            self.warnings_count = 0
            self._update_footer()
            self.latest_security_findings = findings
            self.latest_security_report = report_text
            self.security_page.update_report(findings)
            return

            
        self.errors_count = data.get('error_count', 0)
        self.warnings_count = data.get('warning_count', 0)
        self.status_label.setText(f"STATUS: ● {self.errors_count} ERRORS FOUND")
        self._update_footer()

        errors = data.get("errors", [])
        self.editor.set_errors(errors)
        self.latest_security_findings = findings
        self.latest_security_report = report_text
        self.security_page.update_report(findings)

        # ── Feature 2: pass first error to second opinion page ───────────────
        if errors and NEW_PAGES_AVAILABLE and hasattr(self, "second_opinion_page"):
            first_err = errors[0]
            first_msg = first_err.get("message", "")
            first_ast = first_err.get("ast_node", "")
            try:
                self.second_opinion_page.show_opinion(first_msg, first_ast)
            except Exception:
                pass
        # ─────────────────────────────────────────────────────────────────────

        first_err_line = None
        compiler_html = ""
        created_cards = []

        for idx, e in enumerate(errors):

            etype = e.get("error_type", "error").lower()
            tag_color = RED if etype == "error" else YELLOW
            msg = e.get('message', 'Unknown Issue')
            file_name = e.get("file", "unknown")
            line = e.get("line", "?")
            col = e.get("column", "?")
            
            category = e.get('category', 'Syntax / Parser Error')
            confidence = e.get('confidence', 0.92)

            if first_err_line is None and line != "?":
                first_err_line = int(line)

            # Create and add an error card for this issue
            card = self._create_error_card(e)
            created_cards.append(card)
            self.error_cards_layout.addWidget(card)

            compiler_html += f"<span style='color:{tag_color};'>[{etype.upper()}]</span> {os.path.basename(file_name)}:{line}:{col}: <span style='color:{tag_color};'>{etype}:</span> {msg}<br>"
            
            context = e.get("context", {})
            lines = context.get("lines", [])
            start = context.get("start_line", 1)
            
            if lines and type(lines) == list:
                for i, lt in enumerate(lines, start=start):
                    txt = lt.replace('<','&lt;').replace('>','&gt;').rstrip()
                    if i == int(line) if line != "?" else False:
                        compiler_html += f" <span style='color:{tag_color};'>&gt;</span> {i:3} | <b style='color:{TEXT_MAIN}'>{txt}</b><br>"
                        if col != "?":
                            compiler_html += f"       {' ' * (len(str(i)) + 2 + int(col))}<span style='color:{tag_color}'>^</span><br>"
                    else:
                        compiler_html += f"   {i:3} | <span style='color:{TEXT_DIM}'>{txt}</span><br>"
            compiler_html += "<br>"

        # Asynchronously fetch AI explanations if AI assist is enabled
        if self.is_ai_enabled() and errors:
            try:
                from ai_explainer import AIExplainWorker
                self.ai_status_label.setText("AI: analyzing...")
                src_code = self.editor.toPlainText()
                self.ai_explain_worker = AIExplainWorker(errors[:5], src_code)
                
                def on_ai_batch_ready(results_by_idx: dict, provider: str):
                    provider_disp = (provider or "AI").capitalize()
                    self.ai_status_label.setText(f"AI: explained by {provider_disp}")
                    for idx, ai_data in results_by_idx.items():
                        if 0 <= idx < len(created_cards):
                            created_cards[idx].add_ai_explanation(ai_data)

                def on_ai_failed(reason: str):
                    self.ai_status_label.setText(f"AI: {reason}")

                self.ai_explain_worker.batch_ready.connect(on_ai_batch_ready)
                self.ai_explain_worker.failed.connect(on_ai_failed)
                self.ai_explain_worker.start()
            except Exception as ex:
                self.ai_status_label.setText(f"AI: {ex}")
        else:
            self.update_ai_status()

        compiler_html += f"<br>C++_ANALYZER_V2.0.1_READY > _"
        self.terminal.append_output(f"<div style='white-space:pre-wrap; font-family:{FONT_FAMILY};'>{compiler_html}</div>", is_html=True)


def main():
    app = QApplication(sys.argv)
    window = AppGUI()
    window.show()
    exit_code = app.exec()
    if CODECARBON_AVAILABLE and hasattr(window, 'tracker'):
        try:
            window.tracker.stop()
        except:
            pass
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
