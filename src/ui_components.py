"""
ui_components.py
----------------
Small reusable widgets for the redesigned GUI. All styling comes from theme.py
through objectName / dynamic properties - no setStyleSheet() calls here.

SECURITY NOTE: every label that shows compiler/AI text uses
Qt.TextFormat.PlainText, so crafted messages (e.g. `#error <b>...`) can never
be rendered as HTML.
"""
from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (QApplication, QFrame, QHBoxLayout, QLabel,
                             QPushButton, QToolButton, QVBoxLayout, QWidget)

import theme


# ── helpers ──────────────────────────────────────────────────────────────────
def plain_label(text: str = "", object_name: str = "", wrap: bool = True) -> QLabel:
    lbl = QLabel(text)
    lbl.setTextFormat(Qt.TextFormat.PlainText)      # never interpret as HTML
    lbl.setWordWrap(wrap)
    lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    if object_name:
        lbl.setObjectName(object_name)
    return lbl


def badge(text: str, tone: str = "accent") -> QLabel:
    """tone: accent | error | warn | ok | muted"""
    lbl = QLabel(text)
    lbl.setTextFormat(Qt.TextFormat.PlainText)
    lbl.setObjectName("Badge")
    lbl.setProperty("tone", tone)
    return lbl


def section_label(text: str) -> QLabel:
    lbl = QLabel(text.upper())
    lbl.setObjectName("Section")
    f = lbl.font()
    f.setLetterSpacing(f.SpacingType.PercentageSpacing, 108)
    lbl.setFont(f)
    return lbl


def code_block(text: str, copy_button: bool = True) -> QFrame:
    box = QFrame()
    box.setObjectName("CodeBlock")
    lay = QHBoxLayout(box)
    lay.setContentsMargins(12, 10, 8, 10)
    lbl = plain_label(text, "CodeText")
    lbl.setFont(theme.mono_font(12))
    lay.addWidget(lbl, 1)
    if copy_button:
        btn = QPushButton("Copy")
        btn.setProperty("variant", "ghost")
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.clicked.connect(lambda: QApplication.clipboard().setText(text))
        lay.addWidget(btn, 0, Qt.AlignmentFlag.AlignTop)
    return box


def split_explanation(text: str | None) -> dict:
    """Parse the 'What happened / Why it happened / How to fix it' text
    produced by error_explainer.format_error()."""
    parts = {"what": "", "why": "", "how": "", "extra": ""}
    keys = {"What happened:": "what", "Why it happened:": "why", "How to fix it:": "how"}
    cur = None
    for line in (text or "").splitlines():
        s = line.strip()
        if s in keys:
            cur = keys[s]
            continue
        if cur and s:
            if "This error occurred inside" in s:
                parts["extra"] = s
            else:
                parts[cur] += ("\n" if parts[cur] else "") + s
        elif s and not cur:
            parts["what"] += ("\n" if parts["what"] else "") + s
    return parts


# ── collapsible section ──────────────────────────────────────────────────────
class CollapsibleSection(QWidget):
    def __init__(self, title: str, expanded: bool = True, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(4)

        self.toggle = QToolButton()
        self.toggle.setObjectName("SectionToggle")
        self.toggle.setText(title)
        self.toggle.setCheckable(True)
        self.toggle.setChecked(expanded)
        self.toggle.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.toggle.setArrowType(Qt.ArrowType.DownArrow if expanded else Qt.ArrowType.RightArrow)
        self.toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        self.toggle.toggled.connect(self._on_toggle)
        lay.addWidget(self.toggle)

        self.body = QWidget()
        self.body_lay = QVBoxLayout(self.body)
        self.body_lay.setContentsMargins(18, 0, 0, 6)
        self.body_lay.setSpacing(4)
        self.body.setVisible(expanded)
        lay.addWidget(self.body)

    def set_text(self, text: str) -> None:
        self.body_lay.addWidget(plain_label(text))

    def _on_toggle(self, checked: bool) -> None:
        self.toggle.setArrowType(Qt.ArrowType.DownArrow if checked else Qt.ArrowType.RightArrow)
        self.body.setVisible(checked)


# ── issue card (one compiler diagnostic) ─────────────────────────────────────
class IssueCard(QFrame):
    clicked = pyqtSignal(int)          # emits the line number

    def __init__(self, err: dict, co2_offset: float = 0.0, parent=None):
        super().__init__(parent)
        self.setObjectName("IssueCard")
        self.err = err
        self.line = int(err.get("line") or 0)
        sev = (err.get("type") or err.get("error_type") or "error").lower()
        self.setProperty("sev", sev)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        self.card_layout = QVBoxLayout(self)
        self.card_layout.setContentsMargins(14, 12, 14, 12)
        self.card_layout.setSpacing(10)

        # 1. Top row: Type badge, Category badge, Line badge
        top = QHBoxLayout()
        top.setSpacing(8)
        top.addWidget(badge(sev.upper(), "error" if sev == "error" else "warn"))
        cat = err.get("category")
        if cat:
            top.addWidget(badge(str(cat).replace("_", " ").upper(), "accent"))
        top.addStretch(1)
        if self.line:
            loc = QLabel(f"Line {self.line}")
            loc.setObjectName("Muted")
            top.addWidget(loc)
        self.card_layout.addLayout(top)

        # 2. Issue message title
        self.card_layout.addWidget(plain_label(err.get("message", "Unknown issue"), "IssueTitle"))

        # 3. Compact telemetry & security stats row
        stats_row = QHBoxLayout()
        stats_row.setSpacing(6)
        cpu = "2.5 mWh"
        mem = "12 MB"
        hotspot = f"Line {self.line}" if self.line else "None"
        co2 = f"{(co2_offset * 1e6):.2f} mg"
        risk = str(err.get("security_risk") or "LOW").upper()
        risk_tone = "error" if risk == "HIGH" else ("warn" if risk == "MEDIUM" else "ok")

        stats_row.addWidget(badge(f"⚡ {cpu}", "accent"))
        stats_row.addWidget(badge(f"🧠 {mem}", "accent"))
        stats_row.addWidget(badge(f"🔥 {hotspot}", "warn"))
        stats_row.addWidget(badge(f"🌍 {co2}", "ok"))
        stats_row.addWidget(badge(f"🛡️ {risk}", risk_tone))
        stats_row.addStretch(1)
        self.card_layout.addLayout(stats_row)

        # 4. Code context snippet
        context = err.get("context", {})
        lines = context.get("lines", [])
        start = context.get("start_line", 1)
        col = err.get("column", "?")
        if lines and isinstance(lines, list):
            ctx_text = ""
            for i, lt in enumerate(lines, start=start):
                lt_clean = lt.rstrip("\r\n")
                if str(i) == str(self.line):
                    ctx_text += f"> {i:3} | {lt_clean}\n"
                    if col != "?":
                        try:
                            c_int = int(col)
                            ctx_text += f"      {' ' * (len(str(i)) + 2 + c_int)}^\n"
                        except (ValueError, TypeError):
                            pass
                else:
                    ctx_text += f"  {i:3} | {lt_clean}\n"
            if ctx_text.strip():
                self.card_layout.addWidget(section_label("CODE CONTEXT"))
                self.card_layout.addWidget(code_block(ctx_text.rstrip("\n"), copy_button=False))

        # 5. Explanations (What / Why / How)
        expl_text = err.get("explanation")
        parts = split_explanation(expl_text)
        has_parts = bool(parts["what"] or parts["why"] or parts["how"])

        if has_parts:
            self.card_layout.addWidget(section_label("EXPLANATION"))
            for key, title in (("what", "What happened:"),
                               ("why", "Why it happened:"),
                               ("how", "How to fix it:")):
                if parts[key]:
                    sec = CollapsibleSection(title, expanded=True)
                    sec.set_text(parts[key])
                    self.card_layout.addWidget(sec)
            if parts.get("extra"):
                extra_lbl = plain_label(f"ℹ️ {parts['extra']}", "Muted")
                self.card_layout.addWidget(extra_lbl)
        elif expl_text:
            self.card_layout.addWidget(section_label("EXPLANATION"))
            self.card_layout.addWidget(plain_label(expl_text))

        # 6. Suggested Fix
        if err.get("suggestion"):
            self.card_layout.addWidget(section_label("SUGGESTED FIX"))
            self.card_layout.addWidget(code_block(err["suggestion"], copy_button=True))

        # 7. AI Explanation if already attached
        ai_exp = err.get("ai_explanation")
        if ai_exp and isinstance(ai_exp, dict):
            self.add_ai_explanation(ai_exp)

    def add_ai_explanation(self, ai_data: dict) -> None:
        if not ai_data or not isinstance(ai_data, dict):
            return
        if hasattr(self, "ai_card") and self.ai_card:
            try:
                self.card_layout.removeWidget(self.ai_card)
                self.ai_card.deleteLater()
            except Exception:
                pass
            self.ai_card = None

        provider = (ai_data.get("provider") or "AI").capitalize()
        expl = ai_data.get("explanation", "")
        fix = ai_data.get("fix", "")
        why = ai_data.get("why", "")
        if expl or fix or why:
            self.ai_card = AiCard(provider, expl, fix, why)
            self.card_layout.addWidget(self.ai_card)
            self.update()

    def set_selected(self, selected: bool) -> None:
        theme.set_prop(self, "selected", "true" if selected else "false")

    def mousePressEvent(self, event):
        self.clicked.emit(self.line)
        super().mousePressEvent(event)


# ── AI explanation card ──────────────────────────────────────────────────────
class AiCard(QFrame):
    def __init__(self, provider: str, explanation: str, fix: str = "", why: str = "", parent=None):
        super().__init__(parent)
        self.setObjectName("AiCard")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(8)

        head = QHBoxLayout()
        head.addWidget(badge(f"🤖 AI ASSISTANT · {provider.upper()}", "accent"))
        head.addStretch(1)
        lay.addLayout(head)

        if explanation:
            lay.addWidget(section_label("AI EXPLANATION"))
            lay.addWidget(plain_label(explanation))
        if fix:
            lay.addWidget(section_label("AI SUGGESTED FIX"))
            lay.addWidget(code_block(fix, copy_button=True))
        if why:
            lay.addWidget(section_label("WHY THIS FIX WORKS"))
            lay.addWidget(plain_label(why, "Muted"))
