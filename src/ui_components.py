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

from PyQt6.QtCore import QRect, Qt, pyqtSignal
from PyQt6.QtGui import QColor, QPainter, QPen
from PyQt6.QtWidgets import (QApplication, QFrame, QHBoxLayout, QLabel,
                             QMessageBox, QPushButton, QToolButton, QVBoxLayout, QWidget)

import theme


# ── helpers ──────────────────────────────────────────────────────────────────
def show_message(parent, kind: str, title: str, text: str) -> None:
    """Display a QMessageBox ensuring text is rendered in PlainText format."""
    msg_box = QMessageBox(parent)
    msg_box.setWindowTitle(title)
    msg_box.setText(text)
    msg_box.setTextFormat(Qt.TextFormat.PlainText)
    k = kind.lower()
    if k in ("critical", "error"):
        msg_box.setIcon(QMessageBox.Icon.Critical)
    elif k in ("warning", "warn"):
        msg_box.setIcon(QMessageBox.Icon.Warning)
    elif k in ("information", "info"):
        msg_box.setIcon(QMessageBox.Icon.Information)
    else:
        msg_box.setIcon(QMessageBox.Icon.NoIcon)
    msg_box.exec()


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
    lbl.setTextFormat(Qt.TextFormat.PlainText)
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
    def __init__(self, title: str, expanded: Any = True, parent=None):
        if isinstance(expanded, QWidget):
            content_widget = expanded
            expanded = True
        else:
            content_widget = None

        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(4)

        self.toggle = QToolButton()
        self.toggle.setObjectName("SectionToggle")
        self.toggle.setText(title)
        self.toggle.setCheckable(True)
        self.toggle.setChecked(bool(expanded))
        self.toggle.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.toggle.setArrowType(Qt.ArrowType.DownArrow if expanded else Qt.ArrowType.RightArrow)
        self.toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        self.toggle.toggled.connect(self._on_toggle)
        lay.addWidget(self.toggle)

        self.body = QWidget(self)
        self.body_lay = QVBoxLayout(self.body)
        self.body_lay.setContentsMargins(18, 0, 0, 6)
        self.body_lay.setSpacing(4)
        lay.addWidget(self.body)
        self.body.setVisible(bool(expanded))

        if content_widget is not None:
            self.body_lay.addWidget(content_widget)

    def add_widget(self, widget: QWidget) -> None:
        self.body_lay.addWidget(widget)

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
        self.card_layout.setContentsMargins(14, 14, 14, 14)
        self.card_layout.setSpacing(12)

        # ── Header area ───────────────────────────────────────────────────────
        self.header_widget = QWidget()
        header_lay = QVBoxLayout(self.header_widget)
        header_lay.setContentsMargins(0, 0, 0, 0)
        header_lay.setSpacing(8)

        # 1. Top row: Toggle indicator, Type badge, Category badge, Line badge
        top = QHBoxLayout()
        top.setSpacing(8)

        self.toggle_indicator = plain_label("▸", "Muted", wrap=False)
        self.toggle_indicator.setCursor(Qt.CursorShape.PointingHandCursor)
        top.addWidget(self.toggle_indicator)

        top.addWidget(badge(sev.upper(), "error" if sev == "error" else "warn"))
        cat = err.get("category")
        if cat:
            top.addWidget(badge(str(cat).replace("_", " ").upper(), "accent"))
        top.addStretch(1)
        if self.line:
            loc = plain_label(f"Line {self.line}", "Muted")
            top.addWidget(loc)
        header_lay.addLayout(top)

        # 2. Issue message title
        self.title_label = plain_label(err.get("message", "Unknown issue"), "IssueTitle")
        header_lay.addWidget(self.title_label)

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
        header_lay.addLayout(stats_row)

        self.card_layout.addWidget(self.header_widget)

        # ── Collapsible Body (Code context, Explanation, Fix, AI) ─────────────
        self.body = QWidget(self)
        self.body_layout = QVBoxLayout(self.body)
        self.body_layout.setContentsMargins(0, 4, 0, 0)
        self.body_layout.setSpacing(8)

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
                self.body_layout.addWidget(section_label("CODE CONTEXT"))
                self.body_layout.addWidget(code_block(ctx_text.rstrip("\n"), copy_button=False))

        # 5. Explanations (What / Why / How)
        expl_text = err.get("explanation")
        parts = split_explanation(expl_text)
        has_parts = bool(parts["what"] or parts["why"] or parts["how"])

        if has_parts:
            self.body_layout.addWidget(section_label("EXPLANATION"))
            for key, title in (("what", "What happened:"),
                               ("why", "Why it happened:"),
                               ("how", "How to fix it:")):
                if parts[key]:
                    sec = CollapsibleSection(title, expanded=True)
                    sec.set_text(parts[key])
                    self.body_layout.addWidget(sec)
            if parts.get("extra"):
                extra_lbl = plain_label(f"ℹ️ {parts['extra']}", "Muted")
                self.body_layout.addWidget(extra_lbl)
        elif expl_text:
            self.body_layout.addWidget(section_label("EXPLANATION"))
            self.body_layout.addWidget(plain_label(expl_text))

        # 6. Suggested Fix
        if err.get("suggestion"):
            self.body_layout.addWidget(section_label("SUGGESTED FIX"))
            self.body_layout.addWidget(code_block(err["suggestion"], copy_button=True))

        # 7. AI Explanation if already attached
        ai_exp = err.get("ai_explanation")
        if ai_exp and isinstance(ai_exp, dict):
            self.add_ai_explanation(ai_exp)

        self.card_layout.addWidget(self.body)
        self.body.setVisible(False)

        # Make header transparent for mouse events so all clicks reach the card
        self.header_widget.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        for child in self.header_widget.findChildren(QWidget):
            child.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)

    def toggle_expand(self):
        is_hidden = self.body.isHidden()
        self.body.setVisible(is_hidden)
        self.toggle_indicator.setText("▾" if is_hidden else "▸")

    def add_ai_explanation(self, ai_data: dict) -> None:
        if not ai_data or not isinstance(ai_data, dict):
            return
        if hasattr(self, "ai_card") and self.ai_card:
            try:
                self.body_layout.removeWidget(self.ai_card)
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
            self.body_layout.addWidget(self.ai_card)
            self.update()

    def set_selected(self, selected: bool) -> None:
        theme.set_prop(self, "selected", "true" if selected else "false")

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self.line)
            if self.body.isHidden() or event.pos().y() <= self.header_widget.geometry().bottom():
                self.toggle_expand()
        super().mousePressEvent(event)


# ── AI explanation card ──────────────────────────────────────────────────────
class AiCard(QFrame):
    def __init__(self, provider: str, explanation: str, fix: str = "", why: str = "", parent=None):
        super().__init__(parent)
        self.setObjectName("AiCard")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 14, 14, 14)
        lay.setSpacing(12)

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


# ── Security UI Components (Phase 8a) ────────────────────────────────────────

class SecuritySummaryCard(QFrame):
    """Card at top of Problems panel showing security risk level, score, severity counts, and agents."""
    def __init__(self, summary: dict, quality: Optional[dict] = None, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.summary = summary or {}
        self.quality = quality or {}

        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 14, 14, 14)
        lay.setSpacing(12)

        # Top row: SECURITY label, Badge with level and score, stretch, agents list
        top = QHBoxLayout()
        top.setSpacing(10)
        top.addWidget(section_label("SECURITY"))

        lvl = self.summary.get("level", "Clean")
        score = self.summary.get("score", 0)
        tone = self.summary.get("tone", "ok")
        top.addWidget(badge(f"{lvl.upper()} ({score})", tone))

        agents = self.summary.get("agents", [])
        if agents:
            det_text = f"Detected by {', '.join(agents)}"
            det_lbl = plain_label(det_text, "Muted")
            top.addStretch(1)
            top.addWidget(det_lbl)
        else:
            top.addStretch(1)
        lay.addLayout(top)

        # Quality row: Quality: <level> (Good ok, Fair warn, Needs work warn)
        q_lvl = self.quality.get("level") if self.quality else self.summary.get("quality_level")
        if q_lvl:
            q_tone = "ok" if q_lvl == "Good" else "warn"
            q_row = QHBoxLayout()
            q_row.setSpacing(8)
            q_row.addWidget(section_label("QUALITY"))
            q_row.addWidget(badge(q_lvl.upper(), q_tone))
            q_hints = self.quality.get("hints", [])
            if q_hints:
                q_row.addWidget(plain_label(f"{len(q_hints)} suggestion(s)", "Muted"))
            q_row.addStretch(1)
            lay.addLayout(q_row)

        # Headline
        headline = self.summary.get("headline", "")
        if headline:
            lay.addWidget(plain_label(headline, "IssueTitle"))

        # Severity counts row
        counts = self.summary.get("counts", {})
        total = self.summary.get("total", 0)
        if total > 0:
            chips_row = QHBoxLayout()
            chips_row.setSpacing(6)
            chips_row.addWidget(badge(f"{counts.get('Critical', 0)} Critical", "error" if counts.get('Critical', 0) > 0 else "muted"))
            chips_row.addWidget(badge(f"{counts.get('High', 0)} High", "error" if counts.get('High', 0) > 0 else "muted"))
            chips_row.addWidget(badge(f"{counts.get('Medium', 0)} Medium", "warn" if counts.get('Medium', 0) > 0 else "muted"))
            chips_row.addWidget(badge(f"{counts.get('Low', 0)} Low", "ok" if counts.get('Low', 0) > 0 else "muted"))
            chips_row.addStretch(1)
            lay.addLayout(chips_row)
        else:
            lay.addWidget(plain_label("No security findings detected.", "Muted"))


class SecurityFindingCard(QFrame):
    """Detailed finding card with severity strip, cleaner badge row, agent chips, and collapsible body."""
    clicked = pyqtSignal(int)

    def __init__(self, finding_view_data: dict, parent=None):
        super().__init__(parent)
        self.setObjectName("SecurityFindingCard")
        self.data = finding_view_data or {}
        self.line = int(self.data.get("line") or 0)

        sev = str(self.data.get("severity", "Medium")).lower()
        self.setProperty("sev", sev)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        self.card_layout = QVBoxLayout(self)
        self.card_layout.setContentsMargins(14, 14, 14, 14)
        self.card_layout.setSpacing(12)

        # ── Header area ───────────────────────────────────────────────────────
        self.header_widget = QWidget()
        header_lay = QVBoxLayout(self.header_widget)
        header_lay.setContentsMargins(0, 0, 0, 0)
        header_lay.setSpacing(8)

        # 1. Top row: Toggle indicator, Severity badge, neutral muted tag, action badge (BLOCKED only), line
        top = QHBoxLayout()
        top.setSpacing(8)

        self.toggle_indicator = plain_label("▸", "Muted", wrap=False)
        self.toggle_indicator.setCursor(Qt.CursorShape.PointingHandCursor)
        top.addWidget(self.toggle_indicator)

        top.addWidget(badge(self.data.get("severity", "Medium").upper(), self.data.get("tone", "warn")))

        kind_label = self.data.get("kind_label", "")
        tag_text = "Your code" if kind_label.startswith("Weakness") else "Tool attack"
        top.addWidget(badge(tag_text, "muted"))

        act_label = self.data.get("action_label", "")
        if act_label == "BLOCKED":
            top.addWidget(badge("BLOCKED", "error"))

        top.addStretch(1)
        if self.line > 0:
            top.addWidget(plain_label(f"Line {self.line}", "Muted"))
        header_lay.addLayout(top)

        # 2. Title
        self.title_label = plain_label(self.data.get("title", "Security Finding"), "IssueTitle")
        header_lay.addWidget(self.title_label)

        # 3. DETECTED BY row
        det_row = QHBoxLayout()
        det_row.setSpacing(6)
        det_row.addWidget(section_label("DETECTED BY"))

        kind = "attack" if kind_label.startswith("Attack") else "vuln"
        raw_agents = self.data.get("agents")
        if not raw_agents:
            agents = ["Security Guard"]
        elif isinstance(raw_agents, str):
            agents = [raw_agents]
        elif isinstance(raw_agents, (list, tuple)):
            agents = list(raw_agents)
        else:
            agents = ["Security Guard"]

        for ag in agents:
            chip = plain_label(str(ag), "AgentChip", wrap=False)
            chip.setProperty("kind", kind)
            det_row.addWidget(chip)
        det_row.addStretch(1)
        header_lay.addLayout(det_row)

        # 4. One-line evidence
        evidence = self.data.get("evidence", "")
        if evidence:
            first_ev = ""
            for l in evidence.splitlines():
                if l.strip():
                    first_ev = l.strip()
                    break
            if first_ev:
                self.evidence_label = plain_label(first_ev, "Muted", wrap=False)
                self.evidence_label.setFont(theme.mono_font(12))
                header_lay.addWidget(self.evidence_label)

        self.card_layout.addWidget(self.header_widget)

        # ── Collapsible Body (What / Why / How) ────────────────────────────────
        self.body = QWidget(self)
        self.body_layout = QVBoxLayout(self.body)
        self.body_layout.setContentsMargins(0, 4, 0, 0)
        self.body_layout.setSpacing(8)

        what = self.data.get("what", "")
        why = self.data.get("why", "")
        how = self.data.get("how", "")

        if what:
            sec_what = CollapsibleSection("What happened:", expanded=True)
            sec_what.set_text(what)
            self.body_layout.addWidget(sec_what)

        if why:
            sec_why = CollapsibleSection("Why it is dangerous:", expanded=True)
            sec_why.set_text(why)
            self.body_layout.addWidget(sec_why)

        if how:
            sec_how = CollapsibleSection("How to fix it:", expanded=True)
            sec_how.set_text(how)
            self.body_layout.addWidget(sec_how)

        if evidence and len(evidence.strip().splitlines()) > 1:
            self.body_layout.addWidget(section_label("FULL EVIDENCE"))
            self.body_layout.addWidget(code_block(evidence, copy_button=True))

        self.card_layout.addWidget(self.body)
        self.body.setVisible(False)

        # Make header transparent for mouse events so all clicks reach the card
        self.header_widget.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        for child in self.header_widget.findChildren(QWidget):
            child.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)

    def toggle_expand(self):
        is_hidden = self.body.isHidden()
        self.body.setVisible(is_hidden)
        self.toggle_indicator.setText("▾" if is_hidden else "▸")

    def add_ai_explanation(self, ai_data: dict) -> None:
        """No-op for security finding cards to guard against attribute errors."""
        pass

    def set_selected(self, selected: bool) -> None:
        theme.set_prop(self, "selected", "true" if selected else "false")

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self.line)
            if self.body.isHidden() or event.pos().y() <= self.header_widget.geometry().bottom():
                self.toggle_expand()
        super().mousePressEvent(event)


class BlockedBanner(QFrame):
    """Prominent banner shown at top of Problems panel when compile/run is blocked."""
    fix_clicked = pyqtSignal()

    def __init__(self, banner_data: dict, parent=None):
        super().__init__(parent)
        self.setObjectName("BlockedBanner")
        self.banner_data = banner_data or {}

        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 14, 14, 14)
        lay.setSpacing(12)

        # Title
        title_text = self.banner_data.get("title", "Execution blocked by the security layer")
        title_lbl = plain_label(title_text, "Title")
        title_lbl.setFont(theme.ui_font(13, True))
        lay.addWidget(title_lbl)

        # One-line explanation
        lay.addWidget(plain_label("Execution was blocked to protect your environment from unsafe or destructive operations.", "Muted"))

        # Findings list
        findings = self.banner_data.get("findings", [])
        for f in findings:
            line_str = f"line {f.get('line')}" if f.get('line') is not None else "unknown line"
            agents_str = ", ".join(f.get("agents", []))
            item_text = f"• [{f.get('severity', 'HIGH').upper()}] {f.get('title', 'Security Finding')} ({agents_str}) {line_str}"
            lay.addWidget(plain_label(item_text))

        # Fix with Auto-Heal button
        btn_row = QHBoxLayout()
        self.fix_btn = QPushButton("Fix with Auto-Heal")
        self.fix_btn.setProperty("variant", "primary")
        self.fix_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.fix_btn.clicked.connect(self.fix_clicked.emit)
        btn_row.addWidget(self.fix_btn)
        btn_row.addStretch(1)
        lay.addLayout(btn_row)


class SecurityResultCard(QFrame):
    """Card shown after Auto-Heal detailing before/after risk, applied fixes, suggestions, and remaining findings."""
    def __init__(self, heal_view: dict, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.view = heal_view or {}

        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 14, 14, 14)
        lay.setSpacing(12)

        # Headline and tone
        headline = self.view.get("headline", "Security Healing Result")
        tone = self.view.get("tone", "ok")
        top_row = QHBoxLayout()
        top_row.addWidget(badge(headline, tone))
        top_row.addStretch(1)
        lay.addLayout(top_row)

        # Counts line
        counts = self.view.get("counts", {})
        counts_text = (
            f"Fixed {counts.get('fixed', 0)} · "
            f"Suggested {counts.get('suggested', 0)} · "
            f"Skipped {counts.get('skipped', 0)} · "
            f"Remaining {counts.get('remaining', 0)}"
        )
        lay.addWidget(plain_label(counts_text, "Muted"))
        if self.view.get("stopped_early"):
            lay.addWidget(plain_label(self.view["stopped_early"], "Muted"))

        # Applied fixes (collapsible, closed by default beyond the first 3)
        applied = self.view.get("applied", [])
        if applied:
            app_sec = CollapsibleSection(f"Applied Fixes ({len(applied)})", expanded=True)
            for idx, fix in enumerate(applied):
                fix_box = QFrame()
                fix_box.setObjectName("Card")
                fb_lay = QVBoxLayout(fix_box)
                fb_lay.setContentsMargins(10, 8, 10, 8)
                fb_lay.setSpacing(4)

                l_str = f" · Line {fix.get('line')}" if fix.get('line') else ""
                fb_lay.addWidget(plain_label(f"✓ {fix.get('title')}{l_str}", "IssueTitle"))
                fb_lay.addWidget(plain_label(fix.get("detected_by", ""), "Muted"))

                before_t = fix.get("before", "")
                after_t = fix.get("after", "")
                if before_t or after_t:
                    diff_sec = CollapsibleSection("Diff (Before / After)", expanded=(idx < 3))
                    if before_t:
                        diff_sec.body_lay.addWidget(section_label("ORIGINAL"))
                        diff_sec.body_lay.addWidget(code_block(before_t, copy_button=False))
                    if after_t:
                        diff_sec.body_lay.addWidget(section_label("MODIFIED"))
                        diff_sec.body_lay.addWidget(code_block(after_t, copy_button=False))
                    fb_lay.addWidget(diff_sec)

                app_sec.body_lay.addWidget(fix_box)
            lay.addWidget(app_sec)

        # Suggestions (collapsible, closed by default)
        suggestions = self.view.get("suggestions", [])
        if suggestions:
            sug_sec = CollapsibleSection(f"Suggestions ({len(suggestions)})", expanded=False)
            sug_sec.body_lay.addWidget(plain_label("Not changed automatically — manual review required:", "Muted"))
            for s in suggestions:
                s_box = QFrame()
                s_box.setObjectName("Card")
                sb_lay = QVBoxLayout(s_box)
                sb_lay.setContentsMargins(10, 8, 10, 8)
                sb_lay.setSpacing(4)
                l_str = f" · Line {s.get('line')}" if s.get('line') else ""
                sb_lay.addWidget(plain_label(f"⚡ {s.get('title')}{l_str}", "IssueTitle"))
                sb_lay.addWidget(plain_label(s.get("detected_by", ""), "Muted"))
                sb_lay.addWidget(plain_label(s.get("text", "")))
                sug_sec.body_lay.addWidget(s_box)
            lay.addWidget(sug_sec)

        # Remaining findings (compact finding cards)
        remaining = self.view.get("remaining", [])
        if remaining:
            rem_sec = CollapsibleSection(f"Remaining Findings ({len(remaining)})", expanded=True)
            for rf in remaining:
                r_box = QFrame()
                r_box.setObjectName("Card")
                rb_lay = QVBoxLayout(r_box)
                rb_lay.setContentsMargins(10, 8, 10, 8)
                rb_lay.setSpacing(4)
                l_str = f" · Line {rf.get('line')}" if rf.get('line') else ""
                rb_lay.addWidget(plain_label(f"⚠ {rf.get('title')}{l_str} [{rf.get('severity')}]", "IssueTitle"))
                rb_lay.addWidget(plain_label(rf.get("detected_by", ""), "Muted"))
                rb_lay.addWidget(plain_label(rf.get("what", "")))
                rem_sec.body_lay.addWidget(r_box)
            lay.addWidget(rem_sec)

        # Note line
        lay.addWidget(plain_label("Fixes were applied with a backup. Use Undo to restore the original.", "Muted"))


class QualityHintCard(QFrame):
    """Card displaying a deterministic code quality suggestion in the Problems panel."""
    clicked = pyqtSignal(int)

    def __init__(self, hint: dict, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.hint = hint or {}
        self.line = hint.get("line")

        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 14, 14, 14)
        lay.setSpacing(12)

        top = QHBoxLayout()
        top.setSpacing(8)
        title_text = self.hint.get("title", "Quality hint")
        line_str = f"Line {self.line}" if self.line else "General"
        top.addWidget(plain_label(title_text, "IssueTitle"))
        top.addWidget(badge(line_str, "muted"))
        top.addStretch(1)
        lay.addLayout(top)

        msg = self.hint.get("message", "")
        if msg:
            lay.addWidget(plain_label(msg, "Muted"))

        sug = self.hint.get("suggestion", "")
        if sug:
            lay.addWidget(plain_label(f"💡 {sug}"))

    def set_selected(self, selected: bool) -> None:
        theme.set_prop(self, "selected", "true" if selected else "false")

    def mousePressEvent(self, event):
        if self.line:
            self.clicked.emit(self.line)
        super().mousePressEvent(event)


class SecurityBarChart(QWidget):
    """
    Themed bar chart comparing Baseline ASR vs Defended ASR per threat family.
    Uses QPainter with theme tokens, automatically repainting on theme change.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(240)
        self.families_data: List[Dict[str, Any]] = []
        theme.on_change(lambda m, t: self.update())

    def set_data(self, families_data: List[Dict[str, Any]]) -> None:
        self.families_data = families_data or []
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.fillRect(self.rect(), theme.qcolor("surface"))

        w, h = self.width(), self.height()
        left, top, right, bottom = 45, 30, 20, 60
        pw = max(10, w - left - right)
        ph = max(10, h - top - bottom)
        plot_rect = QRect(left, top, pw, ph)

        painter.setPen(QPen(theme.qcolor("border"), 1))
        painter.drawRect(plot_rect)

        # Horizontal grid lines (25%, 50%, 75%)
        grid_pen = QPen(theme.qcolor("border"), 1, Qt.PenStyle.DashLine)
        painter.setPen(grid_pen)
        for pct in [0.25, 0.50, 0.75]:
            gy = top + int(ph * (1.0 - pct))
            painter.drawLine(left, gy, left + pw, gy)

        # Y-axis labels
        painter.setFont(theme.ui_font(9))
        painter.setPen(theme.qcolor("muted"))
        painter.drawText(6, top + 8, "100%")
        painter.drawText(6, top + int(ph * 0.5) + 4, " 50%")
        painter.drawText(6, top + ph, "  0%")

        if not self.families_data:
            painter.drawText(plot_rect, Qt.AlignmentFlag.AlignCenter, "No benchmark family data available")
            return

        n = len(self.families_data)
        group_w = pw / max(1, n)
        bar_w = max(4, int(group_w * 0.32))

        for i, item in enumerate(self.families_data):
            gx = left + int(i * group_w)
            base_asr = max(0.0, min(1.0, float(item.get("baseline_asr", 0.0))))
            def_asr = max(0.0, min(1.0, float(item.get("defended_asr", 0.0))))

            h_base = int(ph * base_asr)
            h_def = int(ph * def_asr)

            x_base = gx + int(group_w * 0.16)
            y_base = top + ph - h_base
            x_def = x_base + bar_w + 3
            y_def = top + ph - h_def

            # Draw baseline bar (warn tone)
            painter.fillRect(QRect(x_base, y_base, bar_w, h_base), theme.qcolor("warn"))
            # Draw defended bar (ok tone)
            painter.fillRect(QRect(x_def, y_def, bar_w, h_def), theme.qcolor("ok"))

            # Label below
            fam_title = item.get("title", item.get("family", ""))
            short_title = fam_title.split()[0][:8]
            painter.setPen(theme.qcolor("muted"))
            painter.setFont(theme.ui_font(9))
            painter.drawText(QRect(gx, top + ph + 6, int(group_w), 40), Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop, short_title)

        # Legend at top right
        leg_x = left + pw - 190
        painter.fillRect(QRect(leg_x, 8, 12, 10), theme.qcolor("warn"))
        painter.setPen(theme.qcolor("muted"))
        painter.drawText(leg_x + 16, 17, "Baseline ASR")

        painter.fillRect(QRect(leg_x + 95, 8, 12, 10), theme.qcolor("ok"))
        painter.drawText(leg_x + 111, 17, "Defended ASR")



# ── Complexity & Optimization Components ────────────────────────────────────

class ComplexityBadge(QFrame):
    """
    Displays one complexity metric: icon + metric name + Big-O value + colored badge.
    Example: ⏱ Time Complexity: O(n²) [SLOW]
    """
    def __init__(self, icon: str, label: str, big_o: str = "Unknown", tone: str = "muted", badge_text: str = "UNKNOWN", parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(12, 8, 12, 8)
        lay.setSpacing(10)

        self.lbl_title = plain_label(f"{icon}  {label.upper()}:", "Section")
        f = self.lbl_title.font()
        f.setBold(True)
        self.lbl_title.setFont(f)
        lay.addWidget(self.lbl_title)

        self.lbl_val = plain_label(big_o, "IssueTitle")
        f_val = theme.mono_font(12)
        f_val.setBold(True)
        self.lbl_val.setFont(f_val)
        lay.addWidget(self.lbl_val)

        self.badge_lbl = badge(badge_text, tone)
        lay.addWidget(self.badge_lbl)
        lay.addStretch(1)

    def set_complexity(self, big_o: str, tone: str, badge_text: str):
        self.lbl_val.setText(big_o or "Unknown")
        self.badge_lbl.setText(badge_text or "UNKNOWN")
        theme.set_prop(self.badge_lbl, "tone", tone or "muted")


class ComplexityCompareCard(QFrame):
    """
    Displays a Before -> After comparison for time or space complexity.
    Example:
    ⏱ TIME COMPLEXITY
    Before: O(2^n) [DANGER]  ➔  After: O(log n) [FAST]
    """
    def __init__(self, icon: str, title: str,
                 prev_val: str, prev_tone: str, prev_badge: str,
                 new_val: str, new_tone: str, new_badge: str,
                 parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 8, 12, 8)
        lay.setSpacing(6)

        hdr = plain_label(f"{icon}  {title.upper()}", "Section")
        f_h = hdr.font()
        f_h.setBold(True)
        hdr.setFont(f_h)
        lay.addWidget(hdr)

        row = QHBoxLayout()
        row.setSpacing(8)

        # Before section
        lbl_prev_title = plain_label("Before:", "Muted")
        row.addWidget(lbl_prev_title)

        lbl_prev_val = plain_label(prev_val or "Unknown", "Body")
        f_pv = theme.mono_font(11)
        f_pv.setBold(True)
        lbl_prev_val.setFont(f_pv)
        row.addWidget(lbl_prev_val)

        if prev_badge and prev_badge != "UNKNOWN":
            row.addWidget(badge(prev_badge, prev_tone or "muted"))

        # Arrow indicator
        lbl_arrow = plain_label("➔", "Title")
        f_arr = lbl_arrow.font()
        f_arr.setBold(True)
        lbl_arrow.setFont(f_arr)
        lbl_arrow.setStyleSheet("color: #38bdf8; font-weight: bold; margin: 0 4px;")
        row.addWidget(lbl_arrow)

        # After section
        lbl_new_title = plain_label("After:", "Muted")
        row.addWidget(lbl_new_title)

        lbl_new_val = plain_label(new_val or "Unknown", "IssueTitle")
        f_nv = theme.mono_font(11)
        f_nv.setBold(True)
        lbl_new_val.setFont(f_nv)
        row.addWidget(lbl_new_val)

        if new_badge and new_badge != "UNKNOWN":
            row.addWidget(badge(new_badge, new_tone or "ok"))

        row.addStretch(1)
        lay.addLayout(row)


class BottleneckCard(QFrame):
    """
    Card displaying a single efficiency bottleneck with severity badge and description.
    """
    def __init__(self, b_view: dict, parent=None):
        super().__init__(parent)
        self.setObjectName("IssueCard")
        tone = b_view.get("tone", "warn")
        self.setProperty("sev", tone)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 10, 12, 10)
        lay.setSpacing(6)

        hdr = QHBoxLayout()
        hdr.setSpacing(8)

        sev = b_view.get("severity", "Medium")
        hdr.addWidget(badge(sev.upper(), tone))

        line_str = b_view.get("line_str", "")
        if line_str:
            hdr.addWidget(plain_label(line_str, "Muted"))

        hdr.addStretch(1)
        lay.addLayout(hdr)

        desc = b_view.get("description", "")
        if desc:
            lbl_desc = plain_label(desc, "Body")
            lay.addWidget(lbl_desc)


class ComplexityStripWidget(QFrame):
    """
    Thin horizontal status strip that can sit below the code editor.
    Displays: 📊 Complexity: ⏱ O(n²) · 🧠 O(n) · ⚡ N bottleneck(s) · [View Report →]
    Clicking emits the clicked signal to navigate to the Optimization page.
    """
    clicked = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.setVisible(False)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        lay = QHBoxLayout(self)
        lay.setContentsMargins(12, 6, 12, 6)
        lay.setSpacing(10)

        lbl_icon = plain_label("📊 Complexity:", "Section")
        f = lbl_icon.font()
        f.setBold(True)
        lbl_icon.setFont(f)
        lay.addWidget(lbl_icon)

        self.lbl_time = plain_label("⏱ —", "Body")
        self.lbl_space = plain_label("🧠 —", "Body")
        self.lbl_bottlenecks = plain_label("⚡ —", "Body")
        self.lbl_action = plain_label("Click to view details →", "Muted")

        lay.addWidget(self.lbl_time)
        lay.addWidget(plain_label("·", "Muted"))
        lay.addWidget(self.lbl_space)
        lay.addWidget(plain_label("·", "Muted"))
        lay.addWidget(self.lbl_bottlenecks)
        lay.addStretch(1)
        lay.addWidget(self.lbl_action)

    def update_result(self, summary: dict):
        if not summary:
            return
        t_val = summary.get("time_complexity", "—")
        t_badge = summary.get("time_badge", "")
        s_val = summary.get("space_complexity", "—")
        s_badge = summary.get("space_badge", "")
        count = summary.get("bottleneck_count", 0)

        t_text = f"⏱ Time: {t_val}" + (f" ({t_badge})" if t_badge and t_badge != "UNKNOWN" else "")
        s_text = f"🧠 Space: {s_val}" + (f" ({s_badge})" if s_badge and s_badge != "UNKNOWN" else "")
        b_text = f"⚡ {count} bottleneck{'s' if count != 1 else ''}"

        self.lbl_time.setText(t_text)
        self.lbl_space.setText(s_text)
        self.lbl_bottlenecks.setText(b_text)
        self.lbl_action.setText("Click to view full optimization report →")
        self.setVisible(True)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)
