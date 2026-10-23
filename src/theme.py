"""
theme.py
--------
Single source of truth for the UI: design tokens (dark + light), one global
stylesheet, fonts, and a tiny theme manager.

Usage
-----
    import theme
    app = QApplication(sys.argv)
    theme.apply_theme(app, theme.load_saved_mode())   # at startup
    theme.toggle_theme(app)                           # from the theme button

Widgets are styled ONLY through objectName / dynamic properties, e.g.
    btn.setProperty("variant", "primary")
    frame.setObjectName("Card")
Never call setStyleSheet() on individual widgets. Custom-painted widgets
(code editor, graphs, syntax highlighter) must read colours from
theme.tokens() and register a repaint callback with theme.on_change().
"""
from __future__ import annotations

from string import Template

from PyQt6.QtCore import QSettings
from PyQt6.QtGui import QColor, QFont, QTextCharFormat
from PyQt6.QtWidgets import QApplication, QWidget

# ── Fonts ────────────────────────────────────────────────────────────────────
# Set through QFont (not QSS) so a fallback list really works in Qt 6.
UI_FAMILIES = ["Inter", "Segoe UI", "SF Pro Text", "Helvetica Neue", "Arial"]
MONO_FAMILIES = ["JetBrains Mono", "SF Mono", "Menlo", "Consolas", "Courier New"]


def ui_font(px: int = 13, bold: bool = False) -> QFont:
    f = QFont()
    f.setFamilies(UI_FAMILIES)
    f.setPixelSize(px)
    f.setWeight(QFont.Weight.DemiBold if bold else QFont.Weight.Normal)
    return f


def mono_font(px: int = 13, bold: bool = False) -> QFont:
    f = QFont()
    f.setFamilies(MONO_FAMILIES)
    f.setPixelSize(px)
    f.setStyleHint(QFont.StyleHint.Monospace)
    f.setWeight(QFont.Weight.DemiBold if bold else QFont.Weight.Normal)
    return f


# ── Design tokens ────────────────────────────────────────────────────────────
TOKENS = {
    "dark": dict(
        bg="#0E1117", surface="#151A23", surface_alt="#1B2230", border="#252D3B",
        text="#E6EAF2", muted="#8B95A7",
        accent="#6C7BFF", accent_hover="#8290FF", accent_soft="#1F2547", on_accent="#FFFFFF",
        error="#F2555A", warn="#E8B339", ok="#3DBE8B", info="#5AA9FF",
        error_soft="#2A1A1E", warn_soft="#2A2414", ok_soft="#14261F",
        editor_bg="#11161E", gutter_fg="#566074", current_line="#171D28",
        selection="#2A3566", error_line="#2A1A1E", fixed_line="#14261F",
        syn_keyword="#8E9BFF", syn_string="#7FD6A8", syn_number="#E8B339",
        syn_comment="#5E6A80", syn_preproc="#C792EA", syn_type="#5AA9FF",
        syn_plain="#E6EAF2",
    ),
    "light": dict(
        bg="#F6F8FB", surface="#FFFFFF", surface_alt="#F0F3F8", border="#E3E8EF",
        text="#1A1F36", muted="#5B6478",
        accent="#5469D4", accent_hover="#4457BF", accent_soft="#E8ECFB", on_accent="#FFFFFF",
        # slightly deeper status colours so they stay readable on white
        error="#D93B42", warn="#B7791F", ok="#1F9D6B", info="#2B7FD6",
        error_soft="#FCEBEC", warn_soft="#FBF3E2", ok_soft="#E5F6EE",
        editor_bg="#FFFFFF", gutter_fg="#9AA3B5", current_line="#F3F6FC",
        selection="#D6DEFA", error_line="#FCEBEC", fixed_line="#E5F6EE",
        syn_keyword="#5469D4", syn_string="#1F8A5B", syn_number="#B7791F",
        syn_comment="#8A93A6", syn_preproc="#8E44AD", syn_type="#2B7FD6",
        syn_plain="#1A1F36",
    ),
}

# ── Global stylesheet (string.Template: $name -> token) ──────────────────────
_QSS = Template("""
QWidget { color: $text; }
QMainWindow, QDialog, QWidget#Root { background: $bg; }
QLabel { background: transparent; }
QToolTip { background: $surface_alt; color: $text; border: 1px solid $border;
           padding: 4px 8px; }

/* ---------- surfaces ---------- */
QFrame#Card     { background: $surface; border: 1px solid $border; border-radius: 8px; }
QFrame#Sidebar  { background: $surface; border: none; border-right: 1px solid $border; }
QFrame#TopBar   { background: $surface; border: none; border-bottom: 1px solid $border; }
QFrame#StatusBar{ background: $surface; border: none; border-top: 1px solid $border; }
QFrame#Divider  { background: $border; border: none; max-height: 1px; min-height: 1px; }
QFrame#CodeBlock{ background: $editor_bg; border: 1px solid $border; border-radius: 6px; }
QFrame#AiCard   { background: $accent_soft; border: 1px solid $border; border-radius: 8px; }

/* issue cards: thin severity strip on the left */
QFrame#IssueCard, QFrame#SecurityFindingCard { background: $surface; border: 1px solid $border;
                   border-left: 3px solid $muted; border-radius: 8px; }
QFrame#IssueCard[sev="error"], QFrame#SecurityFindingCard[sev="critical"],
QFrame#SecurityFindingCard[sev="high"], QFrame#SecurityFindingCard[sev="error"] { border-left: 3px solid $error; }
QFrame#IssueCard[sev="warning"], QFrame#SecurityFindingCard[sev="medium"],
QFrame#SecurityFindingCard[sev="warn"], QFrame#SecurityFindingCard[sev="warning"] { border-left: 3px solid $warn; }
QFrame#IssueCard[sev="note"], QFrame#SecurityFindingCard[sev="low"],
QFrame#SecurityFindingCard[sev="note"], QFrame#SecurityFindingCard[sev="info"] { border-left: 3px solid $info; }
QFrame#IssueCard[selected="true"], QFrame#SecurityFindingCard[selected="true"] { background: $accent_soft; }

/* blocked banner: error accent border and soft error background */
QFrame#BlockedBanner { background: $error_soft; border: 1px solid $error; border-radius: 8px; }

/* ---------- text roles ---------- */
QLabel#Title      { font-size: 15px; font-weight: 600; }
QLabel#IssueTitle { font-size: 14px; font-weight: 600; }
QLabel#Section    { color: $muted; font-size: 11px; font-weight: 600; }
QLabel#Muted      { color: $muted; }
QLabel#CodeText   { color: $text; background: transparent; }
QLabel#Badge { background: $accent_soft; color: $accent; border-radius: 4px;
               padding: 2px 8px; font-size: 11px; font-weight: 600; }
QLabel#Badge[tone="error"] { background: $error_soft; color: $error; }
QLabel#Badge[tone="warn"]  { background: $warn_soft;  color: $warn; }
QLabel#Badge[tone="ok"]    { background: $ok_soft;    color: $ok; }
QLabel#Badge[tone="muted"] { background: $surface_alt; color: $muted; }

/* ---------- buttons ---------- */
QPushButton { background: $surface; color: $text; border: 1px solid $border;
              border-radius: 6px; padding: 7px 14px; font-weight: 500; }
QPushButton:hover    { background: $surface_alt; }
QPushButton:pressed  { background: $border; }
QPushButton:disabled { color: $muted; background: $bg; }
QPushButton[variant="primary"] { background: $accent; color: $on_accent; border: 1px solid $accent; }
QPushButton[variant="primary"]:hover { background: $accent_hover; border-color: $accent_hover; }
QPushButton[variant="success"] { background: $ok; color: #FFFFFF; border: 1px solid $ok; }
QPushButton[variant="ghost"]   { background: transparent; border: 1px solid transparent; padding: 6px 10px; }
QPushButton[variant="ghost"]:hover { background: $surface_alt; }

QPushButton#NavButton { text-align: left; background: transparent; border: none;
                        border-radius: 6px; padding: 9px 12px; color: $muted; }
QPushButton#NavButton:hover { background: $surface_alt; color: $text; }
QPushButton#NavButton[active="true"] { background: $accent_soft; color: $accent; font-weight: 600; }

QToolButton#SectionToggle { border: none; background: transparent; color: $muted;
                            font-weight: 600; text-align: left; padding: 4px 0; }
QToolButton#SectionToggle:hover { color: $text; }

/* ---------- tabs ---------- */
QTabWidget::pane { border: none; border-top: 1px solid $border; background: $surface; }
QTabBar { background: transparent; }
QTabBar::tab { background: transparent; color: $muted; padding: 8px 14px; border: none;
               border-bottom: 2px solid transparent; margin-right: 2px; }
QTabBar::tab:hover    { color: $text; }
QTabBar::tab:selected { color: $accent; border-bottom: 2px solid $accent; }

/* ---------- inputs / editors ---------- */
QPlainTextEdit, QTextEdit, QTextBrowser, QLineEdit {
    background: $surface; color: $text; border: 1px solid $border; border-radius: 6px;
    selection-background-color: $selection; selection-color: $text; padding: 6px; }
QLineEdit:focus, QTextEdit:focus { border: 1px solid $accent; }
QPlainTextEdit#Editor { background: $editor_bg; border: none; border-radius: 0; padding: 0; }
QTextEdit#Console, QTextBrowser#Console { background: $editor_bg; }
QCheckBox { spacing: 8px; }
QCheckBox::indicator { width: 16px; height: 16px; border: 1px solid $border;
                       border-radius: 4px; background: $surface; }
QCheckBox::indicator:checked { background: $accent; border-color: $accent; }

/* ---------- lists / trees ---------- */
QTreeWidget { background: $surface; alternate-background-color: $surface_alt;
              border: 1px solid $border; border-radius: 8px; }
QTreeWidget::item { padding: 4px; }
QTreeWidget::item:selected { background: $accent_soft; color: $accent; }
QHeaderView::section { background: $surface_alt; color: $muted; border: none;
                       border-bottom: 1px solid $border; padding: 8px; font-weight: 600; }

/* ---------- scroll ---------- */
QScrollArea { border: none; background: transparent; }
QScrollBar:vertical   { background: transparent; width: 10px; margin: 2px; }
QScrollBar:horizontal { background: transparent; height: 10px; margin: 2px; }
QScrollBar::handle:vertical   { background: $border; border-radius: 3px; min-height: 28px; }
QScrollBar::handle:horizontal { background: $border; border-radius: 3px; min-width: 28px; }
QScrollBar::handle:vertical:hover, QScrollBar::handle:horizontal:hover { background: $muted; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }

/* ---------- misc ---------- */
QSplitter::handle { background: $bg; }
QSplitter::handle:horizontal { width: 6px; }
QSplitter::handle:vertical   { height: 6px; }
QProgressBar { background: $surface_alt; border: none; border-radius: 5px;
               min-height: 10px; max-height: 10px; text-align: center; }
QProgressBar::chunk { background: $accent; border-radius: 5px; }
""")

# ── Theme manager ────────────────────────────────────────────────────────────
_mode = "dark"
_listeners: list = []


def mode() -> str:
    return _mode


def tokens(which: str | None = None) -> dict:
    return TOKENS[which or _mode]


def qcolor(name: str) -> QColor:
    return QColor(TOKENS[_mode][name])


def on_change(callback) -> None:
    """callback(mode: str, tokens: dict) is called after every theme switch."""
    _listeners.append(callback)


def load_saved_mode() -> str:
    saved = QSettings("CppExplainer", "App").value("theme", "dark")
    return saved if saved in TOKENS else "dark"


def apply_theme(app: QApplication, new_mode: str | None = None) -> None:
    global _mode
    if new_mode in TOKENS:
        _mode = new_mode
    app.setFont(ui_font(13))
    app.setStyleSheet(_QSS.substitute(TOKENS[_mode]))
    QSettings("CppExplainer", "App").setValue("theme", _mode)
    for cb in list(_listeners):
        try:
            cb(_mode, TOKENS[_mode])
        except Exception:
            pass


def toggle_theme(app: QApplication) -> str:
    apply_theme(app, "light" if _mode == "dark" else "dark")
    return _mode


# ── Helpers ──────────────────────────────────────────────────────────────────
def repolish(widget: QWidget) -> None:
    """Re-evaluate the stylesheet after a dynamic property changed."""
    widget.style().unpolish(widget)
    widget.style().polish(widget)
    widget.update()


def set_prop(widget: QWidget, name: str, value) -> None:
    widget.setProperty(name, value)
    repolish(widget)


def sev_color(severity: str) -> QColor:
    key = {"error": "error", "warning": "warn", "note": "info"}.get(
        (severity or "").lower(), "muted")
    return qcolor("muted" if key == "muted" else key)


def syntax_format(kind: str, bold: bool = False) -> QTextCharFormat:
    """kind: keyword | string | number | comment | preproc | type | plain"""
    fmt = QTextCharFormat()
    fmt.setForeground(QColor(TOKENS[_mode]["syn_" + kind]))
    if bold:
        fmt.setFontWeight(QFont.Weight.DemiBold)
    return fmt
