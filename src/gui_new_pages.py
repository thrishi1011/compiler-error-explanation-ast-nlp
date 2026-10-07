"""
gui_new_pages.py
----------------
Contains SecondOpinionPage (Feature 2) and BenchmarkPage (Feature 4).
Imported by gui.py to keep the change diff small.
"""

from __future__ import annotations

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QProgressBar, QScrollArea, QMessageBox
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont

# Import GUI constants from gui.py at runtime (avoids circular import)
def _c(name):
    import gui as _gui
    return getattr(_gui, name)


def _BG():        return _c("BG_COLOR")
def _PANE():      return _c("PANE_BG")
def _HEADER():    return _c("HEADER_BG")
def _BORDER():    return _c("BORDER_COLOR")
def _PINK():      return _c("PINK")
def _TEXT():      return _c("TEXT_MAIN")
def _DIM():       return _c("TEXT_DIM")
def _GREEN():     return _c("GREEN")
def _RED():       return _c("RED")
def _YELLOW():    return _c("YELLOW")
def _FF():        return _c("FONT_FAMILY")


# ── Feature 2: Second Opinion Page ───────────────────────────────────────────

class SecondOpinionPage(QWidget):
    """
    Displays a two-classifier comparison for the most-recent compiler error.

    Two independent methods classify every error:
      • Regex classifier  — keyword rules, no training needed
      • ML classifier     — TF-IDF + Logistic Regression (offline model)

    When both agree: one confident answer is shown.
    When they disagree: the top N candidates (blended score) are surfaced so
    the user sees the doubt instead of a silently wrong answer.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(14)

        title = QLabel("SECOND OPINION  ·  CLASSIFIER COMPARISON")
        title.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
        title.setStyleSheet("color: #5469d4; padding-bottom: 4px;")
        root.addWidget(title)

        intro = QLabel(
            "Two independent methods classify every error. "
            "When they agree the app is confident. "
            "When they disagree the top candidates are shown instead of hiding the doubt."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet("color: #4f566b; font-size: 12px;")
        root.addWidget(intro)

        # Method comparison cards
        card_row = QHBoxLayout()
        card_row.setSpacing(12)
        self._regex_card = self._make_method_card("Regex Classifier",
                                                  "Rule-based keyword matching")
        self._ml_card    = self._make_method_card("ML Classifier",
                                                  "TF-IDF + Logistic Regression")
        card_row.addWidget(self._regex_card["frame"], 1)
        card_row.addWidget(self._ml_card["frame"],    1)
        root.addLayout(card_row)

        # Verdict banner
        self._verdict_frame = QFrame()
        self._verdict_frame.setStyleSheet(
            "QFrame { background-color: #f4f7f9; border: 1px solid #e6ebf1; "
            "border-radius: 8px; }"
        )
        vl = QVBoxLayout(self._verdict_frame)
        vl.setContentsMargins(14, 12, 14, 12)
        self._verdict_label = QLabel("Compile a file to see the second opinion.")
        self._verdict_label.setWordWrap(True)
        self._verdict_label.setFont(QFont("Consolas", 12, QFont.Weight.Bold))
        self._verdict_label.setStyleSheet("color: #5469d4;")
        self._verdict_label.setTextFormat(Qt.TextFormat.RichText)
        vl.addWidget(self._verdict_label)
        root.addWidget(self._verdict_frame)

        # Candidates frame (only shown when methods disagree)
        cand_outer = QFrame()
        cand_outer.setStyleSheet(
            "QFrame { background-color: #ffffff; border: 1px solid #e6ebf1; "
            "border-radius: 8px; }"
        )
        self._cand_layout = QVBoxLayout(cand_outer)
        self._cand_layout.setContentsMargins(14, 10, 14, 10)
        self._cand_layout.setSpacing(6)
        cand_title = QLabel("TOP CANDIDATES  (blended score)")
        cand_title.setFont(QFont("Consolas", 9, QFont.Weight.Bold))
        cand_title.setStyleSheet("color: #4f566b;")
        self._cand_layout.addWidget(cand_title)
        self._cand_body = QVBoxLayout()
        self._cand_body.setSpacing(4)
        self._cand_layout.addLayout(self._cand_body)
        self._cand_outer = cand_outer
        self._cand_outer.setVisible(False)
        root.addWidget(self._cand_outer)

        root.addStretch()

    # ── helpers ──────────────────────────────────────────────────────────────

    def _make_method_card(self, title: str, subtitle: str) -> dict:
        frame = QFrame()
        frame.setStyleSheet(
            "QFrame { background-color: #ffffff; border: 1px solid #e6ebf1; "
            "border-radius: 8px; }"
        )
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(4)

        t = QLabel(title)
        t.setFont(QFont("Consolas", 10, QFont.Weight.Bold))
        t.setStyleSheet("color: #5469d4;")
        lay.addWidget(t)

        s = QLabel(subtitle)
        s.setStyleSheet("color: #4f566b; font-size: 10px;")
        lay.addWidget(s)

        pred = QLabel("—")
        pred.setFont(QFont("Consolas", 14, QFont.Weight.Bold))
        pred.setStyleSheet("color: #1a1f36; margin-top: 8px;")
        lay.addWidget(pred)

        bar = QProgressBar()
        bar.setRange(0, 100)
        bar.setValue(0)
        bar.setTextVisible(True)
        bar.setFixedHeight(14)
        bar.setFormat("%p%")
        bar.setStyleSheet(
            "QProgressBar { background-color: #f4f7f9; border: 1px solid #e6ebf1; "
            "border-radius: 6px; }"
            "QProgressBar::chunk { background-color: #5469d4; border-radius: 6px; }"
        )
        lay.addWidget(bar)
        return {"frame": frame, "pred": pred, "bar": bar}

    def _clear_candidates(self):
        while self._cand_body.count():
            item = self._cand_body.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    # ── public API ───────────────────────────────────────────────────────────

    def show_opinion(self, error_message: str, ast_node: str = ""):
        """Run second opinion on error_message and update the display."""
        if not error_message:
            self._verdict_label.setText("Compile a file to see the second opinion.")
            self._regex_card["pred"].setText("—")
            self._ml_card["pred"].setText("—")
            self._regex_card["bar"].setValue(0)
            self._ml_card["bar"].setValue(0)
            self._cand_outer.setVisible(False)
            return

        try:
            from second_opinion import get_second_opinion
            result = get_second_opinion(error_message, ast_node)
        except Exception as exc:
            self._verdict_label.setText(f"Error: {exc}")
            return

        # Method cards
        self._regex_card["pred"].setText(result.regex_top)
        self._regex_card["bar"].setValue(int(result.regex_score * 100))

        if result.ml_top:
            self._ml_card["pred"].setText(result.ml_top)
            self._ml_card["bar"].setValue(int(result.ml_score * 100))
        else:
            self._ml_card["pred"].setText("Not available")
            self._ml_card["bar"].setValue(0)

        # Verdict banner
        if result.agreed:
            bg, border = "#efffef", "#24b47e"
            icon = "&#x2705;"   # ✅
        else:
            bg, border = "#fff8ec", "#ffcc00"
            icon = "&#x26A0;&#xFE0F;"  # ⚠️

        self._verdict_frame.setStyleSheet(
            f"QFrame {{ background-color: {bg}; border: 2px solid {border}; "
            f"border-radius: 8px; }}"
        )
        final_pct = int(result.final_confidence * 100)
        self._verdict_label.setText(
            f"{icon}&nbsp;&nbsp;{result.note}"
            f"&nbsp;&mdash;&nbsp;final answer:&nbsp;"
            f"<b>{result.final_category}</b>&nbsp;({final_pct}%)"
        )

        # Candidates
        self._clear_candidates()
        if not result.agreed and result.candidates:
            self._cand_outer.setVisible(True)
            for i, cand in enumerate(result.candidates):
                row = QHBoxLayout()
                cat_lbl = QLabel(f"{i+1}. {cand['category']}")
                cat_lbl.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
                cat_lbl.setStyleSheet(
                    "color: #5469d4;" if i == 0 else "color: #1a1f36;"
                )
                row.addWidget(cat_lbl, 3)
                for val_key, label in [
                    ("regex_score", "Regex"),
                    ("ml_score",    "ML"),
                    ("blended",     "Blended"),
                ]:
                    val = cand.get(val_key, 0.0)
                    lbl = QLabel(f"{label}: {val:.0%}")
                    lbl.setStyleSheet("color: #4f566b; font-size: 11px;")
                    row.addWidget(lbl, 1)
                self._cand_body.addLayout(row)
        else:
            self._cand_outer.setVisible(False)

    def clear(self):
        self.show_opinion("")


# ── Feature 4: Benchmark Page ─────────────────────────────────────────────────

class BenchmarkPage(QWidget):
    """
    Runs the three-method accuracy benchmark and shows a live-updating table.

    Three methods compared:
      A. Regex-only          — keyword rules, zero training
      B. ML-only             — TF-IDF + Logistic Regression offline model
      C. Combined (A + B)    — second_opinion.get_second_opinion() final_category

    A progress bar fills as each test file is processed.
    Results table shows ✓/✗ per file per method.
    Bottom summary: overall accuracy % for each method.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._worker = None

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(14)

        title = QLabel("ACCURACY BENCHMARK  ·  THREE-METHOD COMPARISON")
        title.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
        title.setStyleSheet("color: #5469d4; padding-bottom: 4px;")
        root.addWidget(title)

        intro = QLabel(
            "Runs every labelled test file through three independent classifiers "
            "and compares their accuracy side-by-side. "
            "Fully offline — uses g++ and the local ML model."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet("color: #4f566b; font-size: 12px;")
        root.addWidget(intro)

        # Summary score cards
        score_row = QHBoxLayout()
        score_row.setSpacing(10)
        self._regex_card = self._make_score_card("Regex Classifier", "—")
        self._ml_card    = self._make_score_card("ML Classifier",    "—")
        self._combo_card = self._make_score_card("Combined Method",  "—")
        score_row.addWidget(self._regex_card["frame"], 1)
        score_row.addWidget(self._ml_card["frame"],    1)
        score_row.addWidget(self._combo_card["frame"], 1)
        root.addLayout(score_row)

        # Progress bar
        self._progress = QProgressBar()
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._progress.setTextVisible(True)
        self._progress.setFormat("Press RUN BENCHMARK to start")
        self._progress.setFixedHeight(18)
        self._progress.setStyleSheet(
            "QProgressBar { background-color: #f4f7f9; border: 1px solid #e6ebf1; "
            "border-radius: 8px; }"
            "QProgressBar::chunk { background-color: #5469d4; border-radius: 8px; }"
        )
        root.addWidget(self._progress)

        # Run button (plain QPushButton so no circular import needed)
        from PyQt6.QtWidgets import QPushButton
        btn = QPushButton(" ▶  RUN BENCHMARK ")
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
        btn.setStyleSheet(
            "QPushButton { background-color: #5469d4; color: white; border: none; "
            "border-radius: 6px; padding: 8px 18px; }"
            "QPushButton:hover { background-color: #6578e0; }"
            "QPushButton:pressed { background-color: #4356c0; }"
        )
        btn.clicked.connect(self._start)
        root.addWidget(btn, 0, Qt.AlignmentFlag.AlignLeft)

        # Results table inside a scroll area
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setStyleSheet(
            "QScrollArea { border: 1px solid #e6ebf1; "
            "background-color: #ffffff; border-radius: 6px; }"
        )
        self._table_host = QWidget()
        self._table_host.setStyleSheet("QWidget { background-color: transparent; }")
        self._table_vbox = QVBoxLayout(self._table_host)
        self._table_vbox.setContentsMargins(8, 8, 8, 8)
        self._table_vbox.setSpacing(2)
        self._table_vbox.setAlignment(Qt.AlignmentFlag.AlignTop)
        self._scroll.setWidget(self._table_host)
        root.addWidget(self._scroll, 1)

        self._show_placeholder()

    # ── helpers ──────────────────────────────────────────────────────────────

    def _make_score_card(self, title: str, value: str) -> dict:
        frame = QFrame()
        frame.setStyleSheet(
            "QFrame { background-color: #ffffff; border: 1px solid #e6ebf1; "
            "border-radius: 8px; }"
        )
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(2)
        t = QLabel(title)
        t.setStyleSheet("color: #4f566b; font-size: 10px; font-weight: bold;")
        lay.addWidget(t)
        v = QLabel(value)
        v.setFont(QFont("Consolas", 22, QFont.Weight.Bold))
        v.setStyleSheet("color: #5469d4;")
        lay.addWidget(v)
        return {"frame": frame, "val": v}

    def _clear_table(self):
        while self._table_vbox.count():
            item = self._table_vbox.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def _show_placeholder(self):
        self._clear_table()
        lbl = QLabel("Press RUN BENCHMARK to start.")
        lbl.setStyleSheet("color: #4f566b; font-size: 12px; padding: 20px;")
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._table_vbox.addWidget(lbl)

    def _make_header_row(self) -> QWidget:
        row = QWidget()
        row.setStyleSheet("background-color: #f4f7f9; border-radius: 4px;")
        hl = QHBoxLayout(row)
        hl.setContentsMargins(8, 6, 8, 6)
        hl.setSpacing(0)
        for text, stretch in [
            ("File", 5), ("Expected Category", 4),
            ("Regex", 1), ("ML", 1), ("Combined", 1),
        ]:
            lbl = QLabel(text)
            lbl.setFont(QFont("Consolas", 9, QFont.Weight.Bold))
            lbl.setStyleSheet("color: #5469d4;")
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter if stretch == 1
                             else Qt.AlignmentFlag.AlignLeft)
            hl.addWidget(lbl, stretch)
        return row

    def _make_result_row(self, file_result) -> QWidget:
        row = QWidget()
        hl = QHBoxLayout(row)
        hl.setContentsMargins(8, 4, 8, 4)
        hl.setSpacing(0)

        fname = QLabel(file_result.filename)
        fname.setStyleSheet("color: #1a1f36; font-size: 11px;")
        hl.addWidget(fname, 5)

        exp = QLabel(file_result.expected)
        exp.setStyleSheet("color: #4f566b; font-size: 11px;")
        hl.addWidget(exp, 4)

        for ok in [file_result.regex_ok, file_result.ml_ok, file_result.combo_ok]:
            icon  = "✓" if ok else "✗"
            color = "#24b47e" if ok else "#d12441"
            lbl = QLabel(icon)
            lbl.setStyleSheet(f"color: {color}; font-size: 13px; font-weight: bold;")
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            hl.addWidget(lbl, 1)

        return row

    # ── slots ─────────────────────────────────────────────────────────────────

    def _start(self):
        if self._worker and self._worker.isRunning():
            return

        try:
            from accuracy_benchmark import BenchmarkWorker
        except ImportError:
            QMessageBox.warning(
                self, "Benchmark",
                "accuracy_benchmark.py not found in the src/ directory."
            )
            return

        self._clear_table()
        placeholder = QLabel("Running benchmark … please wait.")
        placeholder.setStyleSheet("color: #4f566b; font-size: 12px; padding: 20px;")
        placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._table_vbox.addWidget(placeholder)

        self._progress.setValue(0)
        self._progress.setFormat("Starting …")

        self._worker = BenchmarkWorker()
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_finished)
        self._worker.start()

    def _on_progress(self, done: int, total: int, fname: str):
        if total > 0:
            self._progress.setValue(int(100 * done / total))
            self._progress.setFormat(f"Testing {fname}  ({done}/{total})")

    def _on_finished(self, results: dict):
        self._progress.setValue(100)
        self._progress.setFormat("Done!")

        # Update summary cards
        self._regex_card["val"].setText(f"{results['regex_pct']:.1f}%")
        self._ml_card["val"].setText(f"{results['ml_pct']:.1f}%")
        self._combo_card["val"].setText(f"{results['combo_pct']:.1f}%")

        # Rebuild table
        self._clear_table()
        self._table_vbox.addWidget(self._make_header_row())

        for file_result in results["rows"]:
            self._table_vbox.addWidget(self._make_result_row(file_result))

        # Separator
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color: #e6ebf1;")
        self._table_vbox.addWidget(sep)

        # Totals row
        tot_widget = QWidget()
        tot_widget.setStyleSheet("background-color: #f4f7f9; border-radius: 4px;")
        tot_hl = QHBoxLayout(tot_widget)
        tot_hl.setContentsMargins(8, 6, 8, 6)
        tot_hl.setSpacing(0)
        tot_lbl = QLabel(f"<b>TOTAL CORRECT  ({results['total']} files)</b>")
        tot_lbl.setStyleSheet("color: #1a1f36; font-size: 11px;")
        tot_hl.addWidget(tot_lbl, 9)
        for correct in [
            results["regex_correct"],
            results["ml_correct"],
            results["combo_correct"],
        ]:
            pct_lbl = QLabel(f"{correct}/{results['total']}")
            pct_lbl.setFont(QFont("Consolas", 10, QFont.Weight.Bold))
            pct_lbl.setStyleSheet("color: #5469d4;")
            pct_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            tot_hl.addWidget(pct_lbl, 1)
        self._table_vbox.addWidget(tot_widget)
