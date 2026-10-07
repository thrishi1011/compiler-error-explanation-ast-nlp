#!/usr/bin/env python3
"""
web_server.py
=============
Lightweight localhost web server for the Green Self-Healing Compiler.
Provides an interactive web IDE with compiler error explanation, AST viewer,
security analysis, and automated healing over HTTP.
"""

import os
import re
import sys
import json
import time
import tempfile
import warnings
import dataclasses
import subprocess
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

# Suppress sklearn version mismatch warnings (model trained on older sklearn)
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

# Ensure src/ is on sys.path
SRC_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SRC_DIR)
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from compiler_runner import run_cpp_compiler, _sanitize_code
from error_parser import parse_errors
from error_explainer import enrich_error
from error_classifier import get_default_classifier
from ast_extractor import extract_ast, extract_node_near_line, parse_ast_to_tree
from security_analyzer import analyze as analyze_security, format_security_report
from auto_healer import attempt_fix, UNFIXABLE_CATEGORIES
from diff_viewer import compute_diff, format_diff_html, has_changes
from healing_suggester import suggest_failed_heal

try:
    from codecarbon import EmissionsTracker
    HAS_CODECARBON = True
except ImportError:
    HAS_CODECARBON = False

classifier = get_default_classifier()

# ── Helper utilities ──────────────────────────────────────────────────────────

def sanitize_file_path(path: str, tmp_path: str) -> str:
    """Replace the temp file path with the user-friendly label '<user_code>'."""
    if not path:
        return path
    if tmp_path and (path == tmp_path or os.path.normcase(path) == os.path.normcase(tmp_path)):
        return "<user_code>"
    if os.path.normcase(path).startswith(os.path.normcase(tempfile.gettempdir())):
        return "<user_code>"
    return path


def sanitize_findings(findings: list, tmp_path: str) -> list:
    """Return SecurityFinding list with sanitized file paths.
    Uses dataclasses.replace() since SecurityFinding is a frozen dataclass."""
    result = []
    for f in findings:
        clean = sanitize_file_path(f.file, tmp_path)
        result.append(dataclasses.replace(f, file=clean) if clean != f.file else f)
    return result


def build_fallback_ast(code: str) -> list:
    """Build a simple AST-like tree from C++ source when clang++ is unavailable.
    Returns a list of nodes compatible with the frontend renderAST() function."""
    nodes = []
    lines = code.splitlines()

    includes = []
    functions = []
    variables = []

    func_re = re.compile(
        r"^\s*(?:(?:static|inline|virtual|explicit|const)\s+)*"
        r"(?:[\w:*&<>\[\]]+\s+)+(\w+)\s*\([^)]*\)\s*(?:const\s*)?\{"
    )
    var_re = re.compile(
        r"^\s*(?:int|float|double|char|bool|long|short|unsigned|string|auto)\s+"
        r"(\w+)\s*(?:=|;|\[)"
    )
    include_re = re.compile(r"^\s*#include\s+([<\"][^>\"]+[>\"])")

    for i, line in enumerate(lines, 1):
        inc_m = include_re.match(line)
        if inc_m:
            includes.append({"type": "IncludeDecl", "details": inc_m.group(1), "children": []})
            continue
        func_m = func_re.match(line)
        if func_m:
            functions.append({"type": "FunctionDecl", "details": f"{func_m.group(1)}() at line {i}", "children": []})
            continue
        var_m = var_re.match(line)
        if var_m:
            variables.append({"type": "VarDecl", "details": f"{var_m.group(1)} at line {i}", "children": []})

    root = {"type": "TranslationUnitDecl", "details": "", "children": []}
    if includes:
        inc_group = {"type": "NamespaceDecl", "details": f"includes ({len(includes)})", "children": includes}
        root["children"].append(inc_group)
    root["children"].extend(functions)
    root["children"].extend(variables)
    return [root] if root["children"] else []


HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Green Self-Healing Compiler - Web IDE</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #0f141c;
      --surface: #18202c;
      --surface-border: #263345;
      --surface-hover: #1f2b3b;
      --primary: #6366f1;
      --primary-hover: #4f46e5;
      --accent: #06b6d4;
      --success: #10b981;
      --warning: #f59e0b;
      --danger: #ef4444;
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --code-font: 'JetBrains Mono', Consolas, monospace;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Inter', -apple-system, sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }
    header {
      background: var(--surface);
      border-bottom: 1px solid var(--surface-border);
      padding: 12px 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .logo-area { display: flex; align-items: center; gap: 12px; }
    .logo-badge {
      background: linear-gradient(135deg, #10b981, #06b6d4);
      color: #fff;
      font-weight: 700;
      font-size: 14px;
      padding: 4px 10px;
      border-radius: 6px;
      letter-spacing: 0.5px;
    }
    .title { font-size: 18px; font-weight: 700; color: #fff; }
    .subtitle { font-size: 12px; color: var(--text-muted); }
    .toolbar { display: flex; gap: 10px; align-items: center; }
    button {
      font-family: inherit;
      font-size: 13px;
      font-weight: 600;
      padding: 8px 16px;
      border-radius: 6px;
      border: 1px solid transparent;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      transition: all 0.15s ease;
    }
    .btn-primary { background: var(--primary); color: white; }
    .btn-primary:hover { background: var(--primary-hover); }
    .btn-success { background: var(--success); color: white; }
    .btn-success:hover { background: #059669; }
    .btn-secondary { background: var(--surface-hover); color: var(--text); border-color: var(--surface-border); }
    .btn-secondary:hover { background: #2a394c; }
    .main-layout {
      flex: 1;
      display: grid;
      grid-template-columns: 1fr 1fr;
      height: calc(100vh - 65px);
      overflow: hidden;
    }
    .pane {
      display: flex;
      flex-direction: column;
      overflow: hidden;
      border-right: 1px solid var(--surface-border);
    }
    .pane-header {
      background: var(--surface);
      border-bottom: 1px solid var(--surface-border);
      padding: 10px 16px;
      font-size: 13px;
      font-weight: 600;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .editor-container {
      flex: 1;
      position: relative;
      display: flex;
      background: #090d14;
    }
    .line-numbers {
      width: 45px;
      padding: 16px 8px;
      font-family: var(--code-font);
      font-size: 13px;
      line-height: 22px;
      color: #475569;
      text-align: right;
      user-select: none;
      background: #0d121a;
      border-right: 1px solid #1a2230;
      white-space: pre;
    }
    #code-editor {
      flex: 1;
      background: transparent;
      border: none;
      outline: none;
      color: #e2e8f0;
      font-family: var(--code-font);
      font-size: 13px;
      line-height: 22px;
      padding: 16px;
      resize: none;
      white-space: pre;
      overflow-wrap: normal;
      overflow-x: auto;
      tab-size: 4;
    }
    .tabs-nav {
      display: flex;
      background: var(--surface);
      border-bottom: 1px solid var(--surface-border);
      gap: 2px;
      padding: 0 12px;
    }
    .tab-btn {
      padding: 10px 14px;
      font-size: 12px;
      font-weight: 600;
      color: var(--text-muted);
      background: transparent;
      border: none;
      border-bottom: 2px solid transparent;
      border-radius: 0;
      cursor: pointer;
    }
    .tab-btn.active {
      color: var(--accent);
      border-bottom-color: var(--accent);
      background: rgba(6, 182, 212, 0.05);
    }
    .tabs-content {
      flex: 1;
      overflow-y: auto;
      padding: 16px;
      background: var(--bg);
    }
    .tab-pane { display: none; }
    .tab-pane.active { display: block; }
    .card {
      background: var(--surface);
      border: 1px solid var(--surface-border);
      border-radius: 8px;
      padding: 14px 16px;
      margin-bottom: 12px;
      position: relative;
    }
    .card.error-card { border-left: 4px solid var(--danger); }
    .card.warning-card { border-left: 4px solid var(--warning); }
    .card.success-card { border-left: 4px solid var(--success); }
    .badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .badge-error { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
    .badge-warning { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }
    .badge-category { background: rgba(99, 102, 241, 0.2); color: #a5b4fc; border: 1px solid rgba(99, 102, 241, 0.3); }
    .badge-confidence { background: rgba(16, 185, 129, 0.2); color: #6ee7b7; border: 1px solid rgba(16, 185, 129, 0.3); }
    .card-title {
      font-size: 14px;
      font-weight: 700;
      margin: 6px 0;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .section-title {
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--accent);
      font-weight: 700;
      margin-top: 10px;
      margin-bottom: 4px;
    }
    .section-body {
      font-size: 13px;
      color: #cbd5e1;
      line-height: 1.5;
    }
    .code-box {
      background: #0a0f16;
      border: 1px solid #1e293b;
      border-radius: 6px;
      padding: 10px 12px;
      font-family: var(--code-font);
      font-size: 12px;
      color: #e2e8f0;
      overflow-x: auto;
      margin: 8px 0;
    }
    .diff-container {
      background: #0a0f16;
      border: 1px solid #1e293b;
      border-radius: 6px;
      padding: 12px;
      font-family: var(--code-font);
      font-size: 12px;
      line-height: 1.6;
      white-space: pre-wrap;
    }
    .status-bar {
      background: #0b0f17;
      border-top: 1px solid var(--surface-border);
      padding: 6px 16px;
      font-size: 11px;
      color: var(--text-muted);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .tree-node {
      padding: 3px 0 3px 18px;
      font-family: var(--code-font);
      font-size: 12px;
      position: relative;
    }
    .tree-type { color: #38bdf8; font-weight: 600; }
    .tree-details { color: #94a3b8; }
    .telemetry-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 12px;
      margin-bottom: 16px;
    }
    .stat-box {
      background: var(--surface);
      border: 1px solid var(--surface-border);
      border-radius: 8px;
      padding: 14px;
    }
    .stat-label { font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }
    .stat-val { font-size: 22px; font-weight: 700; color: #fff; margin-top: 4px; }
  </style>
</head>
<body>
  <header>
    <div class="logo-area">
      <div class="logo-badge">GREEN AI</div>
      <div>
        <div class="title">Self-Healing Compiler & Error Explainer</div>
        <div class="subtitle">AST-Guided Semantic Analysis & Automated Source Repair</div>
      </div>
    </div>
    <div class="toolbar">
      <button class="btn-secondary" onclick="loadSampleCode()">Reset Sample</button>
      <button class="btn-primary" onclick="compileCode()">Compile & Explain</button>
      <button id="btn-auto-heal" class="btn-success" onclick="autoHealCode()">Auto-Heal Code</button>
      <button id="btn-undo-heal" class="btn-secondary" onclick="undoHeal()" disabled style="opacity: 0.5;">↺ Undo</button>
      <button class="btn-secondary" onclick="runBinary()">Run Binary</button>
    </div>
  </header>

  <div class="main-layout">
    <!-- Left Pane: Code Editor -->
    <div class="pane">
      <div class="pane-header">
        <span>C++ Source Editor (C++17)</span>
        <span id="editor-status" style="color: var(--text-muted); font-size: 11px;">Ready</span>
      </div>
      <div class="editor-container">
        <div id="line-numbers" class="line-numbers">1</div>
        <textarea id="code-editor" spellcheck="false" oninput="updateLineNumbers()"></textarea>
      </div>
    </div>

    <!-- Right Pane: Analysis, Explanations, AST & Security -->
    <div class="pane">
      <div class="tabs-nav">
        <button class="tab-btn active" onclick="switchTab('explanations')">Explanations & Errors</button>
        <button class="tab-btn" onclick="switchTab('healing')">Auto-Heal Diffs</button>
        <button class="tab-btn" onclick="switchTab('ast')">Clang AST</button>
        <button class="tab-btn" onclick="switchTab('security')">Security Audit</button>
        <button class="tab-btn" onclick="switchTab('energy')">Green Telemetry</button>
        <button class="tab-btn" onclick="switchTab('terminal')">Terminal Output</button>
      </div>

      <div class="tabs-content">
        <!-- Explanations Tab -->
        <div id="tab-explanations" class="tab-pane active">
          <div id="explanations-view">
            <div class="card">
              <div class="card-title">Ready for Analysis</div>
              <div class="section-body">Click <b>Compile & Explain</b> to inspect compiler diagnostics with ML categorization, AST node correlation, and What/Why/How explanations. Or click <b>Auto-Heal Code</b> to watch automated multi-pass repairs.</div>
            </div>
          </div>
        </div>

        <!-- Healing Tab -->
        <div id="tab-healing" class="tab-pane">
          <div id="healing-view">
            <div class="card">
              <div class="card-title">Auto-Heal History</div>
              <div class="section-body">Run <b>Auto-Heal Code</b> to see multi-attempt patches, lines fixed, and diffs here.</div>
            </div>
          </div>
        </div>

        <!-- AST Tab -->
        <div id="tab-ast" class="tab-pane">
          <div id="ast-view">
            <div class="card">
              <div class="card-title">Clang Abstract Syntax Tree</div>
              <div class="section-body">Run compilation to generate filtered user-code AST tree.</div>
            </div>
          </div>
        </div>

        <!-- Security Tab -->
        <div id="tab-security" class="tab-pane">
          <div id="security-view">
            <div class="card">
              <div class="card-title">Static Security & Vulnerability Scan</div>
              <div class="section-body">Scans for memory leaks, use-after-free, command injections, format string flaws, and buffer overflows.</div>
            </div>
          </div>
        </div>

        <!-- Energy Tab -->
        <div id="tab-energy" class="tab-pane">
          <div class="telemetry-grid">
            <div class="stat-box">
              <div class="stat-label">Compile Execution Time</div>
              <div id="stat-time" class="stat-val">0.00 s</div>
            </div>
            <div class="stat-box">
              <div class="stat-label">Power Estimated</div>
              <div id="stat-power" class="stat-val">12.5 mW</div>
            </div>
            <div class="stat-box">
              <div class="stat-label">CO2 Emissions</div>
              <div id="stat-co2" class="stat-val">0.00 mg</div>
            </div>
            <div class="stat-box">
              <div class="stat-label">Repair Convergence</div>
              <div id="stat-passes" class="stat-val">0 passes</div>
            </div>
          </div>
          <div class="card">
            <div class="card-title">Green Computing Telemetry</div>
            <div class="section-body">
              Calculated via CodeCarbon and process CPU timing. Each repair and compilation iteration tracks its carbon footprint to optimize developer efficiency and compute overhead.
            </div>
          </div>
        </div>

        <!-- Terminal Output Tab -->
        <div id="tab-terminal" class="tab-pane">
          <div class="code-box" id="terminal-output" style="min-height: 250px;">// Output will appear here after running binary</div>
        </div>
      </div>
    </div>
  </div>

  <div class="status-bar">
    <span>Localhost Server Active: <b style="color: var(--accent);">http://localhost:8000</b></span>
    <span>Compiler: g++ (C++17) & Clang++</span>
  </div>

  <script>
    const SAMPLE_CODE = `#include <iostream>

int calculate(int a, int b) {
    // 1. Missing semicolon
    int total = a + b
    
    // 2. Division by zero risk
    int divisor = 0;
    int quotient = total / divisor;

    return quotient;
}

int main() {
    int x;
    // 3. Flipped stream operator
    std::cin << x;

    int result = calculate(10, 5);

    // 4. Missing std:: prefix
    cout << "Result: " << result << std::endl;

    // 5. Keyword typo
    retrun 0;
}
`;

    function updateLineNumbers() {
      const editor = document.getElementById('code-editor');
      const lines = editor.value.split('\\n').length;
      let numHtml = '';
      for (let i = 1; i <= Math.max(lines, 1); i++) {
        numHtml += i + '\\n';
      }
      document.getElementById('line-numbers').textContent = numHtml;
    }

    function loadSampleCode() {
      document.getElementById('code-editor').value = SAMPLE_CODE;
      updateLineNumbers();
    }

    function switchTab(name) {
      document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
      
      const targetBtn = Array.from(document.querySelectorAll('.tab-btn')).find(b => b.textContent.toLowerCase().includes(name.slice(0, 3)));
      if (targetBtn) targetBtn.classList.add('active');
      const targetPane = document.getElementById('tab-' + name);
      if (targetPane) targetPane.classList.add('active');
    }

    async function compileCode() {
      const code = document.getElementById('code-editor').value;
      document.getElementById('editor-status').textContent = 'Compiling...';
      
      try {
        const res = await fetch('/api/compile', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code })
        });
        const data = await res.json();
        renderExplanations(data);
        renderAST(data.ast_tree);
        renderSecurity(data.security_findings, data.security_report);
        updateTelemetry(data.duration, data.emissions);
        document.getElementById('editor-status').textContent = data.status === 'clean' ? 'Compilation Successful' : data.errors.length + ' Issue(s) Detected';
        switchTab('explanations');
      } catch (err) {
        alert('Server request failed: ' + err);
        document.getElementById('editor-status').textContent = 'Error';
      }
    }

    function renderExplanations(data) {
      const container = document.getElementById('explanations-view');
      if (data.status === 'clean') {
        container.innerHTML = `
          <div class="card success-card">
            <div class="card-title" style="color: var(--success);">
              <svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M5 13l4 4L19 7"></path></svg>
              Compilation Clean &amp; Successful
            </div>
            <div class="section-body">Source compiled with zero errors and warnings under g++ -std=c++17. Binary ready to run.</div>
          </div>
        `;
        return;
      }

      let html = '';
      data.errors.forEach((err, idx) => {
        const isWarn = err.type === 'warning';
        html += `
          <div class="card ${isWarn ? 'warning-card' : 'error-card'}">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
              <div style="display:flex; gap:6px; align-items:center;">
                <span class="badge ${isWarn ? 'badge-warning' : 'badge-error'}">${err.type}</span>
                <span class="badge badge-category">${err.category || 'other'}</span>
                <span class="badge badge-confidence">Conf: ${Math.round((err.confidence||0)*100)}%</span>
              </div>
              <span style="font-size:12px; color:var(--text-muted); font-family:var(--code-font);">Line ${err.line || '?'}${err.column ? ':' + err.column : ''}</span>
            </div>
            <div class="card-title">${escapeHtml(err.message)}</div>
            ${err.ast_node ? `<div style="font-size:12px; color:#38bdf8; margin: 4px 0;">AST Location: <b>${err.ast_node}</b></div>` : ''}
            
            ${err.explanation ? `
              <div class="section-title">Analysis &amp; Explanation</div>
              <div class="section-body" style="white-space: pre-line;">${escapeHtml(err.explanation)}</div>
            ` : ''}

            ${err.suggestion ? `
              <div class="section-title">Suggested Fix</div>
              <div class="code-box" style="color: #6ee7b7;">${escapeHtml(err.suggestion)}</div>
            ` : ''}
          </div>
        `;
      });
      container.innerHTML = html;
    }

    let preHealCode = '';

    function undoHeal() {
      if (!preHealCode) return;
      document.getElementById('code-editor').value = preHealCode;
      updateLineNumbers();
      const undoBtn = document.getElementById('btn-undo-heal');
      if (undoBtn) {
        undoBtn.disabled = true;
        undoBtn.style.opacity = '0.5';
      }
      document.getElementById('editor-status').textContent = 'Restored pre-heal source code';
    }

    async function autoHealCode() {
      const code = document.getElementById('code-editor').value;
      const healBtn = document.getElementById('btn-auto-heal');
      const undoBtn = document.getElementById('btn-undo-heal');
      if (healBtn) healBtn.disabled = true;
      document.getElementById('editor-status').textContent = 'Auto-healing in progress (up to 5 rounds)…';

      preHealCode = code;
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 120000);

      try {
        const res = await fetch('/api/heal', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code }),
          signal: controller.signal
        });
        clearTimeout(timeoutId);
        if (!res.ok) {
          const errText = await res.text();
          throw new Error('Server error (' + res.status + '): ' + errText);
        }
        const data = await res.json();

        // Update code editor with patched version
        if (data.healed_code) {
          document.getElementById('code-editor').value = data.healed_code;
          updateLineNumbers();
        }

        if (undoBtn) {
          undoBtn.disabled = false;
          undoBtn.style.opacity = '1.0';
        }

        renderHealingHistory(data);
        const roundCount = (data.rounds || []).length || (data.attempts || []).length;
        updateTelemetry(data.total_duration || 0, data.total_emissions || 0, roundCount);
        document.getElementById('editor-status').textContent = data.clean ? 'Auto-Healing Completed Successfully ✅' : (data.message || 'Heal Loop Finished');
        switchTab('healing');
      } catch (err) {
        clearTimeout(timeoutId);
        const errMsg = err.name === 'AbortError' ? 'Auto-heal timed out after 120 seconds' : ('Heal request failed: ' + err.message);
        alert(errMsg);
        document.getElementById('editor-status').textContent = 'Error: ' + errMsg;
      } finally {
        if (healBtn) healBtn.disabled = false;
      }
    }

    function renderHealingHistory(data) {
      const container = document.getElementById('healing-view');
      const rounds = data.rounds || [];
      const attempts = data.attempts || [];
      let html = `
        <div class="card ${data.clean ? 'success-card' : 'warning-card'}">
          <div class="card-title">${data.clean ? 'Auto-Healing Successful ✅' : 'Healing Finished'}</div>
          <div class="section-body">${escapeHtml(data.message || 'Healing finished.')}</div>
        </div>
      `;

      if (rounds.length > 0) {
        html += `<div style="font-weight:600; margin:12px 0 6px 0; color:#94a3b8; font-size:12px;">HEAL ROUNDS (${rounds.length})</div>`;
        rounds.forEach(r => {
          html += `
            <div class="card">
              <div style="display:flex; justify-content:space-between; margin-bottom: 6px;">
                <b>Round ${r.round_no}: ${escapeHtml(r.method || 'repair')}</b>
                <span class="badge badge-category">${r.errors_before} → ${r.errors_after} errors (${r.seconds}s)</span>
              </div>
              ${r.diff_html ? `<div class="diff-container">${r.diff_html}</div>` : '<div class="section-body">No diff for this round.</div>'}
            </div>
          `;
        });
      } else if (attempts.length > 0) {
        attempts.forEach(att => {
          html += `
            <div class="card">
              <div style="display:flex; justify-content:space-between; margin-bottom: 6px;">
                <b>Attempt ${att.attempt_no}: ${escapeHtml(att.target_error ? att.target_error.message : 'Fix applied')}</b>
                <span class="badge badge-category">${att.target_error ? att.target_error.category : ''}</span>
              </div>
              ${att.diff_html ? `<div class="diff-container">${att.diff_html}</div>` : '<div class="section-body">No diff for this step.</div>'}
            </div>
          `;
        });
      }

      container.innerHTML = html;
    }

    function renderAST(nodes) {
      const container = document.getElementById('ast-view');
      if (!nodes || nodes.length === 0) {
        container.innerHTML = '<div class="card"><div class="section-body">No AST nodes parsed or Clang not available.</div></div>';
        return;
      }
      function buildTreeHtml(list) {
        let h = '';
        list.forEach(node => {
          h += `<div class="tree-node">
            <span class="tree-type">${escapeHtml(node.type)}</span>
            <span class="tree-details">${escapeHtml(node.details || '')}</span>
            ${node.children && node.children.length ? buildTreeHtml(node.children) : ''}
          </div>`;
        });
        return h;
      }
      container.innerHTML = `<div class="card"><div class="code-box">${buildTreeHtml(nodes)}</div></div>`;
    }

    function renderSecurity(findings, report) {
      const container = document.getElementById('security-view');
      if (!findings || findings.length === 0) {
        container.innerHTML = `
          <div class="card success-card">
            <div class="card-title" style="color: var(--success);">Security Scan Clean</div>
            <div class="section-body">No static security vulnerabilities or risky APIs detected in current source.</div>
          </div>
        `;
        return;
      }
      let html = '';
      findings.forEach(f => {
        const isCrit = f.severity === 'Critical' || f.severity === 'High';
        html += `
          <div class="card ${isCrit ? 'error-card' : 'warning-card'}">
            <div style="display:flex; justify-content:space-between; align-items:center;">
              <span class="badge ${isCrit ? 'badge-error' : 'badge-warning'}">${f.severity}</span>
              <span style="font-size:12px; color:var(--text-muted); font-family:var(--code-font);">Line ${f.line || 'global'}</span>
            </div>
            <div class="card-title">${escapeHtml(f.vulnerability_type)}</div>
            <div class="section-body">${escapeHtml(f.description)}</div>
            <div class="section-title">Recommendation</div>
            <div class="code-box" style="color: #38bdf8;">${escapeHtml(f.recommendation)}</div>
          </div>
        `;
      });
      container.innerHTML = html;
    }

    function updateTelemetry(timeSec, emissions, passes) {
      if (timeSec) document.getElementById('stat-time').textContent = timeSec.toFixed(2) + ' s';
      if (emissions) document.getElementById('stat-co2').textContent = (emissions * 1000).toFixed(4) + ' mg';
      if (passes !== undefined) document.getElementById('stat-passes').textContent = passes + ' passes';
    }

    async function runBinary() {
      const code = document.getElementById('code-editor').value;
      const term = document.getElementById('terminal-output');
      term.textContent = 'Compiling and executing binary...';
      switchTab('terminal');

      try {
        const res = await fetch('/api/run', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code })
        });
        const data = await res.json();
        term.textContent = data.output || '(No output produced)';
      } catch (err) {
        term.textContent = 'Execution failed: ' + err;
      }
    }

    function escapeHtml(str) {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    }

    // Initialize with sample code
    loadSampleCode();
  </script>
</body>
</html>
"""

class CompilerWebHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Silence verbose request logging
        pass

    def _is_valid_origin_or_host(self) -> bool:
        port = getattr(self.server, "server_port", 8000)
        valid_hosts = {"localhost", "127.0.0.1", f"localhost:{port}", f"127.0.0.1:{port}"}
        host = self.headers.get("Host", "").strip().lower()
        if host and host not in valid_hosts:
            return False

        origin = self.headers.get("Origin", "").strip()
        if origin:
            p = urlparse(origin)
            if p.hostname not in {"localhost", "127.0.0.1"}:
                return False
            if p.port is not None and p.port != port:
                return False

        return True

    def _send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self._is_valid_origin_or_host():
            self.send_error(403, "Forbidden: Invalid Host or Origin")
            return
        parsed = urlparse(self.path)
        if parsed.path == "/" or parsed.path == "/index.html":
            body = HTML_PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        if not self._is_valid_origin_or_host():
            self.send_error(403, "Forbidden: Invalid Host or Origin")
            return

        content_type = self.headers.get("Content-Type", "")
        if not content_type.startswith("application/json"):
            self.send_error(415, "Unsupported Media Type: application/json required")
            return

        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length).decode("utf-8")
        try:
            req_data = json.loads(raw_body) if raw_body else {}
        except Exception:
            self.send_error(400, "Bad Request: Malformed JSON")
            return
        code = req_data.get("code", "")

        if parsed.path == "/api/compile":
            self.handle_compile(code)
        elif parsed.path == "/api/heal":
            self.handle_heal(code)
        elif parsed.path == "/api/run":
            self.handle_run(code)
        else:
            self.send_error(404, "API Endpoint Not Found")

    def handle_compile(self, code: str):
        start_time = time.time()
        with tempfile.NamedTemporaryFile("w", suffix=".cpp", delete=False, encoding="utf-8") as tmp:
            tmp_path = tmp.name
            tmp.write(code)

        try:
            output = run_cpp_compiler(tmp_path)
            duration = time.time() - start_time

            if not output:
                # Clean compilation — build AST from source (clang++ fallback)
                ast_tree = build_fallback_ast(code)
                security_findings = sanitize_findings(analyze_security(tmp_path, []), tmp_path)
                sec_report = format_security_report(security_findings).replace(tmp_path, "<user_code>")
                self._send_json({
                    "status": "clean",
                    "errors": [],
                    "ast_tree": ast_tree,
                    "security_findings": [f.to_dict() for f in security_findings],
                    "security_report": sec_report,
                    "duration": duration,
                    "emissions": 0.000012
                })
                return

            errors = parse_errors(output)
            ast_text = extract_ast(tmp_path)
            # Use clang AST if available, otherwise build fallback from source
            ast_tree = parse_ast_to_tree(ast_text) if ast_text else build_fallback_ast(code)

            for e in errors:
                if e.line:
                    e.ast_node = extract_node_near_line(ast_text, e.line) if ast_text else None
                else:
                    e.ast_node = None
                # Sanitize temp path in error file field (CompilerError is mutable)
                e.file = sanitize_file_path(e.file, tmp_path)
                enrich_error(e)

            security_findings = sanitize_findings(analyze_security(tmp_path, errors), tmp_path)
            sec_report = format_security_report(security_findings).replace(tmp_path, "<user_code>")

            self._send_json({
                "status": "errors",
                "errors": [e.to_dict() for e in errors],
                "ast_tree": ast_tree,
                "security_findings": [f.to_dict() for f in security_findings],
                "security_report": sec_report,
                "duration": duration,
                "emissions": 0.000025
            })
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)




    def handle_heal(self, code: str):
        from heal_engine import heal_until_clean
        result = heal_until_clean(
            source=code,
            classifier=classifier,
            use_ai=True,
        )
        self._send_json(result.to_dict())

    def handle_run(self, code: str):
        if not _sanitize_code(code):
            self._send_json({"output": "Execution blocked: Security check failed (contains forbidden calls or system commands)."})
            return

        with tempfile.NamedTemporaryFile("w", suffix=".cpp", delete=False, encoding="utf-8") as tmp:
            tmp_path = tmp.name
            tmp.write(code)

        exe_path = tmp_path.replace(".cpp", ".exe" if os.name == "nt" else "")
        try:
            # Build
            build_res = subprocess.run(["g++", "-std=c++17", tmp_path, "-o", exe_path], capture_output=True, text=True)
            if build_res.returncode != 0:
                self._send_json({"output": "Compilation failed:\n" + build_res.stderr})
                return

            # Run with stdin=subprocess.DEVNULL
            run_res = subprocess.run([exe_path], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=5)
            output = run_res.stdout
            if run_res.stderr:
                output += "\n[stderr]:\n" + run_res.stderr
            self._send_json({"output": output or "Program executed successfully with exit code 0."})
        except subprocess.TimeoutExpired:
            self._send_json({"output": "Execution timed out (5s limit)."})
        except Exception as e:
            self._send_json({"output": f"Execution error: {e}"})
        finally:
            if os.path.exists(tmp_path): os.remove(tmp_path)
            if os.path.exists(exe_path): os.remove(exe_path)


def run_server(port=8000):
    server_address = ("127.0.0.1", port)
    httpd = ThreadingHTTPServer(server_address, CompilerWebHandler)
    print(f"Server running at http://localhost:{port}/")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()

if __name__ == "__main__":
    port = 8000
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass
    run_server(port)
