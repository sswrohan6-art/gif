# app.py
# Flask web dashboard for GIF Malware Detector
# Run: py -3.11 app.py
# Open: http://localhost:5000

import os
import sys
import json
import base64
from flask import Flask, request, jsonify, render_template_string
from werkzeug.utils import secure_filename

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from src.detector import detect

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ── HTML Template ─────────────────────────────────────────────────────
HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GIF Malware Detector</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    font-family: 'Segoe UI', sans-serif;
    background: #0f1117;
    color: #e0e0e0;
    min-height: 100vh;
  }

  header {
    background: #1a1d27;
    border-bottom: 1px solid #2a2d3a;
    padding: 20px 40px;
    display: flex;
    align-items: center;
    gap: 16px;
  }

  header h1 {
    font-size: 22px;
    font-weight: 600;
    color: #ffffff;
  }

  header span {
    font-size: 13px;
    color: #6b7280;
    background: #2a2d3a;
    padding: 4px 12px;
    border-radius: 20px;
  }

  .container {
    max-width: 900px;
    margin: 40px auto;
    padding: 0 20px;
  }

  .upload-card {
    background: #1a1d27;
    border: 2px dashed #2a2d3a;
    border-radius: 16px;
    padding: 48px;
    text-align: center;
    transition: border-color 0.2s;
    cursor: pointer;
  }

  .upload-card:hover { border-color: #4f46e5; }
  .upload-card.dragover { border-color: #4f46e5; background: #1e2035; }

  .upload-icon {
    width: 64px;
    height: 64px;
    background: #2a2d3a;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    margin: 0 auto 20px;
    font-size: 28px;
  }

  .upload-card h2 {
    font-size: 18px;
    color: #ffffff;
    margin-bottom: 8px;
  }

  .upload-card p {
    font-size: 14px;
    color: #6b7280;
    margin-bottom: 24px;
  }

  .btn {
    background: #4f46e5;
    color: white;
    border: none;
    padding: 12px 28px;
    border-radius: 8px;
    font-size: 15px;
    cursor: pointer;
    transition: background 0.2s;
  }

  .btn:hover { background: #4338ca; }
  .btn:disabled { background: #2a2d3a; cursor: not-allowed; }

  #file-input { display: none; }

  .selected-file {
    margin-top: 16px;
    font-size: 13px;
    color: #4f46e5;
    display: none;
  }

  /* Loading */
  .loading {
    display: none;
    text-align: center;
    padding: 40px;
  }

  .spinner {
    width: 48px;
    height: 48px;
    border: 3px solid #2a2d3a;
    border-top-color: #4f46e5;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
    margin: 0 auto 16px;
  }

  @keyframes spin { to { transform: rotate(360deg); } }

  /* Result card */
  .result-card {
    display: none;
    background: #1a1d27;
    border-radius: 16px;
    overflow: hidden;
    margin-top: 24px;
  }

  .result-header {
    padding: 24px 32px;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .result-header.safe      { background: #052e16; border-left: 4px solid #22c55e; }
  .result-header.suspicious{ background: #431407; border-left: 4px solid #f97316; }
  .result-header.malicious { background: #450a0a; border-left: 4px solid #ef4444; }

  .verdict-badge {
    font-size: 22px;
    font-weight: 700;
    letter-spacing: 1px;
  }

  .verdict-badge.safe       { color: #22c55e; }
  .verdict-badge.suspicious { color: #f97316; }
  .verdict-badge.malicious  { color: #ef4444; }

  .score-circle {
    width: 72px;
    height: 72px;
    border-radius: 50%;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    border: 3px solid;
  }

  .score-circle.safe       { border-color: #22c55e; }
  .score-circle.suspicious { border-color: #f97316; }
  .score-circle.malicious  { border-color: #ef4444; }

  .score-num {
    font-size: 24px;
    font-weight: 700;
  }

  .score-label {
    font-size: 10px;
    color: #6b7280;
    text-transform: uppercase;
  }

  .result-body { padding: 24px 32px; }

  .metrics-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 16px;
    margin-bottom: 24px;
  }

  .metric-box {
    background: #0f1117;
    border-radius: 10px;
    padding: 16px;
    text-align: center;
  }

  .metric-val {
    font-size: 22px;
    font-weight: 700;
    color: #ffffff;
  }

  .metric-lbl {
    font-size: 12px;
    color: #6b7280;
    margin-top: 4px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  /* Flags */
  .flags-section h3 {
    font-size: 14px;
    color: #9ca3af;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 12px;
  }

  .flag-item {
    background: #0f1117;
    border-radius: 8px;
    padding: 12px 16px;
    margin-bottom: 8px;
    display: flex;
    align-items: flex-start;
    gap: 12px;
  }

  .flag-sev {
    font-size: 11px;
    font-weight: 600;
    padding: 3px 8px;
    border-radius: 4px;
    white-space: nowrap;
    margin-top: 1px;
  }

  .flag-sev.critical { background: #450a0a; color: #ef4444; }
  .flag-sev.high     { background: #431407; color: #f97316; }
  .flag-sev.medium   { background: #422006; color: #fb923c; }

  .flag-text { font-size: 13px; color: #d1d5db; }
  .flag-detail { font-size: 12px; color: #6b7280; margin-top: 2px; }

  .no-flags {
    background: #052e16;
    border-radius: 8px;
    padding: 16px;
    color: #22c55e;
    font-size: 14px;
    text-align: center;
  }

  /* ML section */
  .ml-section {
    margin-top: 20px;
    background: #0f1117;
    border-radius: 10px;
    padding: 16px 20px;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .ml-label {
    font-size: 13px;
    color: #6b7280;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .ml-val {
    font-size: 15px;
    font-weight: 600;
    color: #ffffff;
  }

  .confidence-bar {
    width: 200px;
    height: 6px;
    background: #2a2d3a;
    border-radius: 3px;
    overflow: hidden;
  }

  .confidence-fill {
    height: 100%;
    border-radius: 3px;
    transition: width 0.8s ease;
  }

  .confidence-fill.safe     { background: #22c55e; }
  .confidence-fill.malicious{ background: #ef4444; }

  /* History */
  .history-section {
    margin-top: 32px;
    background: #1a1d27;
    border-radius: 16px;
    overflow: hidden;
  }

  .history-header {
    padding: 16px 24px;
    border-bottom: 1px solid #2a2d3a;
    font-size: 14px;
    font-weight: 600;
    color: #9ca3af;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .history-item {
    padding: 14px 24px;
    border-bottom: 1px solid #2a2d3a;
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-size: 13px;
  }

  .history-item:last-child { border-bottom: none; }

  .hist-name { color: #e0e0e0; font-weight: 500; }
  .hist-time { color: #6b7280; font-size: 12px; }

  .badge {
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 600;
  }

  .badge.safe       { background: #052e16; color: #22c55e; }
  .badge.suspicious { background: #431407; color: #f97316; }
  .badge.malicious  { background: #450a0a; color: #ef4444; }

  .empty-history {
    padding: 32px;
    text-align: center;
    color: #6b7280;
    font-size: 14px;
  }
</style>
</head>
<body>

<header>
  <div style="font-size:24px">🔍</div>
  <h1>GIF Malware Detector</h1>
  <span>v1.0 — Python + ML</span>
</header>

<div class="container">

  <!-- Upload Card -->
  <div class="upload-card" id="drop-zone">
    <div class="upload-icon">📁</div>
    <h2>Drop a GIF file to scan</h2>
    <p>Supports .gif files up to 50MB</p>
    <button class="btn" onclick="document.getElementById('file-input').click()">
      Choose File
    </button>
    <input type="file" id="file-input" accept=".gif" onchange="handleFile(this)">
    <div class="selected-file" id="selected-name"></div>
  </div>

  <!-- Loading -->
  <div class="loading" id="loading">
    <div class="spinner"></div>
    <p style="color:#6b7280">Analyzing file...</p>
  </div>

  <!-- Result -->
  <div class="result-card" id="result-card">
    <div class="result-header" id="result-header">
      <div>
        <div style="font-size:13px;color:#9ca3af;margin-bottom:6px">VERDICT</div>
        <div class="verdict-badge" id="verdict-text"></div>
        <div style="font-size:13px;color:#9ca3af;margin-top:6px" id="filename-text"></div>
      </div>
      <div class="score-circle" id="score-circle">
        <div class="score-num" id="score-num"></div>
        <div class="score-label">score</div>
      </div>
    </div>

    <div class="result-body">
      <div class="metrics-grid">
        <div class="metric-box">
          <div class="metric-val" id="entropy-val">-</div>
          <div class="metric-lbl">Entropy / 8.0</div>
        </div>
        <div class="metric-box">
          <div class="metric-val" id="frames-val">-</div>
          <div class="metric-lbl">Frames</div>
        </div>
        <div class="metric-box">
          <div class="metric-val" id="size-val">-</div>
          <div class="metric-lbl">File size</div>
        </div>
      </div>

      <div class="flags-section">
        <h3>Flags Triggered</h3>
        <div id="flags-list"></div>
      </div>

      <div class="ml-section">
        <div>
          <div class="ml-label">ML Model Vote</div>
          <div class="ml-val" id="ml-vote">-</div>
        </div>
        <div>
          <div class="ml-label" style="margin-bottom:6px">Confidence</div>
          <div class="confidence-bar">
            <div class="confidence-fill" id="conf-fill" style="width:0%"></div>
          </div>
          <div style="font-size:12px;color:#6b7280;margin-top:4px" id="conf-text"></div>
        </div>
      </div>
    </div>
  </div>

  <!-- History -->
  <div class="history-section">
    <div class="history-header">Scan History</div>
    <div id="history-list">
      <div class="empty-history">No scans yet — upload a GIF to get started</div>
    </div>
  </div>

</div>

<script>
  let history = [];

  const dropZone = document.getElementById('drop-zone');

  dropZone.addEventListener('dragover', e => {
    e.preventDefault();
    dropZone.classList.add('dragover');
  });

  dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('dragover');
  });

  dropZone.addEventListener('drop', e => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    const file = e.dataTransfer.files[0];
    if (file) scanFile(file);
  });

  function handleFile(input) {
    if (input.files[0]) scanFile(input.files[0]);
  }

  async function scanFile(file) {
    if (!file.name.toLowerCase().endsWith('.gif')) {
      alert('Please upload a .gif file');
      return;
    }

    document.getElementById('selected-name').style.display = 'block';
    document.getElementById('selected-name').textContent = file.name;
    document.getElementById('loading').style.display = 'block';
    document.getElementById('result-card').style.display = 'none';

    const formData = new FormData();
    formData.append('file', file);

    try {
      const res  = await fetch('/scan', { method: 'POST', body: formData });
      const data = await res.json();
      showResult(data, file.name);
    } catch (err) {
      alert('Scan failed: ' + err.message);
    } finally {
      document.getElementById('loading').style.display = 'none';
    }
  }

  function showResult(data, filename) {
    const verdict  = data.verdict || 'UNKNOWN';
    const cls      = verdict.toLowerCase() === 'safe' ? 'safe' :
                     verdict.toLowerCase() === 'suspicious' ? 'suspicious' : 'malicious';

    // Header
    document.getElementById('result-header').className = 'result-header ' + cls;
    document.getElementById('verdict-text').className  = 'verdict-badge ' + cls;
    document.getElementById('verdict-text').textContent = verdict;
    document.getElementById('filename-text').textContent = filename;

    // Score
    const scoreEl = document.getElementById('score-circle');
    scoreEl.className = 'score-circle ' + cls;
    document.getElementById('score-num').textContent = data.score || 0;

    // Metrics
    document.getElementById('entropy-val').textContent =
      data.entropy ? data.entropy.overall : '-';
    document.getElementById('frames-val').textContent =
      data.analysis ? data.analysis.frame_count : '-';
    document.getElementById('size-val').textContent =
      data.analysis ? data.analysis.size_kb + ' KB' : '-';

    // Flags
    const flagsList = document.getElementById('flags-list');
    if (!data.flags || data.flags.length === 0) {
      flagsList.innerHTML = '<div class="no-flags">No suspicious flags detected</div>';
    } else {
      flagsList.innerHTML = data.flags.map(f => `
        <div class="flag-item">
          <span class="flag-sev ${f.severity}">${f.severity.toUpperCase()}</span>
          <div>
            <div class="flag-text">${f.rule}</div>
            <div class="flag-detail">${f.detail}</div>
          </div>
        </div>
      `).join('');
    }

    // ML vote
    const mlVote = data.ml_prediction === null ? 'Model not loaded' :
                   data.ml_prediction === 1 ? 'MALICIOUS' : 'SAFE';
    const mlCls  = data.ml_prediction === 1 ? 'malicious' : 'safe';
    document.getElementById('ml-vote').textContent = mlVote;
    document.getElementById('conf-fill').className = 'confidence-fill ' + mlCls;
    document.getElementById('conf-fill').style.width = (data.ml_confidence || 0) + '%';
    document.getElementById('conf-text').textContent = (data.ml_confidence || 0) + '%';

    document.getElementById('result-card').style.display = 'block';

    // Add to history
    addHistory(filename, verdict, cls);
  }

  function addHistory(filename, verdict, cls) {
    const now = new Date().toLocaleTimeString();
    history.unshift({ filename, verdict, cls, time: now });

    const list = document.getElementById('history-list');
    list.innerHTML = history.map(h => `
      <div class="history-item">
        <div>
          <div class="hist-name">${h.filename}</div>
          <div class="hist-time">${h.time}</div>
        </div>
        <span class="badge ${h.cls}">${h.verdict}</span>
      </div>
    `).join('');
  }
</script>
</body>
</html>
'''


@app.route('/')
def index():
    return render_template_string(HTML)


@app.route('/scan', methods=['POST'])
def scan():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']

    if not file.filename.endswith('.gif'):
        return jsonify({'error': 'Only GIF files supported'}), 400

    # Save uploaded file
    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    try:
        # Run detection
        result = detect(filepath)

        # Build clean response
        response = {
            'verdict':       result.get('verdict'),
            'score':         result.get('score'),
            'flags':         result.get('flags', []),
            'ml_prediction': result.get('ml_prediction'),
            'ml_confidence': result.get('ml_confidence'),
        }

        if result.get('entropy'):
            response['entropy'] = {
                'overall': result['entropy']['overall_entropy'],
            }

        if result.get('analysis'):
            response['analysis'] = {
                'frame_count': result['analysis']['frame_count'],
                'size_kb':     result['analysis']['size_kb'],
                'width':       result['analysis']['width'],
                'height':      result['analysis']['height'],
            }

        return jsonify(response)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

    finally:
        # Clean up uploaded file
        if os.path.exists(filepath):
            os.remove(filepath)


if __name__ == '__main__':
    print("\n" + "="*50)
    print("  GIF Malware Detector — Web Dashboard")
    print("="*50)
    print("  Open in browser: http://localhost:5000")
    print("  Press Ctrl+C to stop")
    print("="*50 + "\n")
    app.run(debug=False, port=5000)