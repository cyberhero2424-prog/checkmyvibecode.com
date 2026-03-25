import json
import os
from flask import Flask, Response, send_from_directory, abort, redirect, url_for, request
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, 'static')

BLOCKED_NAMES = {'.env', '.git', 'app.py', 'requirements.txt'}
HTML_ENTRY_POINTS = {'index.html', 'checkmyvibecode-app.html'}

app = Flask(__name__)

SUPABASE_URL      = os.environ.get('SUPABASE_URL', '')
SUPABASE_ANON_KEY = os.environ.get('SUPABASE_ANON_KEY', '')

def serve_app():
    with open(os.path.join(BASE_DIR, 'checkmyvibecode-app.html'), 'r', encoding='utf-8') as f:
        html = f.read()
    base_url = request.host_url.rstrip('/')
    html = html.replace('__BASE_URL__', base_url)
    config = json.dumps({'url': SUPABASE_URL, 'anonKey': SUPABASE_ANON_KEY})
    config_script = f'<script>window.SUPABASE_CONFIG={config};</script>\n'
    html = html.replace('</head>', config_script + '</head>', 1)
    resp = Response(html, mimetype='text/html')
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    resp.headers['Pragma'] = 'no-cache'
    return resp

@app.route('/')
def index():
    return serve_app()

@app.route('/static/<path:path>')
def static_files(path):
    return send_from_directory(STATIC_DIR, path)

@app.route('/<path:path>')
def root_files(path):
    # Redirect HTML entry-point aliases back to / so they always get config injected
    if path in HTML_ENTRY_POINTS:
        return redirect(url_for('index'), code=301)
    filename = os.path.basename(path)
    if filename.startswith('.') or filename in BLOCKED_NAMES:
        abort(404)
    safe_path = os.path.normpath(os.path.join(BASE_DIR, path))
    if os.path.commonpath([BASE_DIR, safe_path]) != BASE_DIR:
        abort(404)
    if not os.path.isfile(safe_path):
        abort(404)
    return send_from_directory(BASE_DIR, path)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
