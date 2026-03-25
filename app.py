import html as html_module
import json
import os
import re
import urllib.parse
import urllib.request
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

BASE_URL_OVERRIDE = os.environ.get('BASE_URL', '').rstrip('/')

def serve_app():
    with open(os.path.join(BASE_DIR, 'checkmyvibecode-app.html'), 'r', encoding='utf-8') as f:
        html = f.read()
    base_url = BASE_URL_OVERRIDE or request.host_url.rstrip('/')
    html = html.replace('__BASE_URL__', base_url)
    config = json.dumps({'url': SUPABASE_URL, 'anonKey': SUPABASE_ANON_KEY})
    config_script = f'<script>window.SUPABASE_CONFIG={config};</script>\n'
    html = html.replace('</head>', config_script + '</head>', 1)
    resp = Response(html, mimetype='text/html')
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    resp.headers['Pragma'] = 'no-cache'
    return resp

def _fetch_project(project_id):
    """Fetch a single project from Supabase REST API (for OG tag injection)."""
    if not SUPABASE_URL or not SUPABASE_ANON_KEY:
        return None
    try:
        safe_id = urllib.parse.quote(str(project_id), safe='')
        api_url = (
            f"{SUPABASE_URL}/rest/v1/projects"
            f"?id=eq.{safe_id}"
            f"&select=id,name,description,emoji,author,cat"
            f"&limit=1"
        )
        req = urllib.request.Request(api_url, headers={
            'apikey': SUPABASE_ANON_KEY,
            'Authorization': f'Bearer {SUPABASE_ANON_KEY}',
        })
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())
            return data[0] if data else None
    except Exception:
        return None


def _inject_project_og(html, project):
    """Replace generic OG / Twitter title + description with project-specific values."""
    name   = project.get('name', '') or ''
    emoji  = project.get('emoji', '') or ''
    desc   = project.get('description', '') or ''
    if len(desc) > 250:
        desc = desc[:247] + '...'

    title = f"{emoji} {name} — CheckMyVibeCode" if emoji else f"{name} — CheckMyVibeCode"
    safe_title = html_module.escape(title)
    safe_desc  = html_module.escape(desc)

    html = re.sub(r'<title>[^<]*</title>', f'<title>{safe_title}</title>', html, count=1)
    og_tags = (
        f'<meta property="og:title" content="{safe_title}">\n'
        f'<meta property="og:description" content="{safe_desc}">\n'
        f'<meta name="twitter:title" content="{safe_title}">\n'
        f'<meta name="twitter:description" content="{safe_desc}">\n'
    )
    html = html.replace('<head>', '<head>\n' + og_tags, 1)
    return html


@app.route('/')
def index():
    return serve_app()

@app.route('/static/<path:path>')
def static_files(path):
    return send_from_directory(STATIC_DIR, path)


@app.route('/p/<project_id>')
def project_detail(project_id):
    with open(os.path.join(BASE_DIR, 'checkmyvibecode-app.html'), 'r', encoding='utf-8') as f:
        html = f.read()
    base_url = BASE_URL_OVERRIDE or request.host_url.rstrip('/')
    html = html.replace('__BASE_URL__', base_url)
    project = _fetch_project(project_id)
    if project:
        html = _inject_project_og(html, project)
    config = json.dumps({'url': SUPABASE_URL, 'anonKey': SUPABASE_ANON_KEY})
    config_script = f'<script>window.SUPABASE_CONFIG={config};</script>\n'
    html = html.replace('</head>', config_script + '</head>', 1)
    resp = Response(html, mimetype='text/html')
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    resp.headers['Pragma'] = 'no-cache'
    return resp


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
