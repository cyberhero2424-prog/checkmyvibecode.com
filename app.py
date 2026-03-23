import json
import os
from flask import Flask, Response, send_from_directory

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)

SUPABASE_URL      = os.environ.get('SUPABASE_URL', '')
SUPABASE_ANON_KEY = os.environ.get('SUPABASE_ANON_KEY', '')

@app.route('/')
def index():
    with open(os.path.join(BASE_DIR, 'checkmyvibecode-app.html'), 'r', encoding='utf-8') as f:
        html = f.read()
    config = json.dumps({'url': SUPABASE_URL, 'anonKey': SUPABASE_ANON_KEY})
    config_script = f'<script>window.SUPABASE_CONFIG={config};</script>\n'
    html = html.replace('</head>', config_script + '</head>', 1)
    return Response(html, mimetype='text/html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory(BASE_DIR, path)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
