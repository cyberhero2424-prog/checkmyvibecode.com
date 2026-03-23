import os
from flask import Flask, Response

app = Flask(__name__)

SUPABASE_URL     = os.environ.get('SUPABASE_URL', '')
SUPABASE_ANON_KEY = os.environ.get('SUPABASE_ANON_KEY', '')

@app.route('/')
def index():
    with open('checkmyvibecode-app.html', 'r', encoding='utf-8') as f:
        html = f.read()
    config_script = (
        f'<script>'
        f'window.SUPABASE_CONFIG={{url:"{SUPABASE_URL}",anonKey:"{SUPABASE_ANON_KEY}"}};</script>\n'
    )
    html = html.replace('</head>', config_script + '</head>', 1)
    return Response(html, mimetype='text/html')

@app.route('/<path:path>')
def static_files(path):
    return app.send_static_file(path)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
