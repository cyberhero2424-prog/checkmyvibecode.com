import html as html_module
import json
import os
import re
import secrets
import threading
import time
import urllib.parse
import urllib.request
from collections import defaultdict
from flask import Flask, Response, send_from_directory, abort, redirect, url_for, request, session, render_template
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, 'static')

BLOCKED_NAMES = {'.env', '.git', 'app.py', 'requirements.txt'}
HTML_ENTRY_POINTS = {'index.html', 'checkmyvibecode-app.html'}

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32)

SUPABASE_URL        = os.environ.get('SUPABASE_URL', '')
SUPABASE_ANON_KEY   = os.environ.get('SUPABASE_ANON_KEY', '')
SUPABASE_SERVICE_KEY = os.environ.get('SUPABASE_SERVICE_KEY', '')
ADMIN_PASSWORD      = os.environ.get('ADMIN_PASSWORD', '')
RESEND_API_KEY = os.environ.get('RESEND_API_KEY', '')

BASE_URL_OVERRIDE = os.environ.get('BASE_URL', '').rstrip('/')

# ── Rate limiting & brute force protection ────────────────────────────────────

_submit_log   = defaultdict(list)   # ip -> [timestamps]
_login_log    = defaultdict(list)   # ip -> [timestamps]

def _rate_limit_submit(ip, max_calls=5, window=3600):
    """Allow max 5 project submissions per IP per hour."""
    now = time.time()
    _submit_log[ip] = [t for t in _submit_log[ip] if now - t < window]
    if len(_submit_log[ip]) >= max_calls:
        return False
    _submit_log[ip].append(now)
    return True

def _rate_limit_login(ip, max_attempts=10, window=900):
    """Lock out IP after 10 failed login attempts within 15 minutes."""
    now = time.time()
    _login_log[ip] = [t for t in _login_log[ip] if now - t < window]
    if len(_login_log[ip]) >= max_attempts:
        return False
    _login_log[ip].append(now)
    return True

def _clear_login_attempts(ip):
    """Clear login attempts on successful login."""
    _login_log.pop(ip, None)

# ── Security headers ──────────────────────────────────────────────────────────

@app.after_request
def security_headers(resp):
    resp.headers['X-Content-Type-Options']  = 'nosniff'
    resp.headers['X-Frame-Options']         = 'DENY'
    resp.headers['Referrer-Policy']         = 'strict-origin-when-cross-origin'
    resp.headers['X-XSS-Protection']        = '1; mode=block'
    return resp

# ── URL validator ─────────────────────────────────────────────────────────────

def _safe_url(url):
    """Only allow http:// and https:// URLs — blocks javascript: and data: URIs."""
    if not url:
        return '#'
    url = str(url).strip()[:500]
    if not re.match(r'^https?://', url, re.IGNORECASE):
        return '#'
    return url

# ── Helpers ───────────────────────────────────────────────────────────────────

def _inject_config(html):
    """Inject Supabase config into the HTML <head>."""
    config = json.dumps({'url': SUPABASE_URL, 'anonKey': SUPABASE_ANON_KEY})
    script = f'<script>window.SUPABASE_CONFIG={config};</script>\n'
    return html.replace('</head>', script + '</head>', 1)


def serve_app():
    with open(os.path.join(BASE_DIR, 'checkmyvibecode-app.html'), 'r', encoding='utf-8') as f:
        html = f.read()
    base_url = BASE_URL_OVERRIDE or request.host_url.rstrip('/')
    html = html.replace('__BASE_URL__', base_url)
    html = _inject_config(html)
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
            f"&status=eq.approved"
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


# ── Supabase admin helpers (use service key — bypasses RLS) ───────────────────

def _sb_service_request(method, path, body=None):
    """Make a Supabase REST request using the service role key."""
    if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
        return None, 'SUPABASE_SERVICE_KEY is not configured'
    url = f"{SUPABASE_URL}/rest/v1/{path}"
    data = json.dumps(body).encode() if body is not None else None
    headers = {
        'apikey': SUPABASE_SERVICE_KEY,
        'Authorization': f'Bearer {SUPABASE_SERVICE_KEY}',
        'Content-Type': 'application/json',
        'Prefer': 'return=representation',
    }
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode()), None
    except urllib.error.HTTPError as e:
        return None, f'HTTP {e.code}: {e.read().decode()}'
    except Exception as ex:
        return None, str(ex)


def _admin_list_projects(status='pending'):
    safe_s = urllib.parse.quote(status, safe='')
    path = f"projects?status=eq.{safe_s}&order=created_at.asc&select=id,name,description,idea,build_time,cost,emoji,author,cat,status,upvotes,demo,tools,created_at"
    data, err = _sb_service_request('GET', path)
    return data or [], err


def _admin_count_by_status():
    counts = {'pending': 0, 'approved': 0, 'rejected': 0}
    for status in counts:
        safe_s = urllib.parse.quote(status, safe='')
        path = f"projects?status=eq.{safe_s}&select=id"
        data, _ = _sb_service_request('GET', path)
        counts[status] = len(data) if data else 0
    return counts


def _admin_set_status(project_id, new_status):
    safe_id = urllib.parse.quote(str(project_id), safe='')
    path = f"projects?id=eq.{safe_id}"
    _, err = _sb_service_request('PATCH', path, {'status': new_status})
    return err


def _admin_list_forum_threads():
    """List all forum threads using anon key (public RLS read policy)."""
    raw, err = _sb_get('forum_threads', 'select=*&order=created_at.desc')
    data = json.loads(raw) if raw else []
    return data, err


def _admin_list_forum_replies(thread_id):
    """List replies for a thread using anon key (public RLS read policy)."""
    safe_id = urllib.parse.quote(str(thread_id), safe='')
    raw, err = _sb_get('forum_replies',
        f'thread_id=eq.{safe_id}&order=created_at.asc&select=*')
    data = json.loads(raw) if raw else []
    return data, err


def _sb_admin_delete(table, column, value):
    """Generic service-key DELETE for admin moderation. Returns error string or None."""
    if len(SUPABASE_SERVICE_KEY) < 20:
        return ('SUPABASE_SERVICE_KEY is not properly configured — '
                'set it in Secrets to enable forum deletion')
    safe_val = urllib.parse.quote(str(value), safe='')
    _, err = _sb_service_request('DELETE', f'{table}?{column}=eq.{safe_val}')
    return err


def _admin_delete_forum_thread(thread_id):
    return _sb_admin_delete('forum_threads', 'id', thread_id)


def _admin_delete_forum_reply(reply_id):
    return _sb_admin_delete('forum_replies', 'id', reply_id)


def _admin_forum_thread_count():
    """Return total number of forum threads using anon key (public RLS read policy)."""
    raw, _ = _sb_get('forum_threads', 'select=id')
    data = json.loads(raw) if raw else []
    return len(data)


# ── Public routes ─────────────────────────────────────────────────────────────

@app.route('/')
def index():
    pid = request.args.get('project', '').strip()
    if pid:
        return redirect(url_for('project_detail', project_id=pid), code=301)
    return serve_app()

@app.route('/static/<path:path>')
def static_files(path):
    return send_from_directory(STATIC_DIR, path)


def _fetch_profile_stats(handle):
    """Fetch build count + total upvotes for a user handle from Supabase REST."""
    if not SUPABASE_URL or not SUPABASE_ANON_KEY:
        return None
    try:
        safe_h = urllib.parse.quote(str(handle), safe='')
        api_url = (
            f"{SUPABASE_URL}/rest/v1/projects"
            f"?author=eq.{safe_h}"
            f"&status=eq.approved"
            f"&select=upvotes"
        )
        req = urllib.request.Request(api_url, headers={
            'apikey': SUPABASE_ANON_KEY,
            'Authorization': f'Bearer {SUPABASE_ANON_KEY}',
        })
        with urllib.request.urlopen(req, timeout=3) as resp:
            rows = json.loads(resp.read().decode())
            return {
                'builds': len(rows),
                'upvotes': sum(r.get('upvotes', 0) or 0 for r in rows),
            }
    except Exception:
        return None


@app.route('/u/<handle>')
def user_profile(handle):
    bare_handle = handle.lstrip('@')
    db_handle   = '@' + bare_handle
    with open(os.path.join(BASE_DIR, 'checkmyvibecode-app.html'), 'r', encoding='utf-8') as f:
        html = f.read()
    base_url = BASE_URL_OVERRIDE or request.host_url.rstrip('/')
    html = html.replace('__BASE_URL__', base_url)
    stats = _fetch_profile_stats(db_handle)
    title = f"{db_handle} — CheckMyVibeCode"
    if stats is not None:
        desc = f"{stats['builds']} build{'s' if stats['builds'] != 1 else ''} · {stats['upvotes']} upvotes on CheckMyVibeCode"
    else:
        desc = f"View {db_handle}'s builds on CheckMyVibeCode"
    safe_t  = html_module.escape(title)
    safe_d  = html_module.escape(desc)
    html    = re.sub(r'<title>[^<]*</title>', f'<title>{safe_t}</title>', html, count=1)
    og_tags = (
        f'<meta property="og:title" content="{safe_t}">\n'
        f'<meta property="og:description" content="{safe_d}">\n'
        f'<meta name="twitter:title" content="{safe_t}">\n'
        f'<meta name="twitter:description" content="{safe_d}">\n'
    )
    html = html.replace('<head>', '<head>\n' + og_tags, 1)
    html = _inject_config(html)
    resp = Response(html, mimetype='text/html')
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    resp.headers['Pragma'] = 'no-cache'
    return resp


@app.route('/p/<project_id>')
def project_detail(project_id):
    with open(os.path.join(BASE_DIR, 'checkmyvibecode-app.html'), 'r', encoding='utf-8') as f:
        html = f.read()
    base_url = BASE_URL_OVERRIDE or request.host_url.rstrip('/')
    html = html.replace('__BASE_URL__', base_url)
    project = _fetch_project(project_id)
    if project:
        html = _inject_project_og(html, project)
    html = _inject_config(html)
    resp = Response(html, mimetype='text/html')
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    resp.headers['Pragma'] = 'no-cache'
    return resp


# ── Admin routes ──────────────────────────────────────────────────────────────

def _admin_logged_in():
    return session.get('admin') is True


def _csrf_token():
    """Return (generating if needed) a per-session CSRF token."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']


def _csrf_valid():
    """Check that the submitted form CSRF token matches the session token."""
    return request.form.get('csrf_token') == session.get('csrf_token')


@app.route('/admin')
def admin():
    if not _admin_logged_in():
        return render_template('admin.html', logged_in=False, error=None,
                               csrf_token=_csrf_token())

    tab = request.args.get('tab', 'pending')
    if tab not in ('pending', 'approved', 'rejected', 'forum'):
        tab = 'pending'

    flash_msg  = session.pop('flash_msg', None)
    flash_type = session.pop('flash_type', 'ok')

    counts = _admin_count_by_status()
    forum_thread_count = _admin_forum_thread_count()

    if tab == 'forum':
        forum_threads, _ = _admin_list_forum_threads()
        # Pre-load replies for each thread so template can render inline
        for t in forum_threads:
            t['replies'], _ = _admin_list_forum_replies(t['id'])
        return render_template(
            'admin.html',
            logged_in=True,
            projects=[],
            counts=counts,
            tab=tab,
            forum_threads=forum_threads,
            forum_thread_count=forum_thread_count,
            flash_msg=flash_msg,
            flash_type=flash_type,
            csrf_token=_csrf_token(),
        )

    projects, err = _admin_list_projects(tab)

    return render_template(
        'admin.html',
        logged_in=True,
        projects=projects,
        counts=counts,
        tab=tab,
        forum_threads=[],
        forum_thread_count=forum_thread_count,
        flash_msg=flash_msg,
        flash_type=flash_type,
        csrf_token=_csrf_token(),
    )


@app.route('/admin/login', methods=['POST'])
def admin_login():
    if not _csrf_valid():
        return render_template('admin.html', logged_in=False,
                               error='Invalid request. Please try again.',
                               csrf_token=_csrf_token())
    ip = request.remote_addr
    if not _rate_limit_login(ip):
        return render_template('admin.html', logged_in=False,
                               error='Too many login attempts. Please wait 15 minutes.',
                               csrf_token=_csrf_token())
    password = request.form.get('password', '')
    if not ADMIN_PASSWORD:
        return render_template('admin.html', logged_in=False,
                               error='ADMIN_PASSWORD secret is not configured.',
                               csrf_token=_csrf_token())
    if password == ADMIN_PASSWORD:
        session['admin'] = True
        _clear_login_attempts(ip)
        return redirect(url_for('admin'))
    return render_template('admin.html', logged_in=False,
                           error='Incorrect password. Try again.',
                           csrf_token=_csrf_token())


@app.route('/admin/logout', methods=['POST'])
def admin_logout():
    if not _csrf_valid():
        return redirect(url_for('admin'))
    session.pop('admin', None)
    return redirect(url_for('admin'))


@app.route('/admin/forum-action', methods=['POST'])
def admin_forum_action():
    if not _admin_logged_in():
        return redirect(url_for('admin'))
    if not _csrf_valid():
        session['flash_msg']  = 'Invalid request token. Please try again.'
        session['flash_type'] = 'err'
        return redirect(url_for('admin', tab='forum'))

    action = request.form.get('action', '').strip()

    if action == 'delete_thread':
        thread_id = request.form.get('thread_id', '').strip()
        if not _UUID_RE.match(thread_id):
            session['flash_msg']  = 'Invalid thread ID.'
            session['flash_type'] = 'err'
            return redirect(url_for('admin', tab='forum'))
        err = _admin_delete_forum_thread(thread_id)
        if err:
            session['flash_msg']  = f'Error deleting thread: {err}'
            session['flash_type'] = 'err'
        else:
            session['flash_msg']  = 'Thread and all its replies deleted.'
            session['flash_type'] = 'ok'

    elif action == 'delete_reply':
        reply_id = request.form.get('reply_id', '').strip()
        if not _UUID_RE.match(reply_id):
            session['flash_msg']  = 'Invalid reply ID.'
            session['flash_type'] = 'err'
            return redirect(url_for('admin', tab='forum'))
        err = _admin_delete_forum_reply(reply_id)
        if err:
            session['flash_msg']  = f'Error deleting reply: {err}'
            session['flash_type'] = 'err'
        else:
            session['flash_msg']  = 'Reply deleted.'
            session['flash_type'] = 'ok'

    else:
        session['flash_msg']  = 'Invalid action.'
        session['flash_type'] = 'err'

    return redirect(url_for('admin', tab='forum'))


@app.route('/admin/action', methods=['POST'])
def admin_action():
    if not _admin_logged_in():
        return redirect(url_for('admin'))
    if not _csrf_valid():
        session['flash_msg']  = 'Invalid request token. Please try again.'
        session['flash_type'] = 'err'
        return redirect(url_for('admin'))

    project_id = request.form.get('project_id', '').strip()
    action     = request.form.get('action', '').strip()

    tab = request.form.get('tab', 'pending').strip()
    if tab not in ('pending', 'approved', 'rejected'):
        tab = 'pending'

    if not project_id or action not in ('approve', 'reject', 'delete'):
        session['flash_msg']  = 'Invalid action.'
        session['flash_type'] = 'err'
        return redirect(url_for('admin', tab=tab))

    if action == 'delete':
        err = _sb_admin_delete('projects', 'id', project_id)
        if err:
            session['flash_msg']  = f'Error: {err}'
            session['flash_type'] = 'err'
        else:
            session['flash_msg']  = 'Project permanently deleted.'
            session['flash_type'] = 'ok'
        return redirect(url_for('admin', tab=tab))

    new_status = 'approved' if action == 'approve' else 'rejected'
    err = _admin_set_status(project_id, new_status)

    if err:
        session['flash_msg']  = f'Error: {err}'
        session['flash_type'] = 'err'
    else:
        verb = 'approved' if new_status == 'approved' else 'rejected'
        session['flash_msg']  = f'Project {verb} successfully.'
        session['flash_type'] = 'ok'

    return redirect(url_for('admin', tab=tab))


# ── Email notification helper ─────────────────────────────────────────────────

def _send_resend_email(to, subject, text_body):
    """Send a plain-text email via Resend API. Returns (ok, error_msg)."""
    if not RESEND_API_KEY:
        return False, 'RESEND_API_KEY not configured'
    payload = json.dumps({
        'from': 'CheckMyVibeCode <noreply@checkmyvibecode.com>',
        'to': [to],
        'subject': subject,
        'text': text_body,
    }).encode()
    req = urllib.request.Request(
        'https://api.resend.com/emails',
        data=payload,
        headers={
            'Authorization': f'Bearer {RESEND_API_KEY}',
            'Content-Type': 'application/json',
        },
        method='POST',
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status < 300, None
    except urllib.error.HTTPError as e:
        return False, f'HTTP {e.code}: {e.read().decode()[:200]}'
    except Exception as ex:
        return False, str(ex)


def _verify_supabase_token(token):
    """Verify a Supabase JWT via /auth/v1/user. Returns user dict or None."""
    if not SUPABASE_URL or not SUPABASE_ANON_KEY or not token:
        return None
    try:
        req = urllib.request.Request(
            f"{SUPABASE_URL}/auth/v1/user",
            headers={
                'apikey': SUPABASE_ANON_KEY,
                'Authorization': f'Bearer {token}',
            },
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


@app.route('/api/submit-project', methods=['POST'])
def submit_project():
    """Server-side project submission: verifies Supabase JWT, inserts via
    service key, and sends admin notification email — all in one trusted step.
    No secrets are ever sent to or read from the browser."""
    # 1. Authenticate via the user's Supabase session JWT
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return {'ok': False, 'error': 'Unauthorized'}, 401
    user = _verify_supabase_token(auth_header[7:])
    if not user:
        return {'ok': False, 'error': 'Invalid or expired session'}, 401

    # 1b. Rate limit — max 5 submissions per IP per hour
    if not _rate_limit_submit(request.remote_addr):
        return {'ok': False, 'error': 'Too many submissions. Please wait before trying again.'}, 429

    # 2. Parse and sanitise project data
    payload = request.get_json(silent=True) or {}
    name        = str(payload.get('name', '')).strip()[:200]
    description = str(payload.get('description', '')).strip()[:2000]
    if not name or not description:
        return {'ok': False, 'error': 'name and description are required'}, 400

    def _s(key, limit=500):
        v = payload.get(key)
        return str(v).strip()[:limit] if v else None

    new_project = {
        'name':        name,
        'description': description,
        'idea':        _s('idea'),
        'build_time':  _s('build_time', 200),
        'cost':        _s('cost', 200),
        'demo':        _safe_url(_s('demo', 500)),
        'tools':       [str(t).strip()[:100] for t in (payload.get('tools') or []) if str(t).strip()][:20],
        'score':       None,
        'author':      _s('author', 100) or '@anon',
        'emoji':       _s('emoji', 10) or '🚀',
        'cat':         _s('cat', 100) or 'Other',
        'upvotes':     0,
        'status':      'pending',
    }

    # 3. Insert using service key (bypasses RLS — safe because we verified the JWT)
    _, err = _sb_service_request('POST', 'projects', new_project)
    if err:
        app.logger.error('submit_project DB insert failed: %s', err)
        return {'ok': False, 'error': 'Could not save project. Please try again later.'}, 500

    # 4. Send admin notification email in a background thread (truly non-blocking)
    admin_url = (BASE_URL_OVERRIDE or request.host_url.rstrip('/')) + '/admin'
    email_body = (
        f"New project submitted for review on CheckMyVibeCode!\n\n"
        f"Name:        {name}\n"
        f"Author:      {new_project['author']}\n"
        f"Category:    {new_project['cat']}\n"
        f"Demo URL:    {new_project['demo']}\n"
        f"Description: {description[:300]}\n\n"
        f"Review it here: {admin_url}\n"
    )
    def _notify():
        ok, email_err = _send_resend_email(
            to='contact@checkmyvibecode.com',
            subject=f'[CheckMyVibeCode] New submission: {name}',
            text_body=email_body,
        )
        if not ok:
            app.logger.warning('Submit email notify failed: %s', email_err)
    threading.Thread(target=_notify, daemon=True).start()

    return {'ok': True}, 201


# ── Public project listing (server-side proxy — avoids browser cross-origin blocking) ──

@app.route('/api/projects')
def api_projects():
    """Return approved projects as JSON, fetched server-side.
    The browser calls checkmyvibecode.com/api/projects (same origin),
    so privacy browsers that block supabase.co cannot interfere."""
    key = SUPABASE_ANON_KEY
    if not SUPABASE_URL or not key:
        return {'error': 'Server not configured'}, 503
    endpoint = (SUPABASE_URL.rstrip('/') +
                '/rest/v1/projects?select=*&status=eq.approved&order=upvotes.desc')
    req = urllib.request.Request(endpoint, headers={
        'apikey': key,
        'Authorization': f'Bearer {key}',
    })
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            body = r.read()
        resp = Response(body, mimetype='application/json')
        resp.headers['Cache-Control'] = 'public, max-age=30'
        return resp
    except Exception as e:
        app.logger.error('api_projects error: %s', e)
        return {'error': 'Could not fetch projects'}, 502


@app.route('/api/profile/<path:handle>')
def api_profile(handle):
    """Return approved projects for a given author handle as JSON.
    Routes through Flask so browser-side Supabase JS lock contention cannot block it."""
    import re
    clean = handle.lstrip('@')
    if not clean or not re.match(r'^[A-Za-z0-9_.-]{1,40}$', clean):
        return {'error': 'Invalid handle'}, 404
    key = SUPABASE_ANON_KEY
    if not SUPABASE_URL or not key:
        return {'error': 'Server not configured'}, 503
    safe_handle = urllib.parse.quote('@' + clean, safe='')
    endpoint = (SUPABASE_URL.rstrip('/') +
                f'/rest/v1/projects?select=id,name,description,emoji,author,cat,upvotes,demo,tools,created_at'
                f'&status=eq.approved&author=eq.{safe_handle}&order=upvotes.desc')
    req = urllib.request.Request(endpoint, headers={
        'apikey': key,
        'Authorization': f'Bearer {key}',
    })
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            body = r.read()
        resp = Response(body, mimetype='application/json')
        resp.headers['Cache-Control'] = 'public, max-age=30'
        return resp
    except Exception as e:
        app.logger.error('api_profile error for %s: %s', handle, e)
        return {'error': 'Could not fetch profile'}, 502


# ── Forum proxy endpoints (server-side reads — avoids browser cross-origin blocking) ──

def _sb_get(path, params=''):
    """Helper: GET from Supabase REST using anon key, return (body_bytes, error)."""
    key = SUPABASE_ANON_KEY
    url = SUPABASE_URL.rstrip('/') + '/rest/v1/' + path + (('?' + params) if params else '')
    req = urllib.request.Request(url, headers={
        'apikey': key,
        'Authorization': f'Bearer {key}',
    })
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.read(), None
    except Exception as e:
        return None, str(e)


def _sb_post(path, payload, user_jwt, params=''):
    """Helper: POST to Supabase REST using user JWT (satisfies RLS auth.uid()). Returns (body_bytes, error)."""
    key = SUPABASE_ANON_KEY
    url = SUPABASE_URL.rstrip('/') + '/rest/v1/' + path + (('?' + params) if params else '')
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={
        'apikey': key,
        'Authorization': f'Bearer {user_jwt}',
        'Content-Type': 'application/json',
        'Prefer': 'return=representation',
    })
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.read(), None
    except Exception as e:
        return None, str(e)


@app.route('/api/forum/threads')
def api_forum_threads():
    if not SUPABASE_URL or not SUPABASE_ANON_KEY:
        return {'error': 'Server not configured'}, 503
    body, err = _sb_get('forum_threads', 'select=*&order=created_at.desc')
    if err:
        app.logger.error('api_forum_threads error: %s', err)
        return {'error': 'Could not fetch threads'}, 502
    resp = Response(body, mimetype='application/json')
    resp.headers['Cache-Control'] = 'public, max-age=15'
    return resp


_UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')


@app.route('/api/forum/threads/<thread_id>/replies')
def api_forum_replies(thread_id):
    if not SUPABASE_URL or not SUPABASE_ANON_KEY:
        return {'error': 'Server not configured'}, 503
    if not _UUID_RE.match(thread_id):
        return {'error': 'Invalid thread id'}, 400
    body, err = _sb_get('forum_replies',
                         f'select=*&thread_id=eq.{thread_id}&order=created_at.asc')
    if err:
        app.logger.error('api_forum_replies error: %s', err)
        return {'error': 'Could not fetch replies'}, 502
    resp = Response(body, mimetype='application/json')
    resp.headers['Cache-Control'] = 'public, max-age=15'
    return resp


def _get_user_jwt():
    """Extract Bearer token from the incoming Authorization header. Returns token or None."""
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer ') and len(auth) > 10:
        return auth[7:]
    return None


@app.route('/api/forum/threads', methods=['POST'])
def api_forum_create_thread():
    if not SUPABASE_URL or not SUPABASE_ANON_KEY:
        return {'error': 'Server not configured'}, 503
    user_jwt = _get_user_jwt()
    if not user_jwt:
        return {'error': 'Unauthorized'}, 401
    try:
        payload = request.get_json(force=True) or {}
        title = str(payload.get('title', '')).strip()[:300]
        body_text = str(payload.get('body', '')).strip()[:5000]
        author_handle = str(payload.get('author_handle', '')).strip()[:100]
        author_id = str(payload.get('author_id', '')).strip()
        if not title or not body_text or not author_id:
            return {'error': 'Missing required fields'}, 400
    except Exception:
        return {'error': 'Bad request'}, 400
    result, err = _sb_post('forum_threads',
                            {'title': title, 'body': body_text,
                             'author_handle': author_handle, 'author_id': author_id},
                            user_jwt)
    if err:
        app.logger.error('api_forum_create_thread error: %s', err)
        return {'error': 'Could not create thread'}, 502
    return Response(result, mimetype='application/json')


@app.route('/api/forum/threads/<thread_id>/replies', methods=['POST'])
def api_forum_create_reply(thread_id):
    if not SUPABASE_URL or not SUPABASE_ANON_KEY:
        return {'error': 'Server not configured'}, 503
    if not _UUID_RE.match(thread_id):
        return {'error': 'Invalid thread id'}, 400
    user_jwt = _get_user_jwt()
    if not user_jwt:
        return {'error': 'Unauthorized'}, 401
    try:
        payload = request.get_json(force=True) or {}
        body_text = str(payload.get('body', '')).strip()[:5000]
        author_handle = str(payload.get('author_handle', '')).strip()[:100]
        author_id = str(payload.get('author_id', '')).strip()
        if not body_text or not author_id:
            return {'error': 'Missing required fields'}, 400
    except Exception:
        return {'error': 'Bad request'}, 400
    result, err = _sb_post('forum_replies',
                            {'thread_id': thread_id, 'body': body_text,
                             'author_handle': author_handle, 'author_id': author_id},
                            user_jwt)
    if err:
        app.logger.error('api_forum_create_reply error: %s', err)
        return {'error': 'Could not post reply'}, 502
    return Response(result, mimetype='application/json')


# ── robots.txt ────────────────────────────────────────────────────────────────

@app.route('/robots.txt')
def robots():
    return Response(
        "User-agent: *\nDisallow: /admin\nDisallow: /api/\n",
        mimetype='text/plain'
    )

# ── 404 handler ───────────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return redirect(url_for('index'))

# ── Catch-all static file route ───────────────────────────────────────────────

@app.route('/<path:path>')
def root_files(path):
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
