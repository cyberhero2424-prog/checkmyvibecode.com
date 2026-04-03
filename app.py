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
from whitenoise import WhiteNoise

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, 'static')

BLOCKED_NAMES = {'.env', '.git', 'app.py', 'requirements.txt'}
HTML_ENTRY_POINTS = {'index.html', 'checkmyvibecode-app.html'}

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32)
app.wsgi_app = WhiteNoise(app.wsgi_app, root=STATIC_DIR, prefix='static', max_age=31536000)

SUPABASE_URL        = os.environ.get('SUPABASE_URL', '')
SUPABASE_ANON_KEY   = os.environ.get('SUPABASE_ANON_KEY', '')
SUPABASE_SERVICE_KEY = os.environ.get('SUPABASE_SERVICE_KEY', '')
ADMIN_PASSWORD      = os.environ.get('ADMIN_PASSWORD', '')
# Optional: direct PostgreSQL connection URL (e.g. from Supabase Project Settings > Database)
# Format: postgresql://postgres.[ref]:[password]@aws-0-[region].pooler.supabase.com:6543/postgres
DATABASE_URL        = os.environ.get('DATABASE_URL', '')
RESEND_API_KEY = os.environ.get('RESEND_API_KEY', '')

BASE_URL_OVERRIDE = os.environ.get('BASE_URL', '').rstrip('/')

SCREENSHOT_BUCKET = 'project-screenshots'
ALLOWED_IMAGE_TYPES = {'image/jpeg', 'image/png', 'image/gif', 'image/webp'}
IMAGE_EXT_MAP = {'image/jpeg': 'jpg', 'image/png': 'png', 'image/gif': 'gif', 'image/webp': 'webp'}
MAX_SCREENSHOT_BYTES = 5 * 1024 * 1024  # 5 MB

# ── Rate limiting & brute force protection ────────────────────────────────────

_login_log    = defaultdict(list)   # ip -> [timestamps]

def _derive_author_handle(user):
    """Derive the canonical author handle from a verified Supabase JWT user dict.
    Mirrors the frontend's derivation logic so the handle matches what is stored
    in projects.author. Because this comes from the verified JWT, it cannot be
    spoofed by client-supplied payload data."""
    meta = user.get('user_metadata') or {}
    app_meta = user.get('app_metadata') or {}
    provider = app_meta.get('provider', '')
    if provider == 'github' and meta.get('user_name'):
        return '@' + str(meta['user_name'])
    email = user.get('email', '')
    if email:
        return '@' + email.split('@')[0]
    return '@user_' + str(user.get('id', 'unknown'))[:8]

def _rate_limit_submit_supabase(jwt_handle, max_calls=5, window_secs=3600):
    """Allow max 5 submissions per authenticated author per hour via Supabase.
    The key is the JWT-derived handle (tamper-proof), not the client payload.
    Works correctly across all workers and server restarts."""
    if not jwt_handle:
        return True
    cutoff = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() - window_secs))
    safe_author = urllib.parse.quote(jwt_handle, safe='')
    path = f"projects?author=eq.{safe_author}&created_at=gt.{cutoff}&select=id"
    data, err = _sb_service_request('GET', path)
    if err:
        app.logger.warning('Rate limit check error: %s', err)
        return True  # allow on error to avoid blocking legitimate users
    return len(data or []) < max_calls

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
        for select in (
            'id,name,description,emoji,author,cat,screenshot_url',
            'id,name,description,emoji,author,cat',  # fallback if column missing
        ):
            api_url = (
                f"{SUPABASE_URL}/rest/v1/projects"
                f"?id=eq.{safe_id}"
                f"&select={select}"
                f"&status=eq.approved"
                f"&limit=1"
            )
            req = urllib.request.Request(api_url, headers={
                'apikey': SUPABASE_ANON_KEY,
                'Authorization': f'Bearer {SUPABASE_ANON_KEY}',
            })
            try:
                with urllib.request.urlopen(req, timeout=3) as resp:
                    data = json.loads(resp.read().decode())
                    return data[0] if data else None
            except urllib.error.HTTPError as e:
                body = e.read().decode().lower()
                if 'screenshot_url' in body or ('column' in body and 'does not exist' in body):
                    continue  # retry without screenshot_url
                return None
        return None
    except Exception:
        return None


def _inject_project_og(html, project, project_url):
    """Replace generic OG / Twitter tags with project-specific values.

    Sets og:title, og:description, og:url, twitter:title, twitter:description,
    meta[name=description], and injects a <link rel="canonical"> tag.
    """
    name   = project.get('name', '') or ''
    emoji  = project.get('emoji', '') or ''
    desc   = project.get('description', '') or ''
    if len(desc) > 250:
        desc = desc[:247] + '...'

    title      = f"{emoji} {name} — CheckMyVibeCode" if emoji else f"{name} — CheckMyVibeCode"
    safe_title = html_module.escape(title)
    safe_desc  = html_module.escape(desc)
    safe_url   = html_module.escape(project_url)

    html = re.sub(r'<title>[^<]*</title>', f'<title>{safe_title}</title>', html, count=1)

    # Replace og:url with the project-specific URL
    html = re.sub(
        r'<meta property="og:url"[^>]*>',
        f'<meta property="og:url" content="{safe_url}">',
        html, count=1
    )

    # Replace the generic meta description
    html = re.sub(
        r'<meta name="description"[^>]*>',
        f'<meta name="description" content="{safe_desc}">',
        html, count=1
    )

    # Prepend OG/Twitter title+description overrides and canonical link
    og_tags = (
        f'<link rel="canonical" href="{safe_url}">\n'
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
    for select in (
        'id,name,description,idea,build_time,cost,emoji,author,cat,status,upvotes,demo,tools,created_at,screenshot_url',
        'id,name,description,idea,build_time,cost,emoji,author,cat,status,upvotes,demo,tools,created_at',
    ):
        path = f"projects?status=eq.{safe_s}&order=created_at.asc&select={select}"
        data, err = _sb_service_request('GET', path)
        if err and ('screenshot_url' in err or ('column' in err.lower() and 'does not exist' in err.lower())):
            continue  # retry without screenshot_url
        return data or [], err
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
                'set it in Secrets to enable admin deletion')
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


# ── Supabase Storage helpers ─────────────────────────────────────────────────

def _storage_request(method, path, data=None, content_type='application/json'):
    """Make a Supabase Storage API request with the service key."""
    if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
        return None, 'Storage not configured'
    url = f"{SUPABASE_URL}/storage/v1/{path}"
    headers = {
        'apikey': SUPABASE_SERVICE_KEY,
        'Authorization': f'Bearer {SUPABASE_SERVICE_KEY}',
        'Content-Type': content_type,
    }
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read(), None
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        return None, f'HTTP {e.code}: {body[:200]}'
    except Exception as ex:
        return None, str(ex)


def _ensure_storage_bucket():
    """Create the project-screenshots storage bucket if it doesn't exist."""
    if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
        return
    payload = json.dumps({'id': SCREENSHOT_BUCKET, 'name': SCREENSHOT_BUCKET, 'public': True}).encode()
    _, err = _storage_request('POST', 'bucket', data=payload)
    if err:
        if 'already exists' in err.lower() or 'HTTP 409' in err:
            app.logger.debug('Storage bucket "%s" already exists.', SCREENSHOT_BUCKET)
        else:
            app.logger.warning('Could not create storage bucket "%s": %s', SCREENSHOT_BUCKET, err)
    else:
        app.logger.info('Storage bucket "%s" created successfully.', SCREENSHOT_BUCKET)


def _column_exists(column_name):
    """Return True if column exists in projects table (probe via anon GET)."""
    if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
        return True  # assume exists when not configured
    check_url = (SUPABASE_URL.rstrip('/') +
                 f'/rest/v1/projects?select={column_name}&limit=0')
    req = urllib.request.Request(check_url, headers={
        'apikey': SUPABASE_SERVICE_KEY,
        'Authorization': f'Bearer {SUPABASE_SERVICE_KEY}',
    })
    try:
        with urllib.request.urlopen(req, timeout=8):
            return True
    except urllib.error.HTTPError as e:
        body = e.read().decode().lower()
        if column_name in body or 'column' in body or 'does not exist' in body:
            return False
        return True  # unexpected error — assume exists
    except Exception:
        return True  # network error — assume exists


def _run_migration_via_psycopg2(sql):
    """Execute DDL via a direct PostgreSQL connection (DATABASE_URL env var).
    Returns (success, error_msg)."""
    try:
        import psycopg2
    except ImportError:
        return False, 'psycopg2 not installed'
    db_url = DATABASE_URL
    if not db_url:
        return False, 'DATABASE_URL not set'
    try:
        conn = psycopg2.connect(db_url, connect_timeout=10)
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(sql)
        conn.close()
        return True, None
    except Exception as ex:
        return False, str(ex)


def _run_migration_via_mgmt_api(sql):
    """Attempt DDL via Supabase Management REST API (requires management PAT as service key).
    Returns (success, error_msg)."""
    if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
        return False, 'not configured'
    m = re.match(r'https://([^.]+)\.supabase\.co', SUPABASE_URL.rstrip('/'))
    if not m:
        return False, 'cannot parse project ref from SUPABASE_URL'
    project_ref = m.group(1)
    mgmt_url = f'https://api.supabase.com/v1/projects/{project_ref}/database/query'
    payload = json.dumps({'query': sql}).encode()
    req = urllib.request.Request(mgmt_url, data=payload, headers={
        'Authorization': f'Bearer {SUPABASE_SERVICE_KEY}',
        'Content-Type': 'application/json',
    }, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=10):
            return True, None
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        return False, f'HTTP {e.code}: {body[:150]}'
    except Exception as ex:
        return False, str(ex)


def _ensure_screenshot_column():
    """Try to add screenshot_url column at startup via available mechanisms."""
    if _column_exists('screenshot_url'):
        app.logger.debug('screenshot_url column already exists.')
        return
    sql = 'ALTER TABLE projects ADD COLUMN IF NOT EXISTS screenshot_url TEXT;'
    # 1. Try direct PostgreSQL connection (most reliable — needs DATABASE_URL secret)
    ok, err = _run_migration_via_psycopg2(sql)
    if ok:
        app.logger.info('screenshot_url column added via direct DB connection.')
        return
    app.logger.debug('psycopg2 migration skipped/failed: %s', err)
    # 2. Fall back to Supabase Management API (needs management PAT as service key)
    ok, err = _run_migration_via_mgmt_api(sql)
    if ok:
        app.logger.info('screenshot_url column added via Management API.')
        return
    app.logger.warning(
        'Could not auto-migrate (tried psycopg2 + Management API: %s). '
        'ACTION REQUIRED — run once in Supabase SQL Editor:\n  %s', err, sql
    )


def _startup_init():
    """Run once at startup: ensure storage bucket exists and verify screenshot column."""
    _ensure_storage_bucket()
    _ensure_screenshot_column()


# Run startup tasks in a background thread so gunicorn boot stays fast
threading.Thread(target=_startup_init, daemon=True).start()


# ── Public routes ─────────────────────────────────────────────────────────────

@app.route('/')
def index():
    pid = request.args.get('project', '').strip()
    if pid:
        return redirect(url_for('project_detail', project_id=pid), code=301)
    return serve_app()



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
        project_url = base_url + '/p/' + urllib.parse.quote(str(project_id), safe='')
        html = _inject_project_og(html, project, project_url)
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

    # 1b. Derive canonical author handle from JWT — cannot be spoofed by payload
    jwt_handle = _derive_author_handle(user)

    # 1c. Rate limit — max 5 submissions per authenticated author per hour
    #     Key is JWT-derived (tamper-proof) and checked via Supabase (works across all workers)
    if not _rate_limit_submit_supabase(jwt_handle):
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

    raw_screenshot_url = _s('screenshot_url', 500)
    screenshot_url = _safe_url(raw_screenshot_url) if raw_screenshot_url else None
    if screenshot_url == '#':
        screenshot_url = None

    new_project = {
        'name':        name,
        'description': description,
        'idea':        _s('idea'),
        'build_time':  _s('build_time', 200),
        'cost':        _s('cost', 200),
        'demo':        _safe_url(_s('demo', 500)),
        'tools':       [str(t).strip()[:100] for t in (payload.get('tools') or []) if str(t).strip()][:20],
        'score':       None,
        'author':      jwt_handle,  # always set from JWT, not from client payload
        'emoji':       _s('emoji', 10) or '🚀',
        'cat':         _s('cat', 100) or 'Other',
        'upvotes':     0,
        'status':      'pending',
    }
    # Only include screenshot_url when actually provided — keeps inserts safe on old schemas
    if screenshot_url:
        new_project['screenshot_url'] = screenshot_url

    # 3. Insert using service key (bypasses RLS — safe because we verified the JWT)
    _, err = _sb_service_request('POST', 'projects', new_project)
    if err:
        # If insert failed because screenshot_url column is missing, retry without it
        if screenshot_url and ('screenshot_url' in err or 'column' in err.lower()):
            app.logger.warning('submit_project: screenshot_url column missing, retrying without: %s', err)
            fallback = {k: v for k, v in new_project.items() if k != 'screenshot_url'}
            _, err = _sb_service_request('POST', 'projects', fallback)
    if err:
        app.logger.error('submit_project DB insert failed: %s', err)
        return {'ok': False, 'error': 'Could not save project. Please try again later.'}, 500

    # 4. Send emails in a background thread (truly non-blocking)
    site_url   = BASE_URL_OVERRIDE or request.host_url.rstrip('/')
    admin_url  = site_url + '/admin'
    user_email = user.get('email', '').strip()

    admin_body = (
        f"New project submitted for review on CheckMyVibeCode!\n\n"
        f"Name:        {name}\n"
        f"Author:      {new_project['author']}\n"
        f"Category:    {new_project['cat']}\n"
        f"Demo URL:    {new_project['demo']}\n"
        f"Description: {description[:300]}\n\n"
        f"Review it here: {admin_url}\n"
    )
    confirm_body = (
        f"Hey {jwt_handle},\n\n"
        f"Thanks for submitting \"{name}\" to CheckMyVibeCode! \U0001f389\n\n"
        f"Your project is now in our review queue. We\u2019ll take a look and approve it\n"
        f"shortly. Once approved, it will appear on the platform and the community\n"
        f"can start upvoting and commenting.\n\n"
        f"In the meantime, feel free to browse other builds:\n"
        f"{site_url}\n\n"
        f"Questions? Reply to this email or reach us at contact@checkmyvibecode.com\n\n"
        f"\u2014 The CheckMyVibeCode team\n"
    )

    def _notify():
        ok, email_err = _send_resend_email(
            to='contact@checkmyvibecode.com',
            subject=f'[CheckMyVibeCode] New submission: {name}',
            text_body=admin_body,
        )
        if not ok:
            app.logger.warning('Submit admin email notify failed: %s', email_err)
        if user_email:
            ok2, err2 = _send_resend_email(
                to=user_email,
                subject='Your project is under review — CheckMyVibeCode',
                text_body=confirm_body,
            )
            if not ok2:
                app.logger.warning('Submit confirmation email failed: %s', err2)
    threading.Thread(target=_notify, daemon=True).start()

    return {'ok': True}, 201


@app.route('/api/upload-screenshot', methods=['POST'])
def upload_screenshot():
    """Upload a project screenshot to Supabase Storage.
    Requires a valid Supabase JWT. Accepts multipart/form-data with a 'screenshot' file field.
    Returns {'ok': True, 'url': '<public_url>'} on success."""
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return {'ok': False, 'error': 'Unauthorized'}, 401
    user = _verify_supabase_token(auth_header[7:])
    if not user:
        return {'ok': False, 'error': 'Invalid or expired session'}, 401

    file = request.files.get('screenshot')
    if not file:
        return {'ok': False, 'error': 'No file provided'}, 400

    content_type = (file.content_type or '').split(';')[0].strip().lower()
    if content_type not in ALLOWED_IMAGE_TYPES:
        return {'ok': False, 'error': 'Only jpg, png, gif, webp images are allowed'}, 400

    data = file.read(MAX_SCREENSHOT_BYTES + 1)
    if len(data) > MAX_SCREENSHOT_BYTES:
        return {'ok': False, 'error': 'Image must be 5 MB or smaller'}, 413

    ext = IMAGE_EXT_MAP.get(content_type, 'jpg')
    filename = f"{secrets.token_hex(16)}.{ext}"

    # Use PUT so the request is idempotent and aligns with Supabase Storage semantics
    _, err = _storage_request(
        'PUT',
        f'object/{SCREENSHOT_BUCKET}/{filename}',
        data=data,
        content_type=content_type,
    )
    if err:
        app.logger.error('Screenshot upload failed: %s', err)
        return {'ok': False, 'error': 'Upload failed, please try again'}, 502

    public_url = f"{SUPABASE_URL}/storage/v1/object/public/{SCREENSHOT_BUCKET}/{filename}"
    return {'ok': True, 'url': public_url}


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
    base_qs = f'&status=eq.approved&author=eq.{safe_handle}&order=upvotes.desc'
    for select in (
        'id,name,description,emoji,author,cat,upvotes,demo,tools,created_at,screenshot_url',
        'id,name,description,emoji,author,cat,upvotes,demo,tools,created_at',
    ):
        endpoint = (SUPABASE_URL.rstrip('/') +
                    f'/rest/v1/projects?select={select}{base_qs}')
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
        except urllib.error.HTTPError as e:
            err_body = e.read().decode().lower()
            if 'screenshot_url' in err_body or ('column' in err_body and 'does not exist' in err_body):
                continue  # retry without screenshot_url
            app.logger.error('api_profile error for %s: %s', handle, e)
            return {'error': 'Could not fetch profile'}, 502
        except Exception as e:
            app.logger.error('api_profile error for %s: %s', handle, e)
            return {'error': 'Could not fetch profile'}, 502
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


# ── Sitemap ───────────────────────────────────────────────────────────────────

@app.route('/sitemap.xml')
def sitemap():
    """Dynamic XML sitemap: homepage + all approved project pages."""
    base_url = (BASE_URL_OVERRIDE or request.host_url.rstrip('/')).rstrip('/')

    urls = []

    # Homepage (highest priority)
    urls.append({'loc': base_url + '/', 'changefreq': 'daily', 'priority': '1.0'})

    # All approved projects
    try:
        raw, err = _sb_get('projects', 'status=eq.approved&select=id,updated_at')
        if raw and not err:
            rows = json.loads(raw)
            for row in rows:
                pid = str(row.get('id', ''))
                if not pid:
                    continue
                loc = base_url + '/p/' + urllib.parse.quote(pid, safe='')
                # updated_at may be "2024-01-15T10:30:00+00:00" — take date part only
                raw_ts = row.get('updated_at') or ''
                lastmod = raw_ts[:10] if len(raw_ts) >= 10 else ''
                entry = {'loc': loc, 'changefreq': 'weekly', 'priority': '0.7'}
                if lastmod:
                    entry['lastmod'] = lastmod
                urls.append(entry)
    except Exception:
        pass  # if Supabase is unavailable, serve homepage-only sitemap

    lines = ['<?xml version="1.0" encoding="UTF-8"?>',
             '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    for u in urls:
        lines.append('  <url>')
        lines.append(f'    <loc>{html_module.escape(u["loc"])}</loc>')
        if 'lastmod' in u:
            lines.append(f'    <lastmod>{html_module.escape(u["lastmod"])}</lastmod>')
        lines.append(f'    <changefreq>{u["changefreq"]}</changefreq>')
        lines.append(f'    <priority>{u["priority"]}</priority>')
        lines.append('  </url>')
    lines.append('</urlset>')

    xml = '\n'.join(lines)
    resp = Response(xml, mimetype='application/xml')
    resp.headers['Cache-Control'] = 'public, max-age=3600'
    return resp


# ── robots.txt ────────────────────────────────────────────────────────────────

@app.route('/robots.txt')
def robots():
    base_url = (BASE_URL_OVERRIDE or request.host_url.rstrip('/')).rstrip('/')
    sitemap_url = base_url + '/sitemap.xml'
    body = (
        "User-agent: *\n"
        "Disallow: /admin\n"
        "Disallow: /api/\n"
        f"Sitemap: {sitemap_url}\n"
    )
    return Response(body, mimetype='text/plain')

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
