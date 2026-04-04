import base64
import hashlib
import hmac
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
from flask import Flask, Response, send_from_directory, abort, redirect, url_for, request, session, render_template, jsonify
from flask_compress import Compress
from dotenv import load_dotenv
from whitenoise import WhiteNoise

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, 'static')

BLOCKED_NAMES = {'.env', '.git', 'app.py', 'requirements.txt'}
HTML_ENTRY_POINTS = {'index.html', 'checkmyvibecode-app.html'}

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32)
app.config['COMPRESS_MIMETYPES'] = [
    'text/html', 'text/css', 'text/javascript',
    'application/javascript', 'application/json',
]
app.config['COMPRESS_LEVEL'] = 6
app.config['COMPRESS_MIN_SIZE'] = 500
Compress(app)
app.wsgi_app = WhiteNoise(app.wsgi_app, root=STATIC_DIR, prefix='static', max_age=31536000)

# ── Simple in-process TTL cache ────────────────────────────────────────────────
_cache: dict = {}
_cache_lock = threading.Lock()

def _cache_get(key: str):
    """Return (value, hit) — hit=False means expired/missing."""
    with _cache_lock:
        entry = _cache.get(key)
        if entry and time.monotonic() < entry['exp']:
            return entry['val'], True
        return None, False

def _cache_set(key: str, value, ttl: int = 30):
    with _cache_lock:
        _cache[key] = {'val': value, 'exp': time.monotonic() + ttl}

def _cache_delete(*keys):
    with _cache_lock:
        for k in keys:
            _cache.pop(k, None)

SUPABASE_URL        = os.environ.get('SUPABASE_URL', '')
SUPABASE_ANON_KEY   = os.environ.get('SUPABASE_ANON_KEY', '')
SUPABASE_SERVICE_KEY = os.environ.get('SUPABASE_SERVICE_KEY', '')
ADMIN_PASSWORD      = os.environ.get('ADMIN_PASSWORD', '')
# Optional: Supabase direct PostgreSQL connection URL for startup DB migration.
# Find it in Supabase Dashboard > Project Settings > Database > Connection string (URI mode).
# Format: postgresql://postgres.[ref]:[password]@aws-0-[region].pooler.supabase.com:6543/postgres
SUPABASE_DB_URL     = os.environ.get('SUPABASE_DB_URL', '')
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
        'id,name,description,idea,build_time,cost,emoji,author,cat,status,upvotes,demo,tools,created_at,screenshot_url,featured',
        'id,name,description,idea,build_time,cost,emoji,author,cat,status,upvotes,demo,tools,created_at,screenshot_url',
        'id,name,description,idea,build_time,cost,emoji,author,cat,status,upvotes,demo,tools,created_at',
    ):
        path = f"projects?status=eq.{safe_s}&order=created_at.asc&select={select}"
        data, err = _sb_service_request('GET', path)
        if err and any(col in err for col in ('screenshot_url', 'featured')) or (
                err and 'column' in err.lower() and 'does not exist' in err.lower()):
            continue
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
    """Execute DDL via a direct PostgreSQL connection (SUPABASE_DB_URL env var).
    Returns (success, error_msg)."""
    try:
        import psycopg2
    except ImportError:
        return False, 'psycopg2 not installed'
    db_url = SUPABASE_DB_URL
    if not db_url:
        return False, 'SUPABASE_DB_URL not set'
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


def _apply_screenshot_migration():
    """Try all available migration SQLs. Returns (ok, message)."""
    migrations = [
        'ALTER TABLE projects ADD COLUMN IF NOT EXISTS screenshot_url TEXT;',
        'ALTER TABLE projects ADD COLUMN IF NOT EXISTS featured BOOLEAN DEFAULT false;',
    ]
    results = []
    for sql in migrations:
        col = sql.split('ADD COLUMN IF NOT EXISTS ')[1].split(' ')[0]
        if _column_exists(col):
            results.append(f'{col}: already exists')
            continue
        ok, err = _run_migration_via_psycopg2(sql)
        if ok:
            results.append(f'{col}: applied via psycopg2')
            continue
        ok2, err2 = _run_migration_via_mgmt_api(sql)
        if ok2:
            results.append(f'{col}: applied via mgmt API')
            continue
        hint = ('Set SUPABASE_DB_URL or run in Supabase SQL Editor: ' + sql)
        results.append(f'{col}: FAILED (psycopg2: {err}; mgmt: {err2}). {hint}')
    failed = [r for r in results if 'FAILED' in r]
    msg = '; '.join(results)
    return (len(failed) == 0), msg


def _ensure_screenshot_column():
    """Try to add screenshot_url column at startup via all available mechanisms."""
    try:
        ok, msg = _apply_screenshot_migration()
        if ok:
            app.logger.info('screenshot_url column: %s', msg)
        else:
            app.logger.warning('screenshot_url column migration failed at startup: %s', msg)
    except Exception as ex:
        app.logger.error('screenshot_url migration check raised: %s', ex)


def _apply_unsubscribe_migration():
    """Create email_unsubscribes table if it doesn't exist."""
    sql = (
        "CREATE TABLE IF NOT EXISTS email_unsubscribes ("
        "  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,"
        "  email TEXT NOT NULL UNIQUE,"
        "  created_at TIMESTAMPTZ DEFAULT now()"
        ");"
        "ALTER TABLE email_unsubscribes ENABLE ROW LEVEL SECURITY;"
        "DO $$ BEGIN "
        "IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='email_unsubscribes' AND policyname='Service role full access') THEN "
        "CREATE POLICY \"Service role full access\" ON email_unsubscribes FOR ALL USING (auth.role() = 'service_role'); "
        "END IF; END $$;"
    )
    rows, err = _sb_service_request('GET', 'email_unsubscribes?limit=0')
    if rows is not None:
        return
    ok, err = _run_migration_via_psycopg2(sql)
    if ok:
        app.logger.info('email_unsubscribes table created via psycopg2')
        return
    ok2, err2 = _run_migration_via_mgmt_api(sql)
    if ok2:
        app.logger.info('email_unsubscribes table created via mgmt API')
    else:
        app.logger.info('email_unsubscribes table not found — run migrations/email_unsubscribes.sql in Supabase Dashboard')


def _startup_init():
    """Run once at startup: ensure storage bucket exists and verify screenshot column."""
    _ensure_storage_bucket()
    _ensure_screenshot_column()
    _apply_unsubscribe_migration()


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


@app.route('/api/admin/init-storage', methods=['POST'])
def api_admin_init_storage():
    """Admin-only: ensure storage bucket exists and screenshot_url column is migrated.
    Call once after deploy if SUPABASE_DB_URL secret is set but startup migration was skipped."""
    if not _admin_logged_in():
        return {'ok': False, 'error': 'Unauthorized'}, 401
    # Bucket
    _ensure_storage_bucket()
    # Column
    mig_ok, mig_msg = _apply_screenshot_migration()
    return {
        'ok': mig_ok,
        'bucket': SCREENSHOT_BUCKET,
        'migration': mig_msg,
    }, 200 if mig_ok else 500


@app.route('/api/admin/run-migration', methods=['POST'])
def api_admin_run_migration():
    """Admin-only: alias for /api/admin/init-storage (migration + bucket init)."""
    return api_admin_init_storage()


@app.route('/api/admin/toggle-featured', methods=['POST'])
def api_admin_toggle_featured():
    """Admin-only: pin or unpin a project to the top of the feed.
    Body: {"project_id": "<uuid>", "featured": true|false}"""
    if not _admin_logged_in():
        return {'ok': False, 'error': 'Unauthorized'}, 401
    body = request.get_json(force=True, silent=True) or {}
    project_id = str(body.get('project_id', '')).strip()
    featured = body.get('featured')
    if featured is None or not isinstance(featured, bool):
        return {'ok': False, 'error': '"featured" must be a JSON boolean'}, 400
    if not project_id:
        return {'ok': False, 'error': 'project_id required'}, 400
    safe_id = urllib.parse.quote(project_id, safe='')
    rows, err = _sb_service_request('PATCH', f'projects?id=eq.{safe_id}',
                                    {'featured': featured})
    if err:
        app.logger.error('toggle-featured failed for %s: %s', project_id, err)
        return {'ok': False, 'error': 'Could not update project'}, 500
    if not rows:
        return {'ok': False, 'error': 'Project not found'}, 404
    _cache_delete('projects')
    return {'ok': True, 'featured': featured}


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
            _cache_delete('projects')
            session['flash_msg']  = 'Project permanently deleted.'
            session['flash_type'] = 'ok'
        return redirect(url_for('admin', tab=tab))

    new_status = 'approved' if action == 'approve' else 'rejected'
    err = _admin_set_status(project_id, new_status)

    if err:
        session['flash_msg']  = f'Error: {err}'
        session['flash_type'] = 'err'
    else:
        _cache_delete('projects')
        verb = 'approved' if new_status == 'approved' else 'rejected'
        session['flash_msg']  = f'Project {verb} successfully.'
        session['flash_type'] = 'ok'
        if new_status == 'approved':
            proj_name, author_handle = _get_project_owner(project_id)
            if proj_name and author_handle:
                _notify_project_approved(project_id, proj_name, author_handle)

    return redirect(url_for('admin', tab=tab))


@app.route('/admin/update-project-details', methods=['POST'])
def admin_update_project_details():
    if not _admin_logged_in():
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    project_id = data.get('id', '').strip()
    if not _UUID_RE.match(project_id):
        return jsonify({'error': 'Invalid project id'}), 400
    updates = {}
    if 'build_time' in data:
        val = (data['build_time'] or '').strip()[:200]
        updates['build_time'] = val or None
    if 'cost' in data:
        val = (data['cost'] or '').strip()[:200]
        updates['cost'] = val or None
    if not updates:
        return jsonify({'error': 'Nothing to update'}), 400
    result, err = _sb_service_request('PATCH', f'projects?id=eq.{project_id}', body=updates)
    if err:
        return jsonify({'error': f'Update failed: {err}'}), 500
    _cache_delete('projects')
    return jsonify({'ok': True})


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


def _make_unsubscribe_token(email):
    """Create an HMAC-signed token for the unsubscribe link."""
    return hmac.new(app.secret_key.encode() if isinstance(app.secret_key, str) else app.secret_key,
                    email.lower().encode(), hashlib.sha256).hexdigest()[:32]


def _verify_unsubscribe_token(email, token):
    """Verify an unsubscribe token matches the email."""
    expected = _make_unsubscribe_token(email)
    return hmac.compare_digest(expected, token)


def _unsubscribe_link(email):
    """Generate a full unsubscribe URL for an email address."""
    site_url = BASE_URL_OVERRIDE or 'https://checkmyvibecode.com'
    token = _make_unsubscribe_token(email)
    return f"{site_url}/unsubscribe?email={urllib.parse.quote(email)}&token={token}"


def _is_unsubscribed(email):
    """Check if an email has unsubscribed from notifications.
    Returns False if the table doesn't exist yet (graceful fallback)."""
    if not email:
        return False
    safe_email = urllib.parse.quote(email.lower(), safe='')
    rows, err = _sb_service_request('GET', f'email_unsubscribes?select=id&email=eq.{safe_email}&limit=1')
    if err:
        return False
    return bool(rows)


def _unsubscribe_footer(email):
    """Return the unsubscribe footer text to append to notification emails."""
    link = _unsubscribe_link(email)
    return f"\n---\nDon't want these emails? Unsubscribe: {link}\n"


_email_cache: dict = {}
_email_cache_lock = threading.Lock()

def _resolve_handle_to_email(handle):
    """Look up a user's email by their author handle (e.g. '@username').
    Uses Supabase Auth admin API. Cached for 10 minutes."""
    if not handle or not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
        return None
    clean = handle.lstrip('@').lower()
    if not clean:
        return None
    with _email_cache_lock:
        entry = _email_cache.get(clean)
        if entry and time.monotonic() < entry['exp']:
            return entry['val']
    try:
        req = urllib.request.Request(
            f"{SUPABASE_URL}/auth/v1/admin/users?page=1&per_page=1000",
            headers={
                'apikey': SUPABASE_SERVICE_KEY,
                'Authorization': f'Bearer {SUPABASE_SERVICE_KEY}',
            },
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
        users = data.get('users', [])
        for u in users:
            email = u.get('email', '')
            meta = u.get('user_metadata') or {}
            app_meta = u.get('app_metadata') or {}
            provider = app_meta.get('provider', '')
            if provider == 'github' and meta.get('user_name'):
                u_handle = str(meta['user_name']).lower()
            elif email:
                u_handle = email.split('@')[0].lower()
            else:
                u_handle = 'user_' + str(u.get('id', ''))[:8]
            if u_handle == clean and email:
                with _email_cache_lock:
                    _email_cache[clean] = {'val': email, 'exp': time.monotonic() + 600}
                return email
        with _email_cache_lock:
            _email_cache[clean] = {'val': None, 'exp': time.monotonic() + 300}
        return None
    except Exception as ex:
        app.logger.warning('_resolve_handle_to_email error: %s', ex)
        return None


def _get_project_owner(project_id):
    """Return (project_name, author_handle) for a project, or (None, None)."""
    safe_id = urllib.parse.quote(str(project_id), safe='')
    rows, err = _sb_service_request('GET', f'projects?select=name,author&id=eq.{safe_id}&limit=1')
    if err or not rows:
        return None, None
    return rows[0].get('name'), rows[0].get('author')


_upvote_notify_timestamps: dict = {}
_upvote_notify_lock = threading.Lock()

def _claim_upvote_throttle(project_id, throttle_secs=3600):
    """Atomically check and claim throttle slot. Returns True if claimed.
    Sets timestamp immediately to prevent concurrent threads from also claiming."""
    now = time.monotonic()
    with _upvote_notify_lock:
        last = _upvote_notify_timestamps.get(project_id, 0)
        if now - last < throttle_secs:
            return False
        _upvote_notify_timestamps[project_id] = now
        return True

def _release_upvote_throttle(project_id):
    """Release throttle slot if send failed, so next upvote can retry."""
    with _upvote_notify_lock:
        _upvote_notify_timestamps.pop(project_id, None)


def _notify_project_approved(project_id, project_name, author_handle):
    """Send 'your project is live' email to the project owner. Run in background thread."""
    def _do():
        email = _resolve_handle_to_email(author_handle)
        if not email:
            return
        if _is_unsubscribed(email):
            return
        site_url = BASE_URL_OVERRIDE or 'https://checkmyvibecode.com'
        project_url = f"{site_url}/p/{project_id}"
        body = (
            f"Hey {author_handle},\n\n"
            f"Great news! Your project \"{project_name}\" has been approved "
            f"and is now live on CheckMyVibeCode! \U0001f389\n\n"
            f"Check it out: {project_url}\n\n"
            f"Share it with the community to get upvotes and feedback.\n\n"
            f"Questions? Reply to this email or reach us at contact@checkmyvibecode.com\n\n"
            f"\u2014 The CheckMyVibeCode team"
            f"{_unsubscribe_footer(email)}"
        )
        ok, err = _send_resend_email(
            to=email,
            subject=f'Your project "{project_name}" is now live! — CheckMyVibeCode',
            text_body=body,
        )
        if not ok:
            app.logger.warning('Approval notification email failed for %s: %s', author_handle, err)
    threading.Thread(target=_do, daemon=True).start()


def _notify_new_comment(project_id, commenter_handle, comment_body):
    """Send 'new comment' email to the project owner. Run in background thread."""
    def _do():
        proj_name, owner_handle = _get_project_owner(project_id)
        if not proj_name or not owner_handle:
            return
        if owner_handle.lower() == commenter_handle.lower():
            return
        email = _resolve_handle_to_email(owner_handle)
        if not email:
            return
        if _is_unsubscribed(email):
            return
        site_url = BASE_URL_OVERRIDE or 'https://checkmyvibecode.com'
        project_url = f"{site_url}/p/{project_id}"
        preview = comment_body[:200] + ('...' if len(comment_body) > 200 else '')
        body = (
            f"Hey {owner_handle},\n\n"
            f"{commenter_handle} commented on your project \"{proj_name}\":\n\n"
            f"\"{preview}\"\n\n"
            f"See it here: {project_url}\n\n"
            f"\u2014 The CheckMyVibeCode team"
            f"{_unsubscribe_footer(email)}"
        )
        ok, err = _send_resend_email(
            to=email,
            subject=f'{commenter_handle} commented on "{proj_name}" — CheckMyVibeCode',
            text_body=body,
        )
        if not ok:
            app.logger.warning('Comment notification email failed for %s: %s', owner_handle, err)
    threading.Thread(target=_do, daemon=True).start()


def _notify_new_upvote(project_id, upvote_count):
    """Send 'new upvote' email to the project owner. Throttled. Run in background thread."""
    if not _claim_upvote_throttle(project_id):
        return
    def _do():
        proj_name, owner_handle = _get_project_owner(project_id)
        if not proj_name or not owner_handle:
            _release_upvote_throttle(project_id)
            return
        email = _resolve_handle_to_email(owner_handle)
        if not email:
            _release_upvote_throttle(project_id)
            return
        if _is_unsubscribed(email):
            _release_upvote_throttle(project_id)
            return
        site_url = BASE_URL_OVERRIDE or 'https://checkmyvibecode.com'
        project_url = f"{site_url}/p/{project_id}"
        body = (
            f"Hey {owner_handle},\n\n"
            f"Your project \"{proj_name}\" just got upvoted! \U0001f44d\n"
            f"It now has {upvote_count} upvote{'s' if upvote_count != 1 else ''}.\n\n"
            f"See it here: {project_url}\n\n"
            f"\u2014 The CheckMyVibeCode team"
            f"{_unsubscribe_footer(email)}"
        )
        ok, err = _send_resend_email(
            to=email,
            subject=f'Your project "{proj_name}" got upvoted! ({upvote_count} total) — CheckMyVibeCode',
            text_body=body,
        )
        if not ok:
            _release_upvote_throttle(project_id)
            app.logger.warning('Upvote notification email failed for %s: %s', owner_handle, err)
    threading.Thread(target=_do, daemon=True).start()


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


def _decode_jwt_user_id(token):
    """Decode a Supabase JWT locally (no network call) and return the user_id (sub claim).
    Checks expiry and issuer. Used for low-latency forum operations where the
    service key enforces actual DB security — we just need to know who the user is."""
    if not token:
        return None
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        padding = 4 - len(parts[1]) % 4
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=' * (padding % 4)).decode())
        if payload.get('exp', 0) < time.time():
            return None
        user_id = payload.get('sub')
        if not user_id:
            return None
        iss = payload.get('iss', '')
        if SUPABASE_URL and SUPABASE_URL.rstrip('/').split('//')[1].split('.')[0] not in iss:
            return None
        return user_id
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
    # Restrict screenshot URLs to our own Supabase Storage domain to prevent external injection
    if screenshot_url and SUPABASE_URL:
        storage_host = SUPABASE_URL.rstrip('/').split('://')[-1]
        if storage_host not in screenshot_url:
            app.logger.warning('submit_project: screenshot_url not from storage host, ignoring: %s', screenshot_url)
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
        # If the column is missing, fail visibly so screenshots are never silently dropped
        if screenshot_url and ('screenshot_url' in err or 'column' in err.lower()):
            app.logger.error(
                'submit_project: screenshot_url column missing — failing visibly. '
                'Run POST /api/admin/init-storage to apply the migration, or set '
                'SUPABASE_DB_URL and restart. DB error: %s', err
            )
            return {
                'ok': False,
                'error': 'Screenshot column not yet migrated. Please contact the site admin.',
            }, 500
    if err:
        app.logger.error('submit_project DB insert failed: %s', err)
        return {'ok': False, 'error': 'Could not save project. Please try again later.'}, 500

    # New submission doesn't affect public feed (status='pending') but invalidate anyway
    # so that if a project transitions quickly it won't show stale data
    _cache_delete('projects')

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
    so privacy browsers that block supabase.co cannot interfere.
    Responses are cached server-side for 60s to avoid Supabase round trips."""
    key = SUPABASE_ANON_KEY
    if not SUPABASE_URL or not key:
        return {'error': 'Server not configured'}, 503
    cached, hit = _cache_get('projects')
    if hit:
        resp = Response(cached, mimetype='application/json')
        resp.headers['Cache-Control'] = 'public, max-age=60'
        return resp
    base_qs = '&status=eq.approved&order=upvotes.desc'
    select_with = 'id,name,description,emoji,author,cat,upvotes,demo,tools,created_at,score,screenshot_url,featured,build_time,cost'
    select_without = 'id,name,description,emoji,author,cat,upvotes,demo,tools,created_at,score,screenshot_url,build_time,cost'
    select_bare = 'id,name,description,emoji,author,cat,upvotes,demo,tools,created_at,score,build_time,cost'
    for select in (select_with, select_without, select_bare):
        endpoint = (SUPABASE_URL.rstrip('/') +
                    f'/rest/v1/projects?select={select}{base_qs}')
        req = urllib.request.Request(endpoint, headers={
            'apikey': key,
            'Authorization': f'Bearer {key}',
        })
        try:
            with urllib.request.urlopen(req, timeout=8) as r:
                body = r.read()
            _cache_set('projects', body, ttl=30)
            resp = Response(body, mimetype='application/json')
            resp.headers['Cache-Control'] = 'public, max-age=60'
            return resp
        except urllib.error.HTTPError as e:
            err_body = e.read().decode().lower()
            if any(c in err_body for c in ('screenshot_url', 'featured')) or (
                    'column' in err_body and 'does not exist' in err_body):
                continue
            app.logger.error('api_projects error: %s', e)
            return {'error': 'Could not fetch projects'}, 502
        except Exception as e:
            app.logger.error('api_projects error: %s', e)
            return {'error': 'Could not fetch projects'}, 502
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


# ── Project upvote toggle (service-key, bypasses RLS) ──────────────────────────

@app.route('/api/projects/<project_id>/toggle-upvote', methods=['POST'])
def toggle_project_upvote(project_id):
    """Toggle upvote for a project. Uses service key so RLS cannot block writes."""
    import re
    if not re.match(r'^[0-9a-f-]{36}$', project_id):
        return {'error': 'Invalid project id'}, 400
    auth_header = request.headers.get('Authorization', '')
    token = auth_header[7:] if auth_header.startswith('Bearer ') else ''
    user_id = _decode_jwt_user_id(token)
    if not user_id:
        user = _verify_supabase_token(token)
        user_id = user.get('id') if user else None
    if not user_id:
        return {'error': 'Invalid or expired session'}, 401

    # Check if user already voted
    existing, err = _sb_service_request(
        'GET', f'upvotes?select=id&project_id=eq.{project_id}&user_id=eq.{user_id}&limit=1'
    )
    if err:
        app.logger.error('toggle_project_upvote check error: %s', err)
        return {'error': 'Database error'}, 502

    if existing:
        # Remove vote
        _, err = _sb_service_request(
            'DELETE', f'upvotes?project_id=eq.{project_id}&user_id=eq.{user_id}'
        )
        voted = False
    else:
        # Add vote
        _, err = _sb_service_request(
            'POST', 'upvotes', {'project_id': project_id, 'user_id': user_id}
        )
        voted = True

    if err:
        app.logger.error('toggle_project_upvote write error: %s', err)
        return {'error': 'Could not save vote'}, 502

    # Get authoritative count and update projects table
    rows, _ = _sb_service_request('GET', f'upvotes?select=id&project_id=eq.{project_id}')
    count = len(rows) if isinstance(rows, list) else None
    if count is not None:
        _sb_service_request('PATCH', f'projects?id=eq.{project_id}', {'upvotes': count})
    _cache_delete('projects')

    if voted and count is not None:
        _notify_new_upvote(project_id, count)

    return {'ok': True, 'voted': voted, 'count': count}


@app.route('/api/projects/user-votes')
def project_user_votes():
    """Return list of project IDs the current user has upvoted."""
    auth_header = request.headers.get('Authorization', '')
    token = auth_header[7:] if auth_header.startswith('Bearer ') else ''
    user_id = _decode_jwt_user_id(token)
    if not user_id:
        return json.dumps([]), 200, {'Content-Type': 'application/json'}
    rows, err = _sb_service_request('GET', f'upvotes?select=project_id&user_id=eq.{user_id}')
    if err or not rows:
        return json.dumps([]), 200, {'Content-Type': 'application/json'}
    return json.dumps([r['project_id'] for r in rows]), 200, {'Content-Type': 'application/json'}


# ── Project comments (service-key, bypasses RLS) ────────────────────────────

@app.route('/api/projects/<project_id>/upvote-count')
def get_project_upvote_count(project_id):
    """Return the upvote count for a project. Public."""
    if not re.match(r'^[0-9a-f-]{36}$', project_id):
        return jsonify({'error': 'Invalid project id'}), 400
    rows, err = _sb_service_request('GET', f'upvotes?select=id&project_id=eq.{project_id}')
    if err:
        return jsonify({'error': 'Could not fetch count'}), 502
    count = len(rows) if rows else 0
    return jsonify({'count': count})


@app.route('/api/projects/<project_id>/comments')
def get_project_comments(project_id):
    """Return comments for a project, newest first. Public — no auth required."""
    if not re.match(r'^[0-9a-f-]{36}$', project_id):
        return {'error': 'Invalid project id'}, 400
    rows, err = _sb_service_request(
        'GET', f'comments?select=id,author,body,user_id,created_at&project_id=eq.{project_id}&order=created_at.desc'
    )
    if err and 'user_id' in err:
        rows, err = _sb_service_request(
            'GET', f'comments?select=id,author,body,created_at&project_id=eq.{project_id}&order=created_at.desc'
        )
    if err:
        app.logger.error('get_project_comments error: %s', err)
        return {'error': 'Could not fetch comments'}, 502
    return json.dumps(rows or []), 200, {'Content-Type': 'application/json'}


@app.route('/api/projects/<project_id>/comments', methods=['POST'])
def post_project_comment(project_id):
    """Post a comment on a project. Auth required via JWT."""
    if not re.match(r'^[0-9a-f-]{36}$', project_id):
        return {'error': 'Invalid project id'}, 400
    auth_header = request.headers.get('Authorization', '')
    token = auth_header[7:] if auth_header.startswith('Bearer ') else ''
    user_id = _decode_jwt_user_id(token)
    verified_user = None
    if not user_id:
        verified_user = _verify_supabase_token(token)
        user_id = verified_user.get('id') if verified_user else None
    if not user_id:
        app.logger.warning('post_comment auth failed for project %s, token len=%s', project_id, len(token) if token else 0)
        return {'error': 'Invalid or expired session'}, 401
    try:
        payload = request.get_json(force=True) or {}
        body_text = str(payload.get('body', '')).strip()[:2000]
        author = str(payload.get('author', '')).strip()[:100]
        if not body_text:
            return {'error': 'Comment body is required'}, 400
    except Exception:
        return {'error': 'Bad request'}, 400
    result, err = _sb_service_request('POST', 'comments', {
        'project_id': project_id,
        'author': author,
        'body': body_text,
        'user_id': user_id,
    })
    if err:
        if 'user_id' in err or ('column' in err.lower() and 'does not exist' in err.lower()):
            result, err = _sb_service_request('POST', 'comments', {
                'project_id': project_id,
                'author': author,
                'body': body_text,
            })
    if err:
        app.logger.error('post_project_comment error: %s', err)
        return {'error': 'Could not save comment'}, 502
    jwt_handle = None
    if verified_user:
        jwt_handle = _derive_author_handle(verified_user)
    else:
        verified_user = _verify_supabase_token(token)
        if verified_user:
            jwt_handle = _derive_author_handle(verified_user)
    _notify_new_comment(project_id, jwt_handle or author, body_text)
    return json.dumps(result), 200, {'Content-Type': 'application/json'}


@app.route('/api/comments/<comment_id>', methods=['DELETE'])
def delete_comment(comment_id):
    """Delete a comment. Only the comment author can delete their own comment."""
    if not _UUID_RE.match(comment_id):
        return jsonify({'error': 'Invalid comment id'}), 400
    auth_header = request.headers.get('Authorization', '')
    token = auth_header[7:] if auth_header.startswith('Bearer ') else ''
    user_id = _decode_jwt_user_id(token)
    if not user_id:
        user = _verify_supabase_token(token)
        user_id = user.get('id') if user else None
    if not user_id:
        return jsonify({'error': 'Invalid or expired session'}), 401
    author_handle = str(request.args.get('author', '')).strip()
    rows, err = _sb_service_request('GET', f'comments?select=id,author&id=eq.{comment_id}&limit=1')
    if err or not rows:
        return jsonify({'error': 'Comment not found'}), 404
    if author_handle and rows[0].get('author') != author_handle:
        return jsonify({'error': 'You can only delete your own comments'}), 403
    _, err = _sb_service_request('DELETE', f'comments?id=eq.{comment_id}')
    if err:
        app.logger.error('delete_comment error: %s', err)
        return jsonify({'error': 'Could not delete comment'}), 502
    return jsonify({'ok': True})


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


_FORUM_THREAD_COLS = 'id,title,body,author_handle,created_at,upvotes'
_FORUM_REPLY_COLS  = 'id,thread_id,body,author_handle,created_at'


@app.route('/api/forum/threads')
def api_forum_threads():
    if not SUPABASE_URL or not SUPABASE_ANON_KEY:
        return {'error': 'Server not configured'}, 503
    cached, hit = _cache_get('forum_threads')
    if hit:
        resp = Response(cached, mimetype='application/json')
        resp.headers['Cache-Control'] = 'public, max-age=60'
        return resp
    body, err = _sb_get('forum_threads',
                         f'select={_FORUM_THREAD_COLS}&order=created_at.desc')
    if err:
        app.logger.error('api_forum_threads error: %s', err)
        return {'error': 'Could not fetch threads'}, 502
    _cache_set('forum_threads', body, ttl=30)
    resp = Response(body, mimetype='application/json')
    resp.headers['Cache-Control'] = 'public, max-age=60'
    return resp


_UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')


@app.route('/api/forum/threads/<thread_id>/replies')
def api_forum_replies(thread_id):
    if not SUPABASE_URL or not SUPABASE_ANON_KEY:
        return {'error': 'Server not configured'}, 503
    if not _UUID_RE.match(thread_id):
        return {'error': 'Invalid thread id'}, 400
    cache_key = f'forum_replies:{thread_id}'
    cached, hit = _cache_get(cache_key)
    if hit:
        resp = Response(cached, mimetype='application/json')
        resp.headers['Cache-Control'] = 'public, max-age=60'
        return resp
    body, err = _sb_get('forum_replies',
                         f'select={_FORUM_REPLY_COLS}&thread_id=eq.{thread_id}&order=created_at.asc')
    if err:
        app.logger.error('api_forum_replies error: %s', err)
        return {'error': 'Could not fetch replies'}, 502
    _cache_set(cache_key, body, ttl=30)
    resp = Response(body, mimetype='application/json')
    resp.headers['Cache-Control'] = 'public, max-age=60'
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
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return {'error': 'Unauthorized'}, 401
    user_id = _decode_jwt_user_id(auth_header[7:])
    if not user_id:
        return {'error': 'Invalid or expired session'}, 401
    try:
        payload = request.get_json(force=True) or {}
        title = str(payload.get('title', '')).strip()[:300]
        body_text = str(payload.get('body', '')).strip()[:5000]
        author_handle = str(payload.get('author_handle', '')).strip()[:100]
        if not title or not body_text:
            return {'error': 'Missing required fields'}, 400
    except Exception:
        return {'error': 'Bad request'}, 400
    result, err = _sb_service_request('POST', 'forum_threads',
                                      {'title': title, 'body': body_text,
                                       'author_handle': author_handle, 'author_id': user_id})
    if err:
        app.logger.error('api_forum_create_thread error: %s', err)
        return {'error': 'Could not create thread'}, 502
    _cache_delete('forum_threads')
    return Response(json.dumps(result), mimetype='application/json')


@app.route('/api/forum/threads/<thread_id>/replies', methods=['POST'])
def api_forum_create_reply(thread_id):
    if not SUPABASE_URL or not SUPABASE_ANON_KEY:
        return {'error': 'Server not configured'}, 503
    if not _UUID_RE.match(thread_id):
        return {'error': 'Invalid thread id'}, 400
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return {'error': 'Unauthorized'}, 401
    user_id = _decode_jwt_user_id(auth_header[7:])
    if not user_id:
        return {'error': 'Invalid or expired session'}, 401
    try:
        payload = request.get_json(force=True) or {}
        body_text = str(payload.get('body', '')).strip()[:5000]
        author_handle = str(payload.get('author_handle', '')).strip()[:100]
        if not body_text:
            return {'error': 'Missing required fields'}, 400
    except Exception:
        return {'error': 'Bad request'}, 400
    result, err = _sb_service_request('POST', 'forum_replies',
                                      {'thread_id': thread_id, 'body': body_text,
                                       'author_handle': author_handle, 'author_id': user_id})
    if err:
        app.logger.error('api_forum_create_reply error: %s', err)
        return {'error': 'Could not post reply'}, 502
    _cache_delete(f'forum_replies:{thread_id}')
    return Response(json.dumps(result), mimetype='application/json')


@app.route('/api/forum/user-votes')
def api_forum_user_votes():
    """Return forum thread IDs the current user has upvoted. No auth = empty list."""
    auth_header = request.headers.get('Authorization', '')
    token = auth_header[7:] if auth_header.startswith('Bearer ') else ''
    user_id = _decode_jwt_user_id(token)
    if not user_id:
        return Response('[]', mimetype='application/json')
    safe_uid = urllib.parse.quote(user_id, safe='')
    data, err = _sb_service_request('GET',
        f'forum_thread_upvotes?user_id=eq.{safe_uid}&select=thread_id')
    if err or not data:
        return Response('[]', mimetype='application/json')
    ids = [r['thread_id'] for r in data if r.get('thread_id')]
    resp = Response(json.dumps(ids), mimetype='application/json')
    resp.headers['Cache-Control'] = 'private, max-age=0'
    return resp


@app.route('/api/forum/threads/<thread_id>/toggle-upvote', methods=['POST'])
def api_forum_toggle_upvote(thread_id):
    """Toggle upvote for a forum thread. Returns {ok, voted, upvotes}."""
    if not SUPABASE_URL or not SUPABASE_ANON_KEY:
        return {'error': 'Server not configured'}, 503
    if not _UUID_RE.match(thread_id):
        return {'error': 'Invalid thread id'}, 400
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return {'error': 'Unauthorized'}, 401
    user_id = _decode_jwt_user_id(auth_header[7:])
    if not user_id:
        return {'error': 'Invalid or expired session'}, 401
    safe_tid = urllib.parse.quote(thread_id, safe='')
    safe_uid = urllib.parse.quote(user_id, safe='')
    existing, err = _sb_service_request('GET',
        f'forum_thread_upvotes?thread_id=eq.{safe_tid}&user_id=eq.{safe_uid}&select=id')
    if err:
        app.logger.error('api_forum_toggle_upvote check error: %s', err)
        return {'error': 'Could not check vote status'}, 502
    if existing:
        _, err = _sb_service_request('DELETE',
            f'forum_thread_upvotes?thread_id=eq.{safe_tid}&user_id=eq.{safe_uid}')
        if err:
            app.logger.error('api_forum_toggle_upvote delete error: %s', err)
            return {'error': 'Could not remove upvote'}, 502
        voted = False
    else:
        _, err = _sb_service_request('POST', 'forum_thread_upvotes',
                                     {'thread_id': thread_id, 'user_id': user_id})
        if err:
            app.logger.error('api_forum_toggle_upvote insert error: %s', err)
            return {'error': 'Could not add upvote'}, 502
        voted = True
    thread_data, _ = _sb_service_request('GET',
        f'forum_threads?id=eq.{safe_tid}&select=upvotes')
    current_count = thread_data[0].get('upvotes') or 0 if thread_data else 0
    new_count = max(0, current_count + (1 if voted else -1))
    _sb_service_request('PATCH', f'forum_threads?id=eq.{safe_tid}', {'upvotes': new_count})
    _cache_delete('forum_threads')
    return {'ok': True, 'voted': voted, 'upvotes': new_count}


# ── Sitemap ───────────────────────────────────────────────────────────────────

@app.route('/unsubscribe')
def unsubscribe():
    """Handle email unsubscribe requests via signed link."""
    email = request.args.get('email', '').strip().lower()
    token = request.args.get('token', '').strip()
    if not email or not token:
        return _unsubscribe_page('Invalid unsubscribe link.', success=False), 400
    if not _verify_unsubscribe_token(email, token):
        return _unsubscribe_page('Invalid or expired unsubscribe link.', success=False), 403
    if _is_unsubscribed(email):
        return _unsubscribe_page('You are already unsubscribed from notifications.', success=True)
    _, err = _sb_service_request('POST', 'email_unsubscribes', {'email': email})
    if err:
        if 'duplicate' in str(err).lower() or '23505' in str(err):
            return _unsubscribe_page('You are already unsubscribed from notifications.', success=True)
        app.logger.error('Unsubscribe insert failed for %s: %s', email, err)
        return _unsubscribe_page('Something went wrong. Please try again later.', success=False), 500
    app.logger.info('User unsubscribed from notifications: %s', email)
    return _unsubscribe_page('You have been unsubscribed from CheckMyVibeCode notifications.', success=True)


def _unsubscribe_page(message, success=True):
    icon = '\u2705' if success else '\u274c'
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Unsubscribe — CheckMyVibeCode</title>
<style>
body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; background:#f8f8f6; color:#1a1a18; }}
.card {{ text-align:center; background:#fff; border:1px solid #e5e5e3; border-radius:16px; padding:40px 32px; max-width:420px; box-shadow:0 2px 8px rgba(0,0,0,.06); }}
.icon {{ font-size:48px; margin-bottom:16px; }}
h1 {{ font-size:20px; margin:0 0 12px; }}
p {{ font-size:14px; color:#666; line-height:1.5; margin:0 0 20px; }}
a {{ color:#16a34a; text-decoration:none; font-weight:500; }}
a:hover {{ text-decoration:underline; }}
</style></head><body>
<div class="card">
<div class="icon">{icon}</div>
<h1>{'Unsubscribed' if success else 'Error'}</h1>
<p>{html_module.escape(message)}</p>
<p><a href="/">← Back to CheckMyVibeCode</a></p>
</div></body></html>"""


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
