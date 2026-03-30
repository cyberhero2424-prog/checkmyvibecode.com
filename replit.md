# CheckMyVibeCode

"Product Hunt for vibe coding" — a community platform where users showcase AI-built projects.

## Stack
- **Backend**: Flask (Python) — `app.py`
- **Frontend**: Single-page HTML app — `checkmyvibecode-app.html` (source) → `index.html` (served)
- **Database**: Supabase (PostgreSQL) — Supabase JS SDK in browser
- **Auth**: Supabase Auth — Google OAuth + GitHub OAuth
- **Analytics**: GA4 (G-946DB9M5F4) — conditional on cookie consent
- **Production**: checkmyvibecode.com

## Important Workflow
**Always edit `checkmyvibecode-app.html`, then sync:**
```
cp checkmyvibecode-app.html index.html
```
Flask serves `index.html` (replaces `__BASE_URL__` and injects Supabase config).

## Supabase Tables
- `projects` — AI projects with upvotes, tools, score, author
- `upvotes` — (project_id, user_id) unique — project upvote deduplication
- `comments` — project comments
- `bookmarks` — (project_id, user_id) — saved projects
- `forum_threads` — forum posts (title, body, author_handle, author_id, upvotes, reply_count)
- `forum_replies` — replies to threads (thread_id, body, author_handle, author_id)
- `forum_thread_upvotes` — (thread_id, user_id) unique — forum upvote deduplication

## Pending SQL Migrations
Run `migrations/forum.sql` in the Supabase Dashboard > SQL Editor to enable the Forum feature.

## Pages (SPA via switchPage())
- `projects` — main feed with project cards
- `forum` — community forum with threads & replies
- `checker` — Code Checker (Coming Soon overlay)
- `privacy` — Privacy Policy
- `terms` — Terms of Service

## Key Config
- Supabase project ref: `cltqungsctxkzonqigcf`
- GA4 ID: `G-946DB9M5F4`
- Cookie consent key: `cookie_consent` in localStorage (`'granted'` or `'denied'`)
- Contact: contact@checkmyvibecode.com

## Static Files
- `static/logo2.png` — nav logo
- `static/logo-preloader.png` — preloader logo
- `static/og-image.png` — 1200×630 OG image

## Migrations
- `migrations/bookmarks.sql` — bookmarks table + RLS
- `migrations/forum.sql` — forum tables + RLS (run in Supabase dashboard)
