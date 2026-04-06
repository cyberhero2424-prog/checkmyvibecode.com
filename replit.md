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
- `notifications` — in-app notifications (user_id, type, project_id, actor_handle, message, read)

## Pending SQL Migrations
Run `migrations/forum.sql` in the Supabase Dashboard > SQL Editor to enable the Forum feature.
The notifications table is auto-created at startup via `_apply_notifications_migration()`, or run `migrations/notifications.sql` manually.

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
- Contact: support@checkmyvibecode.com

## Static Files
- `static/logo2.png` — nav logo
- `static/logo-preloader.png` — preloader logo
- `static/og-image.png` — 1200×630 OG image
- `static/favicon-logo.png` — favicon + apple-touch-icon (the grid/checkmark logo)

## Email Notifications (via Resend)
- **Submission confirmation** — sent when user submits a project
- **Approval notification** — sent when admin approves a project ("Your project is live!")
- **Comment notification** — sent to project owner when someone comments (skips self-comments)
- **Upvote notification** — sent to project owner on upvote (throttled: max 1/project/hour)
- All emails are plain-text, sent from `noreply@checkmyvibecode.com` via Resend API
- Helper `_resolve_handle_to_email()` maps author handles to emails via Supabase Auth admin API (cached 10min)
- Helper `_get_project_owner()` looks up project name + author for a project_id

## Email Unsubscribe System
- Users can unsubscribe from all notification emails via a signed link in the email footer
- `/unsubscribe` GET endpoint verifies HMAC token, stores email in `email_unsubscribes` table
- All `_notify_*` functions check `_is_unsubscribed(email)` before sending
- All notification emails include an unsubscribe footer link via `_unsubscribe_footer(email)`
- HMAC tokens are generated using `FLASK_SECRET_KEY`

## Project Statistics
- `view_count` — incremented when a user opens a project drawer (deduplicated per session + server-side per IP)
- `click_count` — incremented when a user clicks "View Project" demo link (same deduplication)
- Displayed on project cards (eye icon + count) and in the drawer info-grid (Views + Demo Clicks)
- POST endpoints: `/api/projects/<id>/view` and `/api/projects/<id>/click`

## SEO & Structured Data
- **JSON-LD**: SoftwareApplication schema on project pages, ItemList on homepage, ProfilePage on profile pages
- **SSR**: Noscript blocks with project data injected server-side for search engine crawlers
- **Sitemap**: Dynamic XML sitemap includes homepage, all approved project pages (`/p/<id>`), and all author profile pages (`/u/<handle>`) with lastmod dates
- **Meta tags**: OG/Twitter tags on project + profile pages; canonical URL + description meta on profile pages
- **XSS protection**: All JSON-LD output escaped with `</ → <\/` to prevent script injection

## User Profile Features
- **Profile picture**: Users set a URL-based avatar in Account Settings (stored in Supabase `user_metadata.avatar_url`)
- **Bio**: Short text bio (max 150 chars) in Account Settings (stored in `user_metadata.bio`)
- **Profile panel**: Shows avatar image + bio on user profiles; falls back to emoji/initial if no avatar
- **Nav avatar**: Shows profile picture in navbar when set; falls back to initial letter
- **API**: `/api/profile-meta/<handle>` returns `{avatar_url, bio}` for any user (cached 2min, paginated up to 5000 users)

## Migrations
- `migrations/bookmarks.sql` — bookmarks table + RLS
- `migrations/forum.sql` — forum tables + RLS (run in Supabase dashboard)
- `migrations/email_unsubscribes.sql` — email unsubscribe list + RLS (run in Supabase dashboard)
- `migrations/project_stats.sql` — view_count + click_count columns on projects (run in Supabase dashboard)
