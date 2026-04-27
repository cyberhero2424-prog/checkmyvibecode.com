# checkmyvibecode.com

## What is this project?
A community platform where vibe coders (people who build apps with AI tools like Claude, Cursor, Lovable etc.) can submit, showcase and upvote their projects. Think Product Hunt, but exclusively for AI-built projects.

## Tech Stack
- Backend: Python / Flask (app.py)
- Database: Supabase (PostgreSQL with Row Level Security)
- Frontend: HTML / CSS / Vanilla JavaScript
- Templates: Jinja2 (templates/ folder)
- Hosting: Replit

## Project Structure
- app.py — all backend routes and business logic
- templates/ — HTML templates
- static/ — images, icons, og-image
- migrations/ — SQL migration files for Supabase

## Features already built (do NOT rebuild these)
- User profiles at /u/<handle>
- Project detail pages at /p/<project_id>
- Dynamic sitemap at /sitemap.xml
- Newsletter subscription system
- Follow / unfollow users
- Direct messages between users
- Notifications system
- Comment system with nested replies
- Upvotes on projects and comments
- Bookmarks (database table exists)
- Forum with threads and replies
- Admin panel at /admin
- Featured flag on projects (admin can toggle)
- View and click tracking per project

## Design Rules — never change these
- Background color: #0a0a09 (dark)
- Primary accent: #22c55e (green)
- Secondary colors: #3b82f6 (blue), #a855f7 (purple), #f59e0b (amber), #ef4444 (red)
- Always keep the dark theme — no light mode

## Rules for working on this project
- Always read and analyze app.py and the templates/ folder before making any changes
- Always show a plan before writing any code
- Never change the database schema without asking first
- Never touch authentication logic
- Never modify Replit config files (.replit, replit.nix)
- Implement one feature at a time, never multiple at once
