#!/usr/bin/env python3
"""One-time script: rename every @info handle in auth.users metadata to be unique.

This targets users whose stored handle is exactly '@info' (the most common
collision), but the GENERIC_PREFIXES set can be extended to cover others.
It does NOT touch users who already have a unique, non-generic handle.

Usage:
    SUPABASE_URL=https://xxx.supabase.co \
    SUPABASE_SERVICE_KEY=<service_role_key> \
    python scripts/fix_info_handles.py [--dry-run]
"""

import os, sys, re, hashlib, argparse
import requests

SUPABASE_URL = os.environ["SUPABASE_URL"].rstrip("/")
SERVICE_KEY  = os.environ["SUPABASE_SERVICE_KEY"]
HEADERS      = {"apikey": SERVICE_KEY, "Authorization": f"Bearer {SERVICE_KEY}"}

GENERIC_PREFIXES = {"info", "admin", "contact", "hello", "support",
                    "mail", "noreply", "no-reply", "sales", "team"}


def list_all_users():
    users, page = [], 1
    while True:
        r = requests.get(
            f"{SUPABASE_URL}/auth/v1/admin/users",
            headers=HEADERS,
            params={"page": page, "per_page": 1000},
        )
        r.raise_for_status()
        batch = r.json().get("users", [])
        users.extend(batch)
        if len(batch) < 1000:
            break
        page += 1
    return users


def derive_better_handle(user):
    """Return the preferred handle based on domain, mirroring app.py logic."""
    meta  = user.get("user_metadata") or {}
    email = user.get("email", "")
    if not email or "@" not in email:
        return None
    prefix, domain = email.split("@", 1)
    domain_name = domain.split(".")[0] if domain else ""
    if prefix.lower() in GENERIC_PREFIXES and domain_name:
        return "@" + domain_name
    return None  # prefix is already fine, no change needed


def update_user_handle(user_id, new_handle, dry_run):
    if dry_run:
        print(f"  [dry-run] would set handle={new_handle} for {user_id}")
        return
    r = requests.put(
        f"{SUPABASE_URL}/auth/v1/admin/users/{user_id}",
        headers={**HEADERS, "Content-Type": "application/json"},
        json={"user_metadata": {"handle": new_handle}},
    )
    r.raise_for_status()
    print(f"  Updated {user_id} → {new_handle}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    print("Fetching all users…")
    users = list_all_users()
    print(f"Found {len(users)} users total.")

    # Track handles we've already assigned in this run to avoid new collisions
    assigned: set[str] = set()

    candidates = []
    for u in users:
        meta   = u.get("user_metadata") or {}
        handle = meta.get("handle", "")
        email  = u.get("email", "")
        if not handle or not email:
            continue
        prefix = email.split("@")[0] if "@" in email else ""
        if prefix.lower() in GENERIC_PREFIXES:
            candidates.append(u)

    print(f"{len(candidates)} users have a generic-prefix handle.")

    for u in candidates:
        uid    = u["id"]
        meta   = u.get("user_metadata") or {}
        old    = meta.get("handle", "")
        better = derive_better_handle(u)
        if better is None or better == old:
            continue

        # Ensure uniqueness within this batch
        candidate = better
        short_id  = uid.replace("-", "")[:6]
        suffix_n  = 0
        while candidate in assigned:
            suffix_n += 1
            candidate = f"{better}_{short_id}" if suffix_n == 1 else f"{better}_{short_id}{suffix_n}"

        assigned.add(candidate)
        print(f"  {uid}: {old!r} → {candidate!r}")
        update_user_handle(uid, candidate, args.dry_run)

    print("Done.")


if __name__ == "__main__":
    main()
