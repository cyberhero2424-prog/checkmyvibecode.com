-- Migration: Unique handle constraint + deduplicate existing @info collisions
-- Run this in Supabase SQL Editor

-- Step 1: Ensure the profiles table has a handle column
ALTER TABLE profiles
  ADD COLUMN IF NOT EXISTS handle text;

-- Step 2: Deduplicate any existing @info (or other generic) handles by appending
-- the first 6 chars of the user_id so each row becomes unique before we add the
-- constraint.  This is idempotent — rows that are already unique are untouched.
DO $$
DECLARE
  dup_handle text;
  rec        record;
  new_handle text;
  suffix     text;
BEGIN
  -- Find every handle that appears more than once
  FOR dup_handle IN
    SELECT handle
    FROM   profiles
    WHERE  handle IS NOT NULL
    GROUP  BY handle
    HAVING COUNT(*) > 1
  LOOP
    -- For each duplicate, keep the oldest row as-is, rename the rest
    FOR rec IN
      SELECT id, handle
      FROM   profiles
      WHERE  handle = dup_handle
      ORDER  BY created_at ASC NULLS LAST
      OFFSET 1   -- skip the first (oldest) owner
    LOOP
      suffix     := LEFT(REPLACE(rec.id::text, '-', ''), 6);
      new_handle := rec.handle || '_' || suffix;

      -- Make sure even the new handle isn't already taken
      WHILE EXISTS (SELECT 1 FROM profiles WHERE handle = new_handle) LOOP
        suffix     := LEFT(MD5(rec.id::text || suffix), 6);
        new_handle := rec.handle || '_' || suffix;
      END LOOP;

      UPDATE profiles SET handle = new_handle WHERE id = rec.id;
      RAISE NOTICE 'Renamed % → % for user %', dup_handle, new_handle, rec.id;
    END LOOP;
  END LOOP;
END $$;

-- Step 3: Add the unique constraint (safe now that duplicates are gone)
ALTER TABLE profiles
  ADD CONSTRAINT profiles_handle_unique UNIQUE (handle);

-- Step 4: Index for fast handle lookups
CREATE INDEX IF NOT EXISTS idx_profiles_handle ON profiles (handle);
