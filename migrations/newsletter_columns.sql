-- Migration: Add newsletter subscription columns to profiles
-- Run this in Supabase SQL Editor

-- Add newsletter_subscribed column (NULL = never shown modal, false = declined, true = subscribed)
ALTER TABLE profiles
  ADD COLUMN IF NOT EXISTS newsletter_subscribed boolean DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS newsletter_subscribed_at timestamptz DEFAULT NULL;

-- Index for quick lookup of subscribers
CREATE INDEX IF NOT EXISTS idx_profiles_newsletter
  ON profiles (newsletter_subscribed)
  WHERE newsletter_subscribed = true;
