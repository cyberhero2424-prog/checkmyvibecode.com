-- Email unsubscribe list for notification preferences
-- Run this in Supabase Dashboard > SQL Editor

CREATE TABLE IF NOT EXISTS email_unsubscribes (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Allow service role full access (backend uses service key)
ALTER TABLE email_unsubscribes ENABLE ROW LEVEL SECURITY;

-- No public access — only the backend (service role) reads/writes this table
CREATE POLICY "Service role full access" ON email_unsubscribes
  FOR ALL USING (auth.role() = 'service_role');
