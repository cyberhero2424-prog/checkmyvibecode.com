-- Migration: comment_replies table
-- Stores nested replies on project comments (one level deep)

CREATE TABLE IF NOT EXISTS comment_replies (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  comment_id uuid NOT NULL,
  user_id uuid NOT NULL,
  author_handle text NOT NULL,
  body text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Fast lookup: all replies for a given comment
CREATE INDEX IF NOT EXISTS idx_comment_replies_comment_id ON comment_replies (comment_id);

-- RLS policies
ALTER TABLE comment_replies ENABLE ROW LEVEL SECURITY;

-- Everyone can read replies
CREATE POLICY "comment_replies_select" ON comment_replies
  FOR SELECT USING (true);

-- Authenticated users can insert their own replies
CREATE POLICY "comment_replies_insert" ON comment_replies
  FOR INSERT WITH CHECK (auth.uid() = user_id);

-- Authenticated users can delete their own replies
CREATE POLICY "comment_replies_delete" ON comment_replies
  FOR DELETE USING (auth.uid() = user_id);
