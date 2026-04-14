-- Migration: comment_upvotes table
-- Stores upvotes on comments (project comments + forum replies)
-- Each user can upvote a comment at most once (enforced by primary key)

CREATE TABLE IF NOT EXISTS comment_upvotes (
  comment_id uuid NOT NULL,
  user_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (comment_id, user_id)
);

-- Index for fast lookup: "how many upvotes does this comment have?"
CREATE INDEX IF NOT EXISTS idx_comment_upvotes_comment_id ON comment_upvotes (comment_id);

-- Index for fast lookup: "which comments has this user upvoted?"
CREATE INDEX IF NOT EXISTS idx_comment_upvotes_user_id ON comment_upvotes (user_id);

-- RLS policies
ALTER TABLE comment_upvotes ENABLE ROW LEVEL SECURITY;

-- Everyone can read upvotes
CREATE POLICY "comment_upvotes_select" ON comment_upvotes
  FOR SELECT USING (true);

-- Authenticated users can insert their own upvotes
CREATE POLICY "comment_upvotes_insert" ON comment_upvotes
  FOR INSERT WITH CHECK (auth.uid() = user_id);

-- Authenticated users can delete their own upvotes
CREATE POLICY "comment_upvotes_delete" ON comment_upvotes
  FOR DELETE USING (auth.uid() = user_id);
