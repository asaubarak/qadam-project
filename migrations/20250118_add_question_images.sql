-- Add image_url column to questions table
ALTER TABLE questions ADD COLUMN IF NOT EXISTS image_url TEXT;
