-- Add solution_image_url column to questions table
ALTER TABLE questions ADD COLUMN IF NOT EXISTS solution_image_url TEXT;
