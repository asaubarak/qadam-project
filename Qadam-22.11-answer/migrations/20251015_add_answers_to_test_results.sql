-- Add answers column to test_results table for storing user answers
ALTER TABLE test_results ADD COLUMN answers JSONB;