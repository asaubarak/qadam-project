-- Add question type column to track question format
ALTER TABLE questions 
ADD COLUMN question_type VARCHAR(50) DEFAULT 'single_choice';

-- Add difficulty level column (A=basic, B=medium, C=advanced)
ALTER TABLE questions
ADD COLUMN difficulty_level VARCHAR(10) DEFAULT 'A';

-- Add context_id for contextual questions that belong to same passage
ALTER TABLE questions
ADD COLUMN context_id VARCHAR(36);

-- Update testResults to track earned points separately
ALTER TABLE test_results
ADD COLUMN earned_points INTEGER DEFAULT 0,
ADD COLUMN total_points INTEGER DEFAULT 0;

-- Create index for faster queries
CREATE INDEX idx_questions_context_id ON questions(context_id);
CREATE INDEX idx_questions_question_type ON questions(question_type);
CREATE INDEX idx_questions_difficulty ON questions(difficulty_level);
