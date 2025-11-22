-- Add system_settings table for admin configurable settings
CREATE TABLE IF NOT EXISTS system_settings (
  id VARCHAR PRIMARY KEY DEFAULT gen_random_uuid(),
  key TEXT NOT NULL UNIQUE,
  value TEXT NOT NULL,
  updated_at TIMESTAMP DEFAULT NOW(),
  updated_by VARCHAR REFERENCES users(id)
);

-- Insert default ENT date (January 16, 2025)
INSERT INTO system_settings (key, value) 
VALUES ('ent_exam_date', '2025-01-16T00:00:00.000Z')
ON CONFLICT (key) DO NOTHING;
