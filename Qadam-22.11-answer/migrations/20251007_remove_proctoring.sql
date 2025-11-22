-- Migration: remove proctoring artifacts
-- Created: 2025-10-07
-- Safe procedure:
-- 1) Create a backup table `backup_video_recordings` if `video_recordings` exists
-- 2) Copy all data into backup table
-- 3) Drop `video_recordings` table
-- 4) Drop column `requires_proctoring` from `blocks` if exists

BEGIN;

-- Create backup if video_recordings exists
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'video_recordings') THEN
        -- Create backup table (if not exists) and copy data
        IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'backup_video_recordings') THEN
            CREATE TABLE backup_video_recordings AS TABLE video_recordings WITH NO DATA;
        END IF;
        INSERT INTO backup_video_recordings SELECT * FROM video_recordings;
        -- Optionally drop the original table
        DROP TABLE video_recordings;
    END IF;
END$$;

-- Drop the column from blocks if it exists
ALTER TABLE IF EXISTS blocks DROP COLUMN IF EXISTS requires_proctoring;

COMMIT;

-- Notes:
-- - This migration creates a backup table `backup_video_recordings` in the same DB. Move it to long-term storage if needed.
-- - For large datasets consider using pg_dump or streaming the data out before DROP.
-- - Run in a maintenance window on production and ensure you have a DB snapshot.
