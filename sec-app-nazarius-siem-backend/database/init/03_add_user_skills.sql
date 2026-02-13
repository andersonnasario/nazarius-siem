-- Migration: Add skills and specializations columns to users table
-- Date: 2026-02-09
-- Description: Adds skills and specializations arrays for Alert Triage analyst profiles

-- Add skills column if not exists
DO $$ 
BEGIN 
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='users' AND column_name='skills') THEN
        ALTER TABLE users ADD COLUMN skills TEXT[];
    END IF;
END $$;

-- Add specializations column if not exists
DO $$ 
BEGIN 
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='users' AND column_name='specializations') THEN
        ALTER TABLE users ADD COLUMN specializations TEXT[];
    END IF;
END $$;

-- Comments
COMMENT ON COLUMN users.skills IS 'Array of technical skills for alert triage (e.g., alert_analysis, incident_response)';
COMMENT ON COLUMN users.specializations IS 'Array of specialization areas for alert triage (e.g., siem, pci_dss)';
