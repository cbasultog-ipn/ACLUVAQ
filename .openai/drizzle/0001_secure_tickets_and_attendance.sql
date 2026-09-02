ALTER TABLE registrations ADD COLUMN email_domain TEXT;
ALTER TABLE registrations ADD COLUMN email_type TEXT NOT NULL DEFAULT 'institucional';
ALTER TABLE registrations ADD COLUMN checked_in_at TEXT;
ALTER TABLE registrations ADD COLUMN checked_in_by TEXT;
CREATE INDEX IF NOT EXISTS idx_registrations_ticket_status ON registrations(ticket_code, status);
CREATE INDEX IF NOT EXISTS idx_registrations_checked_in ON registrations(checked_in_at) WHERE checked_in_at IS NOT NULL;
