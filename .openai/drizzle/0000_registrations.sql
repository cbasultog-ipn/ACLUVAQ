CREATE TABLE IF NOT EXISTS registrations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  request_code TEXT NOT NULL UNIQUE,
  first_name TEXT NOT NULL,
  last_name TEXT NOT NULL,
  email TEXT NOT NULL,
  phone TEXT,
  company TEXT NOT NULL,
  club_member TEXT NOT NULL DEFAULT 'no_se',
  member_company TEXT,
  job_title TEXT NOT NULL,
  job_level TEXT NOT NULL,
  influence TEXT NOT NULL,
  interest TEXT,
  status TEXT NOT NULL DEFAULT 'pendiente',
  admin_notes TEXT,
  ticket_code TEXT UNIQUE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  reviewed_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_registrations_email ON registrations(lower(email));
CREATE INDEX IF NOT EXISTS idx_registrations_status_created ON registrations(status, created_at DESC);
