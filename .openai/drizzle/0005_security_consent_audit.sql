ALTER TABLE registrations ADD COLUMN necessary_consent_at TEXT;
ALTER TABLE registrations ADD COLUMN privacy_notice_version TEXT;
ALTER TABLE registrations ADD COLUMN additional_comms_consent INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS admin_audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  registration_id INTEGER,
  details TEXT,
  ip_address TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON admin_audit_log(created_at DESC);

CREATE TABLE IF NOT EXISTS rate_limits (
  bucket TEXT PRIMARY KEY,
  hits INTEGER NOT NULL DEFAULT 1,
  window_started_at INTEGER NOT NULL
);

INSERT OR IGNORE INTO application_settings(setting_key,setting_value) VALUES ('public_registration_enabled','true');
INSERT OR IGNORE INTO application_settings(setting_key,setting_value) VALUES ('privacy_notice_url','');
INSERT OR IGNORE INTO application_settings(setting_key,setting_value) VALUES ('privacy_notice_version','2026-09');
