-- === Database (idempotent) ===
CREATE DATABASE IF NOT EXISTS widgetlogs
  DEFAULT CHARACTER SET utf8mb4
  DEFAULT COLLATE utf8mb4_unicode_ci;

USE widgetlogs;

-- === Table: proxy_logs (parsed rows, dedup by line_hash) ===
CREATE TABLE IF NOT EXISTS proxy_logs (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  line_hash CHAR(40) NOT NULL,              -- SHA1 of raw line (dedupe)
  vhost VARCHAR(255) NULL,
  remote_host VARCHAR(255) NULL,
  x_forwarded_for VARCHAR(255) NULL,
  time_iso VARCHAR(35) NULL,                -- original ISO with timezone
  time_utc DATETIME NULL,                   -- normalized to UTC for queries
  method VARCHAR(16) NULL,
  path TEXT NULL,
  http_version VARCHAR(16) NULL,
  query_string TEXT NULL, 
  status INT NULL,
  bytes BIGINT NULL,
  time_us BIGINT NULL,
  idm_trf_i VARCHAR(64) NULL,
  idm_srf_i VARCHAR(64) NULL,
  idm_trf_o VARCHAR(64) NULL,
  idm_srf_o VARCHAR(64) NULL,
  referer TEXT NULL,
  user_agent TEXT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_line_hash (line_hash),
  KEY idx_time_utc (time_utc),
  KEY idx_vhost_status (vhost, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- === Table: ingest_state (per-file checkpoint to avoid re-reading) ===
CREATE TABLE IF NOT EXISTS ingest_state (
  file_path VARCHAR(512) NOT NULL,          -- absolute path
  inode BIGINT UNSIGNED NULL,               -- for rotation detection
  last_offset BIGINT UNSIGNED NOT NULL DEFAULT 0,
  last_mtime DATETIME NULL,
  last_hash CHAR(40) NULL,                  -- last processed line hash
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (file_path)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- === Table: ingest_audit (per-run stats for troubleshooting) ===
CREATE TABLE IF NOT EXISTS ingest_audit (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  file_path VARCHAR(512) NOT NULL,
  started_at DATETIME NOT NULL,
  ended_at DATETIME NULL,
  lines_read BIGINT UNSIGNED NOT NULL DEFAULT 0,
  lines_inserted BIGINT UNSIGNED NOT NULL DEFAULT 0,
  lines_skipped BIGINT UNSIGNED NOT NULL DEFAULT 0,
  errors BIGINT UNSIGNED NOT NULL DEFAULT 0,
  note TEXT NULL,
  PRIMARY KEY (id),
  KEY idx_file_time (file_path, started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
