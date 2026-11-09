-- =====================================================================
-- Migration 001: email-only verification (removes phone / SMS)
-- For databases created by the older phone + SMS version of TrustVault.
-- A fresh install does not need this file (mysql_schema.sql already has it).
--
-- Run ONCE, as the MySQL root user, e.g.
--   docker compose exec -T db sh -c 'mysql -uroot -p"$MYSQL_ROOT_PASSWORD" trustvault' < backend/migrations/001_email_only.sql
-- Existing users, documents, grants and the audit trail are kept.
-- =====================================================================
SET NAMES utf8mb4;

-- Unused or half-finished verification state from the old flow
DELETE FROM otp_codes;
DELETE FROM pending_signups;

ALTER TABLE otp_codes
    DROP COLUMN channel,
    MODIFY COLUMN purpose ENUM('SIGNUP','RESET') NOT NULL;

ALTER TABLE pending_signups DROP COLUMN phone;
ALTER TABLE users DROP COLUMN phone;
