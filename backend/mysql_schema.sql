-- =====================================================================
-- TrustVault Enterprise V2 — MySQL 8.0+ schema
-- Loaded automatically by the MySQL container on first start
-- (/docker-entrypoint-initdb.d). For a manual install:
--     mysql -u root -p trustvault < mysql_schema.sql
-- =====================================================================
SET NAMES utf8mb4;
SET time_zone = '+00:00';

-- ---------------------------------------------------------------------
-- Users
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username        VARCHAR(32)  NOT NULL,
    display_name    VARCHAR(80)  NOT NULL,
    role            ENUM('ADMIN','OWNER','VIEWER') NOT NULL DEFAULT 'VIEWER',
    email           VARCHAR(254) NULL,
    password_hash   VARCHAR(255) NOT NULL,
    is_verified     TINYINT(1)   NOT NULL DEFAULT 0,
    is_blocked      TINYINT(1)   NOT NULL DEFAULT 0,
    must_reset      TINYINT(1)   NOT NULL DEFAULT 0,
    warnings        INT UNSIGNED NOT NULL DEFAULT 0,
    warnings_seen   INT UNSIGNED NOT NULL DEFAULT 0,
    token_version   INT UNSIGNED NOT NULL DEFAULT 0,
    created_at      DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    -- utf8mb4_0900_ai_ci is case-insensitive, so "Naveen" and "naveen" collide
    UNIQUE KEY uq_users_username (username),
    UNIQUE KEY uq_users_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- Documents (metadata) and their content (kept in a separate table so
-- list queries never touch the payload)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS documents (
    id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    owner_id        INT UNSIGNED NOT NULL,
    name            VARCHAR(120) NOT NULL,
    category        ENUM('HR','Contracts','Drawings','Audit','Other') NOT NULL DEFAULT 'Other',
    mime_type       VARCHAR(80)  NOT NULL,
    is_text         TINYINT(1)   NOT NULL DEFAULT 0,
    size_bytes      INT UNSIGNED NOT NULL,
    sha256          CHAR(64)     NOT NULL,
    passcode_hash   VARCHAR(255) NULL,
    is_deleted      TINYINT(1)   NOT NULL DEFAULT 0,
    created_at      DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at      DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    KEY ix_documents_owner (owner_id),
    CONSTRAINT fk_documents_owner FOREIGN KEY (owner_id) REFERENCES users(id)
) ENGINE=InnoDB AUTO_INCREMENT=1001 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS document_blobs (
    document_id     INT UNSIGNED PRIMARY KEY,
    content         LONGBLOB NOT NULL,
    CONSTRAINT fk_blobs_document FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS document_grants (
    document_id     INT UNSIGNED NOT NULL,
    user_id         INT UNSIGNED NOT NULL,
    level           ENUM('READ','EDIT') NOT NULL DEFAULT 'READ',
    can_rename      TINYINT(1) NOT NULL DEFAULT 0,
    granted_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (document_id, user_id),
    KEY ix_grants_user (user_id),
    CONSTRAINT fk_grants_document FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
    CONSTRAINT fk_grants_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- Sign-up requests waiting for the emailed code
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS pending_signups (
    id              CHAR(36)     PRIMARY KEY,
    username        VARCHAR(32)  NOT NULL,
    email           VARCHAR(254) NOT NULL,
    password_hash   VARCHAR(255) NOT NULL,
    expires_at      DATETIME(6)  NOT NULL,
    created_at      DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY ix_pending_expiry (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- One-time email codes (sign-up and forgot password): only an HMAC-SHA256 of each code is stored.
-- 5-minute expiry, single use, 5 attempts per challenge.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS otp_codes (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    challenge_id    CHAR(36)     NOT NULL,
    purpose         ENUM('SIGNUP','RESET') NOT NULL,
    user_id         INT UNSIGNED NULL,
    code_hash       CHAR(64)     NOT NULL,
    expires_at      DATETIME(6)  NOT NULL,
    is_used         TINYINT(1)   NOT NULL DEFAULT 0,
    attempts        INT UNSIGNED NOT NULL DEFAULT 0,
    created_at      DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY ix_otp_challenge (challenge_id),
    KEY ix_otp_expiry (expires_at),
    CONSTRAINT fk_otp_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- Failure counters for sign-in and document passcodes.
-- Keyed by a hash of (purpose, subject, client IP) so a stranger cannot
-- lock a real user out from somewhere else.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS lockouts (
    key_hash        CHAR(64)     PRIMARY KEY,
    failures        INT UNSIGNED NOT NULL DEFAULT 0,
    locked_until    DATETIME(6)  NULL,
    updated_at      DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- Safety & support
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS reports (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    reporter_id     INT UNSIGNED NOT NULL,
    target_id       INT UNSIGNED NOT NULL,
    document_id     INT UNSIGNED NULL,
    category        VARCHAR(40)  NOT NULL,
    details         VARCHAR(500) NOT NULL,
    created_at      DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_reports_reporter FOREIGN KEY (reporter_id) REFERENCES users(id),
    CONSTRAINT fk_reports_target FOREIGN KEY (target_id) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS messages (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    sender_id       INT UNSIGNED NOT NULL,
    recipient_id    INT UNSIGNED NOT NULL,
    document_id     INT UNSIGNED NOT NULL,
    body            VARCHAR(500) NOT NULL,
    created_at      DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY ix_messages_recipient (recipient_id),
    CONSTRAINT fk_messages_sender FOREIGN KEY (sender_id) REFERENCES users(id),
    CONSTRAINT fk_messages_recipient FOREIGN KEY (recipient_id) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- Tamper-resistant audit trail
--   * entry_hash = SHA-256(previous_hash | created_at | actor | action |
--                          document_ref | doc_owner_id | result | detail | ip)
--     computed by the database itself in a BEFORE INSERT trigger,
--     replacing the PostgreSQL pgcrypto digest() version.
--   * BEFORE UPDATE / BEFORE DELETE triggers refuse any change with
--     SIGNAL SQLSTATE '45000'.
--   * The application serialises inserts with GET_LOCK('tv_audit_chain')
--     so two writers can never fork the chain.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    created_at      DATETIME(6)  NOT NULL,
    actor           VARCHAR(32)  NOT NULL,
    action          VARCHAR(40)  NOT NULL,
    document_ref    VARCHAR(16)  NOT NULL DEFAULT '',
    doc_owner_id    INT UNSIGNED NULL,
    result          ENUM('allowed','denied') NOT NULL,
    detail          VARCHAR(255) NOT NULL DEFAULT '',
    ip              VARCHAR(45)  NOT NULL DEFAULT '',
    previous_hash   CHAR(64)     NOT NULL DEFAULT '',
    entry_hash      CHAR(64)     NOT NULL DEFAULT '',
    UNIQUE KEY uq_audit_entry_hash (entry_hash),
    KEY ix_audit_actor (actor),
    KEY ix_audit_owner (doc_owner_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TRIGGER IF EXISTS trg_audit_logs_chain;
DROP TRIGGER IF EXISTS trg_audit_logs_no_update;
DROP TRIGGER IF EXISTS trg_audit_logs_no_delete;

DELIMITER //

CREATE TRIGGER trg_audit_logs_chain
BEFORE INSERT ON audit_logs
FOR EACH ROW
BEGIN
    DECLARE prev CHAR(64);
    SELECT entry_hash INTO prev FROM audit_logs ORDER BY id DESC LIMIT 1;
    SET NEW.previous_hash = COALESCE(prev, REPEAT('0', 64));
    SET NEW.entry_hash = SHA2(CONCAT_WS('|',
        NEW.previous_hash,
        DATE_FORMAT(NEW.created_at, '%Y-%m-%d %H:%i:%s.%f'),
        NEW.actor,
        NEW.action,
        NEW.document_ref,
        COALESCE(CAST(NEW.doc_owner_id AS CHAR), ''),
        NEW.result,
        NEW.detail,
        NEW.ip), 256);
END//

CREATE TRIGGER trg_audit_logs_no_update
BEFORE UPDATE ON audit_logs
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'audit_logs is append-only: UPDATE is forbidden';
END//

CREATE TRIGGER trg_audit_logs_no_delete
BEFORE DELETE ON audit_logs
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'audit_logs is append-only: DELETE is forbidden';
END//

DELIMITER ;
