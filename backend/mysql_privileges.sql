-- =====================================================================
-- Least-privilege grants for the application account (runs after the
-- schema, as root, from /docker-entrypoint-initdb.d).
--
-- The MySQL image gives MYSQL_USER "ALL" on the database. That would let a
-- compromised app DROP the audit triggers or TRUNCATE audit_logs (TRUNCATE
-- skips triggers). This script replaces it with:
--   * SELECT/INSERT/UPDATE/DELETE on business tables
--   * SELECT/INSERT only on audit_logs (no UPDATE, DELETE, DROP, TRUNCATE)
--   * no ALTER, DROP, CREATE, TRIGGER or GRANT anywhere
-- The triggers stay as a second line of defence for privileged accounts.
-- =====================================================================
REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'trustvault'@'%';

GRANT SELECT, INSERT, UPDATE, DELETE ON trustvault.users            TO 'trustvault'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON trustvault.documents        TO 'trustvault'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON trustvault.document_blobs   TO 'trustvault'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON trustvault.document_grants  TO 'trustvault'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON trustvault.pending_signups  TO 'trustvault'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON trustvault.otp_codes        TO 'trustvault'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON trustvault.lockouts         TO 'trustvault'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON trustvault.reports          TO 'trustvault'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON trustvault.messages         TO 'trustvault'@'%';
GRANT SELECT, INSERT                 ON trustvault.audit_logs       TO 'trustvault'@'%';

FLUSH PRIVILEGES;
