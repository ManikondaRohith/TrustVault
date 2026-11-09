-- The audit trail is append-only: any UPDATE or DELETE on audit_logs is refused by the database.
CREATE OR REPLACE FUNCTION tv_audit_logs_immutable() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_logs is append-only (% refused)', TG_OP;
END;
$$ LANGUAGE plpgsql;
--> statement-breakpoint
CREATE TRIGGER trg_audit_logs_no_update BEFORE UPDATE ON audit_logs FOR EACH ROW EXECUTE FUNCTION tv_audit_logs_immutable();
--> statement-breakpoint
CREATE TRIGGER trg_audit_logs_no_delete BEFORE DELETE ON audit_logs FOR EACH ROW EXECUTE FUNCTION tv_audit_logs_immutable();
--> statement-breakpoint
CREATE TRIGGER trg_audit_logs_no_truncate BEFORE TRUNCATE ON audit_logs FOR EACH STATEMENT EXECUTE FUNCTION tv_audit_logs_immutable();
