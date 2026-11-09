CREATE TYPE "category" AS ENUM('HR', 'Contracts', 'Drawings', 'Audit', 'Other');--> statement-breakpoint
CREATE TYPE "grant_level" AS ENUM('READ', 'EDIT');--> statement-breakpoint
CREATE TYPE "otp_purpose" AS ENUM('SIGNUP', 'RESET');--> statement-breakpoint
CREATE TYPE "audit_result" AS ENUM('allowed', 'denied');--> statement-breakpoint
CREATE TYPE "role" AS ENUM('ADMIN', 'OWNER', 'VIEWER');--> statement-breakpoint
CREATE TABLE "app_secrets" (
	"name" varchar(40) PRIMARY KEY,
	"value" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "audit_logs" (
	"id" bigserial PRIMARY KEY,
	"created_at" timestamp(3) NOT NULL,
	"actor" varchar(32) NOT NULL,
	"action" varchar(40) NOT NULL,
	"document_ref" varchar(16) DEFAULT '' NOT NULL,
	"doc_owner_id" integer,
	"result" "audit_result" NOT NULL,
	"detail" varchar(255) DEFAULT '' NOT NULL,
	"ip" varchar(45) DEFAULT '' NOT NULL,
	"previous_hash" varchar(64) DEFAULT '' NOT NULL,
	"entry_hash" varchar(64) DEFAULT '' NOT NULL
);
--> statement-breakpoint
CREATE TABLE "document_grants" (
	"document_id" integer,
	"user_id" integer,
	"level" "grant_level" DEFAULT 'READ'::"grant_level" NOT NULL,
	"can_rename" boolean DEFAULT false NOT NULL,
	"granted_at" timestamp(3) DEFAULT now() NOT NULL,
	CONSTRAINT "document_grants_pkey" PRIMARY KEY("document_id","user_id")
);
--> statement-breakpoint
CREATE TABLE "documents" (
	"id" integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "documents_id_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 2147483647 START WITH 1001 CACHE 1),
	"owner_id" integer NOT NULL,
	"name" varchar(120) NOT NULL,
	"category" "category" DEFAULT 'Other'::"category" NOT NULL,
	"mime_type" varchar(80) NOT NULL,
	"is_text" boolean DEFAULT false NOT NULL,
	"size_bytes" integer NOT NULL,
	"sha256" varchar(64) NOT NULL,
	"passcode_hash" varchar(255),
	"is_deleted" boolean DEFAULT false NOT NULL,
	"created_at" timestamp(3) DEFAULT now() NOT NULL,
	"updated_at" timestamp(3) DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "lockouts" (
	"key_hash" varchar(64) PRIMARY KEY,
	"failures" integer DEFAULT 0 NOT NULL,
	"locked_until" timestamp(3),
	"updated_at" timestamp(3) DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "messages" (
	"id" bigserial PRIMARY KEY,
	"sender_id" integer NOT NULL,
	"recipient_id" integer NOT NULL,
	"document_id" integer NOT NULL,
	"body" varchar(500) NOT NULL,
	"created_at" timestamp(3) DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "otp_codes" (
	"id" bigserial PRIMARY KEY,
	"challenge_id" varchar(36) NOT NULL,
	"purpose" "otp_purpose" NOT NULL,
	"user_id" integer,
	"code_hash" varchar(64) NOT NULL,
	"expires_at" timestamp(3) NOT NULL,
	"is_used" boolean DEFAULT false NOT NULL,
	"attempts" integer DEFAULT 0 NOT NULL,
	"created_at" timestamp(3) DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "pending_signups" (
	"id" varchar(36) PRIMARY KEY,
	"username" varchar(32) NOT NULL,
	"email" varchar(254) NOT NULL,
	"password_hash" varchar(255) NOT NULL,
	"expires_at" timestamp(3) NOT NULL,
	"created_at" timestamp(3) DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "rate_limits" (
	"key" varchar(128) PRIMARY KEY,
	"window_start" timestamp(3) NOT NULL,
	"hits" integer DEFAULT 0 NOT NULL
);
--> statement-breakpoint
CREATE TABLE "reports" (
	"id" bigserial PRIMARY KEY,
	"reporter_id" integer NOT NULL,
	"target_id" integer NOT NULL,
	"document_id" integer,
	"category" varchar(40) NOT NULL,
	"details" varchar(500) NOT NULL,
	"created_at" timestamp(3) DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "users_id_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 2147483647 START WITH 1 CACHE 1),
	"username" varchar(32) NOT NULL,
	"display_name" varchar(80) NOT NULL,
	"role" "role" DEFAULT 'VIEWER'::"role" NOT NULL,
	"email" varchar(254),
	"password_hash" varchar(255) NOT NULL,
	"is_verified" boolean DEFAULT false NOT NULL,
	"is_blocked" boolean DEFAULT false NOT NULL,
	"must_reset" boolean DEFAULT false NOT NULL,
	"warnings" integer DEFAULT 0 NOT NULL,
	"warnings_seen" integer DEFAULT 0 NOT NULL,
	"token_version" integer DEFAULT 0 NOT NULL,
	"created_at" timestamp(3) DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE INDEX "ix_grants_user" ON "document_grants" ("user_id");--> statement-breakpoint
CREATE INDEX "ix_documents_owner" ON "documents" ("owner_id");--> statement-breakpoint
CREATE INDEX "ix_otp_challenge" ON "otp_codes" ("challenge_id");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_users_username" ON "users" (lower("username"));--> statement-breakpoint
CREATE UNIQUE INDEX "uq_users_email" ON "users" ("email");--> statement-breakpoint
ALTER TABLE "document_grants" ADD CONSTRAINT "document_grants_document_id_documents_id_fkey" FOREIGN KEY ("document_id") REFERENCES "documents"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "document_grants" ADD CONSTRAINT "document_grants_user_id_users_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "documents" ADD CONSTRAINT "documents_owner_id_users_id_fkey" FOREIGN KEY ("owner_id") REFERENCES "users"("id");--> statement-breakpoint
ALTER TABLE "messages" ADD CONSTRAINT "messages_sender_id_users_id_fkey" FOREIGN KEY ("sender_id") REFERENCES "users"("id");--> statement-breakpoint
ALTER TABLE "messages" ADD CONSTRAINT "messages_recipient_id_users_id_fkey" FOREIGN KEY ("recipient_id") REFERENCES "users"("id");--> statement-breakpoint
ALTER TABLE "otp_codes" ADD CONSTRAINT "otp_codes_user_id_users_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "reports" ADD CONSTRAINT "reports_reporter_id_users_id_fkey" FOREIGN KEY ("reporter_id") REFERENCES "users"("id");--> statement-breakpoint
ALTER TABLE "reports" ADD CONSTRAINT "reports_target_id_users_id_fkey" FOREIGN KEY ("target_id") REFERENCES "users"("id");