import { sql } from "drizzle-orm";
import {
  bigserial, boolean, index, integer, pgEnum, pgTable, primaryKey, text, timestamp, uniqueIndex, varchar,
} from "drizzle-orm/pg-core";

export const roleEnum = pgEnum("role", ["ADMIN", "OWNER", "VIEWER"]);
export const categoryEnum = pgEnum("category", ["HR", "Contracts", "Drawings", "Audit", "Other"]);
export const levelEnum = pgEnum("grant_level", ["READ", "EDIT"]);
export const purposeEnum = pgEnum("otp_purpose", ["SIGNUP", "RESET"]);
export const resultEnum = pgEnum("audit_result", ["allowed", "denied"]);

const ts = (name: string) => timestamp(name, { precision: 3, mode: "date" });

export const users = pgTable("users", {
  id: integer().primaryKey().generatedAlwaysAsIdentity(),
  username: varchar({ length: 32 }).notNull(),
  displayName: varchar("display_name", { length: 80 }).notNull(),
  role: roleEnum().notNull().default("VIEWER"),
  email: varchar({ length: 254 }),
  passwordHash: varchar("password_hash", { length: 255 }).notNull(),
  isVerified: boolean("is_verified").notNull().default(false),
  isBlocked: boolean("is_blocked").notNull().default(false),
  mustReset: boolean("must_reset").notNull().default(false),
  warnings: integer().notNull().default(0),
  warningsSeen: integer("warnings_seen").notNull().default(0),
  tokenVersion: integer("token_version").notNull().default(0),
  createdAt: ts("created_at").notNull().defaultNow(),
}, (t) => [
  // case-insensitive: "Naveen" and "naveen" collide
  uniqueIndex("uq_users_username").on(sql`lower(${t.username})`),
  uniqueIndex("uq_users_email").on(t.email),
]);

export const documents = pgTable("documents", {
  id: integer().primaryKey().generatedAlwaysAsIdentity({ startWith: 1001 }),
  ownerId: integer("owner_id").notNull().references(() => users.id),
  name: varchar({ length: 120 }).notNull(),
  category: categoryEnum().notNull().default("Other"),
  mimeType: varchar("mime_type", { length: 80 }).notNull(),
  isText: boolean("is_text").notNull().default(false),
  sizeBytes: integer("size_bytes").notNull(),
  sha256: varchar({ length: 64 }).notNull(),
  passcodeHash: varchar("passcode_hash", { length: 255 }),
  isDeleted: boolean("is_deleted").notNull().default(false),
  createdAt: ts("created_at").notNull().defaultNow(),
  updatedAt: ts("updated_at").notNull().defaultNow(),
}, (t) => [index("ix_documents_owner").on(t.ownerId)]);

export const documentGrants = pgTable("document_grants", {
  documentId: integer("document_id").notNull().references(() => documents.id, { onDelete: "cascade" }),
  userId: integer("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  level: levelEnum().notNull().default("READ"),
  canRename: boolean("can_rename").notNull().default(false),
  grantedAt: ts("granted_at").notNull().defaultNow(),
}, (t) => [primaryKey({ columns: [t.documentId, t.userId] }), index("ix_grants_user").on(t.userId)]);

export const pendingSignups = pgTable("pending_signups", {
  id: varchar({ length: 36 }).primaryKey(),
  username: varchar({ length: 32 }).notNull(),
  email: varchar({ length: 254 }).notNull(),
  passwordHash: varchar("password_hash", { length: 255 }).notNull(),
  expiresAt: ts("expires_at").notNull(),
  createdAt: ts("created_at").notNull().defaultNow(),
});

export const otpCodes = pgTable("otp_codes", {
  id: bigserial({ mode: "number" }).primaryKey(),
  challengeId: varchar("challenge_id", { length: 36 }).notNull(),
  purpose: purposeEnum().notNull(),
  userId: integer("user_id").references(() => users.id, { onDelete: "cascade" }),
  codeHash: varchar("code_hash", { length: 64 }).notNull(),
  expiresAt: ts("expires_at").notNull(),
  isUsed: boolean("is_used").notNull().default(false),
  attempts: integer().notNull().default(0),
  createdAt: ts("created_at").notNull().defaultNow(),
}, (t) => [index("ix_otp_challenge").on(t.challengeId)]);

export const lockouts = pgTable("lockouts", {
  keyHash: varchar("key_hash", { length: 64 }).primaryKey(),
  failures: integer().notNull().default(0),
  lockedUntil: ts("locked_until"),
  updatedAt: ts("updated_at").notNull().defaultNow(),
});

// Fixed-window request counters shared by every function instance.
export const rateLimits = pgTable("rate_limits", {
  key: varchar({ length: 128 }).primaryKey(),
  windowStart: ts("window_start").notNull(),
  hits: integer().notNull().default(0),
});

export const reports = pgTable("reports", {
  id: bigserial({ mode: "number" }).primaryKey(),
  reporterId: integer("reporter_id").notNull().references(() => users.id),
  targetId: integer("target_id").notNull().references(() => users.id),
  documentId: integer("document_id"),
  category: varchar({ length: 40 }).notNull(),
  details: varchar({ length: 500 }).notNull(),
  createdAt: ts("created_at").notNull().defaultNow(),
});

export const messages = pgTable("messages", {
  id: bigserial({ mode: "number" }).primaryKey(),
  senderId: integer("sender_id").notNull().references(() => users.id),
  recipientId: integer("recipient_id").notNull().references(() => users.id),
  documentId: integer("document_id").notNull(),
  body: varchar({ length: 500 }).notNull(),
  createdAt: ts("created_at").notNull().defaultNow(),
});

export const auditLogs = pgTable("audit_logs", {
  id: bigserial({ mode: "number" }).primaryKey(),
  createdAt: ts("created_at").notNull(),
  actor: varchar({ length: 32 }).notNull(),
  action: varchar({ length: 40 }).notNull(),
  documentRef: varchar("document_ref", { length: 16 }).notNull().default(""),
  docOwnerId: integer("doc_owner_id"),
  result: resultEnum().notNull(),
  detail: varchar({ length: 255 }).notNull().default(""),
  ip: varchar({ length: 45 }).notNull().default(""),
  previousHash: varchar("previous_hash", { length: 64 }).notNull().default(""),
  entryHash: varchar("entry_hash", { length: 64 }).notNull().default(""),
});

// Server-generated secrets (JWT signing key, peppers). Created on first use, never sent to clients.
export const appSecrets = pgTable("app_secrets", {
  name: varchar({ length: 40 }).primaryKey(),
  value: text().notNull(),
});
