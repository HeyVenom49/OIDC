import {
  boolean,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid,
  varchar,
} from "drizzle-orm/pg-core";

export const users = pgTable("users", {
  id: uuid("id").primaryKey().defaultRandom(),
  firstName: varchar("first_name", { length: 25 }),
  lastName: varchar("last_name", { length: 25 }),
  profileImageURL: text("profile_image_url"),
  email: varchar("email", { length: 322 }).notNull(),
  emailVerified: boolean("email_verified").default(false).notNull(),
  password: varchar("password", { length: 66 }),
  salt: text("salt"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").$onUpdate(() => new Date()),
});

export const clients = pgTable(
  "clients",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    displayName: text("display_name").notNull(),
    applicationUrl: text("application_url").notNull(),
    redirectUri: text("redirect_uri").notNull(),
    clientId: text("client_id").notNull(),
    clientSecret: text("client_secret").notNull(),
    createdAt: timestamp("created_at").defaultNow().notNull(),
  },
  (table) => [uniqueIndex("clients_client_id_idx").on(table.clientId)],
);
