CREATE TABLE "clients" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"display_name" text NOT NULL,
	"application_url" text NOT NULL,
	"redirect_uri" text NOT NULL,
	"client_id" text NOT NULL,
	"client_secret" text NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX "clients_client_id_idx" ON "clients" USING btree ("client_id");