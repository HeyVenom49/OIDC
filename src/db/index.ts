import "dotenv/config";
import { drizzle, type NodePgDatabase } from "drizzle-orm/node-postgres";
import * as schema from "./schema";

const connectionString = process.env.DATABASE_URL;

if (!connectionString) {
  throw new Error("DATABASE_URL environment variable is required");
}

export const db: NodePgDatabase<typeof schema> = drizzle(connectionString, {
  schema,
});
