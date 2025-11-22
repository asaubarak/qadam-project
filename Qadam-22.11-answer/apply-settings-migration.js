import { db } from "./server/db.js";
import { sql } from "drizzle-orm";
import fs from "fs";

async function runMigration() {
  try {
    console.log("Reading migration file...");
    const migrationSQL = fs.readFileSync("./migrations/20251021_add_system_settings.sql", "utf8");
    
    console.log("Applying migration...");
    await db.execute(sql.raw(migrationSQL));
    
    console.log("✅ Migration applied successfully!");
    process.exit(0);
  } catch (error) {
    console.error("❌ Migration failed:", error);
    process.exit(1);
  }
}

runMigration();
