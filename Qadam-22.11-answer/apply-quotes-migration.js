import 'dotenv/config';
import pg from 'pg';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const client = new pg.Client({
  connectionString: process.env.DATABASE_URL,
});

async function applyMigration() {
  try {
    await client.connect();
    console.log('📦 Connected to database');
    
    const migrationPath = path.join(__dirname, 'migrations', '20251022_add_quotes.sql');
    const sql = fs.readFileSync(migrationPath, 'utf8');
    
    console.log('🚀 Applying migration: add quotes table...');
    await client.query(sql);
    
    console.log('✅ Migration applied successfully!');
    console.log('📊 Quotes table created');
  } catch (error) {
    console.error('❌ Migration failed:', error);
    process.exit(1);
  } finally {
    await client.end();
  }
}

applyMigration();
