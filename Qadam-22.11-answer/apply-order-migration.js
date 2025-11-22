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
    
    const migrationPath = path.join(__dirname, 'migrations', '20251021_add_order_fields.sql');
    const sql = fs.readFileSync(migrationPath, 'utf8');
    
    console.log('🚀 Applying migration: add order fields...');
    await client.query(sql);
    
    console.log('✅ Migration applied successfully!');
    console.log('📊 Order fields added to:');
    console.log('   - blocks');
    console.log('   - variants');
    console.log('   - subjects');
    console.log('   - questions');
    console.log('   - answers');
  } catch (error) {
    console.error('❌ Migration failed:', error);
    process.exit(1);
  } finally {
    await client.end();
  }
}

applyMigration();
