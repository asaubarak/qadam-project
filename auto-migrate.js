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

async function runMigrations() {
  try {
    await client.connect();
    console.log('✅ Connected to database');
    
    // Миграция 1: добавление order полей
    console.log('📦 Running migration: add order fields...');
    const migration1 = fs.readFileSync(path.join(__dirname, 'migrations', '20251021_add_order_fields.sql'), 'utf8');
    await client.query(migration1);
    console.log('✅ Migration 1 complete');
    
    // Миграция 2: системные настройки
    console.log('📦 Running migration: add system settings...');
    const migration2 = fs.readFileSync(path.join(__dirname, 'migrations', '20251021_add_system_settings.sql'), 'utf8');
    await client.query(migration2);
    console.log('✅ Migration 2 complete');
    
    // Миграция 3: цитаты
    console.log('📦 Running migration: add quotes...');
    const migration3 = fs.readFileSync(path.join(__dirname, 'migrations', '20251022_add_quotes.sql'), 'utf8');
    await client.query(migration3);
    console.log('✅ Migration 3 complete');
    // Добавь после всех миграций
    console.log('👑 Creating admin user...');
    try {
      await import('./create-admin-prod.js');
      console.log('✅ Admin user created successfully');
    } catch (error) {
      console.log('⚠️ Admin creation:', error.message);
    }
    console.log('🎉 All migrations completed successfully!');
    
  } catch (error) {
    // Игнорируем ошибки "already exists" - значит миграции уже применены
    if (error.message.includes('already exists') || error.message.includes('duplicate')) {
      console.log('ℹ️ Migrations already applied, skipping...');
    } else {
      console.error('❌ Migration failed:', error.message);
      throw error;
    }
  } finally {
    await client.end();
  }
}

runMigrations().catch(console.error);
