import { config } from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Загружаем .env из корневой папки проекта
config({ path: resolve(__dirname, '../.env') });

import pkg from 'pg';
const { Pool } = pkg;
import { drizzle } from 'drizzle-orm/node-postgres';
import * as schema from '@shared/schema';

console.log('DATABASE_URL after load:', process.env.DATABASE_URL);

if (!process.env.DATABASE_URL) {
    throw new Error("DATABASE_URL must be set. Did you forget to provision a database?");
}

const pool = new Pool({
    connectionString: process.env.DATABASE_URL
});

const db = drizzle(pool, { schema });
export { db, pool };