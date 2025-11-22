import 'dotenv/config';
import pg from 'pg';
import { scrypt, randomBytes } from 'crypto';
import { promisify } from 'util';

const scryptAsync = promisify(scrypt);

async function hashPassword(password) {
  const salt = randomBytes(16).toString("hex");
  const buf = await scryptAsync(password, salt, 64);
  return `${buf.toString("hex")}.${salt}`;
}

const client = new pg.Client({
  connectionString: process.env.DATABASE_URL,
});

async function createAdmin() {
  try {
    await client.connect();
    console.log('📦 Connected to database');
    
    // Проверяем, есть ли уже админ
    const existingAdmin = await client.query(
      'SELECT id FROM users WHERE username = $1',
      ['admin']
    );
    
    if (existingAdmin.rows.length > 0) {
      console.log('⚠️  Admin already exists!');
      
      // Обновляем пароль существующего админа
      const newPassword = 'admin123';
      const hashedPassword = await hashPassword(newPassword);
      
      await client.query(
        'UPDATE users SET password = $1 WHERE username = $2',
        [hashedPassword, 'admin']
      );
      
      console.log('✅ Admin password updated!');
      console.log(`🔑 Username: admin`);
      console.log(`🔑 Password: ${newPassword}`);
    } else {
      // Создаем нового админа
      const username = 'admin';
      const email = 'admin@qadam.com';
      const password = 'admin123';
      
      const hashedPassword = await hashPassword(password);
      
      await client.query(
        'INSERT INTO users (username, email, password) VALUES ($1, $2, $3)',
        [username, email, hashedPassword]
      );
      
      console.log('✅ Admin created successfully!');
      console.log(`🔑 Username: ${username}`);
      console.log(`🔑 Email: ${email}`);
      console.log(`🔑 Password: ${password}`);
    }
    
    console.log('🌐 Login at your Render URL /auth');
    
  } catch (error) {
    console.error('❌ Error creating admin:', error);
    process.exit(1);
  } finally {
    await client.end();
  }
}

createAdmin();
