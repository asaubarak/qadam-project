import 'dotenv/config';
import pg from 'pg';

const client = new pg.Client({
  connectionString: process.env.DATABASE_URL,
});

async function checkDatabase() {
  try {
    await client.connect();
    
    console.log('=== BLOCKS (Блоки) ===');
    const blocks = await client.query('SELECT id, name FROM blocks ORDER BY "order" LIMIT 5');
    blocks.rows.forEach(r => console.log(`  - ${r.name}`));
    
    console.log('\n=== VARIANTS (Варианты) ===');
    const variants = await client.query('SELECT id, name, block_id FROM variants ORDER BY "order" LIMIT 10');
    variants.rows.forEach(r => console.log(`  - ${r.name}`));
    
    console.log('\n=== SUBJECTS (Предметы) ===');
    const subjects = await client.query('SELECT id, name, variant_id FROM subjects ORDER BY "order" LIMIT 10');
    subjects.rows.forEach(r => console.log(`  - ${r.name}`));
    
    console.log('\n=== QUESTIONS (Вопросы - первые 3) ===');
    const questions = await client.query('SELECT id, text FROM questions ORDER BY "order" LIMIT 3');
    questions.rows.forEach(r => console.log(`  - ${r.text.substring(0, 80)}${r.text.length > 80 ? '...' : ''}`));
    
  } catch (error) {
    console.error('❌ Error:', error);
  } finally {
    await client.end();
  }
}

checkDatabase();
