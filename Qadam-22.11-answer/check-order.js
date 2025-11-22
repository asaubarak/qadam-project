import 'dotenv/config';
import pg from 'pg';

const client = new pg.Client({
  connectionString: process.env.DATABASE_URL,
});

async function checkOrder() {
  try {
    await client.connect();
    console.log('📊 Проверка порядка элементов в базе данных\n');
    
    console.log('=== ВАРИАНТЫ (отсортированные по order) ===');
    const variants = await client.query('SELECT id, name, "order", block_id FROM variants ORDER BY "order"');
    variants.rows.forEach((r, idx) => console.log(`  ${idx + 1}. ${r.name} (order: ${r.order})`));
    
    console.log('\n=== ПРЕДМЕТЫ (отсортированные по order) ===');
    const subjects = await client.query('SELECT id, name, "order", variant_id FROM subjects ORDER BY variant_id, "order" LIMIT 15');
    subjects.rows.forEach((r, idx) => console.log(`  ${idx + 1}. ${r.name} (order: ${r.order})`));
    
    console.log('\n=== ВОПРОСЫ (первые 10, отсортированные по order) ===');
    const questions = await client.query('SELECT id, text, "order", subject_id FROM questions ORDER BY subject_id, "order" LIMIT 10');
    questions.rows.forEach((r, idx) => {
      const shortText = r.text.substring(0, 50);
      console.log(`  ${idx + 1}. ${shortText}... (order: ${r.order})`);
    });
    
  } catch (error) {
    console.error('❌ Error:', error);
  } finally {
    await client.end();
  }
}

checkOrder();
