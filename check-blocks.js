import 'dotenv/config';
import { db } from './server/db.ts';
import { blocks } from './shared/schema.ts';

async function checkBlocks() {
  try {
    const allBlocks = await db.select().from(blocks);
    console.log('📋 Блоки в базе данных:');
    allBlocks.forEach((block, i) => {
      console.log(`${i+1}. "${block.name}" (ID: ${block.id})`);
    });
    console.log(`\nВсего блоков: ${allBlocks.length}`);
    process.exit(0);
  } catch (error) {
    console.error('❌ Ошибка:', error);
    process.exit(1);
  }
}

checkBlocks();