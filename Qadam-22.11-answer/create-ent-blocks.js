import 'dotenv/config';
import { db } from './server/db.ts';
import { blocks } from './shared/schema.ts';

async function createENTBlocks() {
  try {
    console.log('📚 Создаем стандартные блоки для ЕНТ...');
    
    const entBlocks = [
      {
        name: 'Физика+Математика',
        description: 'Физико-математическое направление',
        order: 1
      },
      {
        name: 'Химия+Биология',
        description: 'Естественно-научное направление',
        order: 2
      },
      {
        name: 'География+История',
        description: 'Общественно-гуманитарное направление',
        order: 3
      },
      {
        name: 'Английский язык',
        description: 'Иностранный язык',
        order: 4
      },
      {
        name: 'Творческие специальности',
        description: 'Творческое направление',
        order: 5
      }
    ];

    // Сначала проверим, какие блоки уже есть
    const existingBlocks = await db.select().from(blocks);
    console.log(`Существующих блоков: ${existingBlocks.length}`);

    for (const block of entBlocks) {
      // Проверяем, есть ли уже такой блок
      const exists = existingBlocks.find(b => b.name === block.name);
      if (!exists) {
        await db.insert(blocks).values(block);
        console.log(`✅ Блок "${block.name}" создан`);
      } else {
        console.log(`⚠️ Блок "${block.name}" уже существует`);
      }
    }
    
    console.log('🎉 Все блоки ЕНТ готовы!');
    process.exit(0);
  } catch (error) {
    console.error('❌ Ошибка при создании блоков:', error);
    process.exit(1);
  }
}

createENTBlocks();