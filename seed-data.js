import pkg from 'pg';
const { Pool } = pkg;
import { drizzle } from 'drizzle-orm/node-postgres';
import * as schema from '@shared/schema';

const { blocks, variants, subjects, questions, answers } = schema;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

const db = drizzle(pool);

async function seed() {
  try {
    console.log('🌱 Starting seed...');

    // 1. Создаем блок "2025"
    const [block] = await db.insert(blocks).values({
      name: '2025',
      hasCalculator: true,
      hasPeriodicTable: true
    }).returning();
    console.log('✅ Block created:', block.name);

    // 2. Создаем 10 вариантов (все бесплатные)
    const createdVariants = [];
    for (let v = 1; v <= 10; v++) {
      const [variant] = await db.insert(variants).values({
        blockId: block.id,
        name: `Вариант ${v}`,
        isFree: true,
        duration: 215,
        questionsPerSubject: 20
      }).returning();
      createdVariants.push(variant);
      console.log(`✅ Variant created: Вариант ${v}`);
    }

    // 3. Создаем предметы для КАЖДОГО варианта (стандартный ЕНТ)
    const subjectsList = [
      { name: 'Математическая грамотность' },
      { name: 'Грамотность чтения' },
      { name: 'История Казахстана' },
      { name: 'Математика' },
      { name: 'Физика' }
    ];

    let totalQuestions = 0;
    let totalSubjects = 0;

    for (const variant of createdVariants) {
      console.log(`\n📝 Creating subjects and questions for ${variant.name}...`);
      
      const createdSubjects = [];
      for (const subj of subjectsList) {
        const [subject] = await db.insert(subjects).values({
          variantId: variant.id,
          name: subj.name
        }).returning();
        createdSubjects.push(subject);
        totalSubjects++;
      }

      // 4. Создаем вопросы для каждого предмета (по 20 вопросов)
      for (const subject of createdSubjects) {
        for (let i = 1; i <= 20; i++) {
          const [question] = await db.insert(questions).values({
            subjectId: subject.id,
            text: `${subject.name} - Вопрос ${i}`
          }).returning();

          // Создаем ответы
          const answerOptions = ['A', 'B', 'C', 'D', 'E'];
          for (let j = 0; j < 5; j++) {
            await db.insert(answers).values({
              questionId: question.id,
              text: `Ответ ${answerOptions[j]}`,
              isCorrect: j === 0
            });
          }
          totalQuestions++;
        }
        console.log(`  ✅ ${subject.name}: 20 questions created`);
      }
    }

    console.log('\n🎉 Seed completed successfully!');
    console.log(`Created:
    - 1 block (2025)
    - ${createdVariants.length} variants
    - ${totalSubjects} subjects (${subjectsList.length} per variant)
    - ${totalQuestions} questions (100 per variant)
    - ${totalQuestions * 5} answers
    `);

  } catch (error) {
    console.error('❌ Seed failed:', error);
    throw error;
  } finally {
    await pool.end();
  }
}

seed();