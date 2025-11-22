import 'dotenv/config';
import pg from 'pg';
import { randomUUID } from 'crypto';

const client = new pg.Client({
  connectionString: process.env.DATABASE_URL,
});

// Реальные пары профильных предметов ЕНТ
const blockPairs = [
  { name: "Физика-Математика", subjects: ["Физика", "Математика"] },
  { name: "Химия-Биология", subjects: ["Химия", "Биология"] },
  { name: "География-Математика", subjects: ["География", "Математика"] },
  { name: "Всемирная история-Человек. Общество. Право", subjects: ["Всемирная история", "Человек. Общество. Право"] },
  { name: "Физика-География", subjects: ["Физика", "География"] },
  { name: "Математика-География", subjects: ["Математика", "География"] },
  { name: "Химия-Физика", subjects: ["Химия", "Физика"] },
  { name: "Биология-География", subjects: ["Биология", "География"] },
  { name: "Иностранный язык-Всемирная история", subjects: ["Иностранный язык", "Всемирная история"] },
  { name: "Творческий экзамен-География", subjects: ["Творческий экзамен", "География"] }
];

// Базовые предметы (одинаковые для всех)
const baseSubjects = [
  { name: "История Казахстана", questionCount: 20, answerCount: 5 },
  { name: "Математическая грамотность", questionCount: 10, answerCount: 5 },
  { name: "Грамотность чтения", questionCount: 10, answerCount: 5 }
];

// Генерация вопроса с ответами
function generateQuestion(subjectName, questionNum, answerCount) {
  const text = `${subjectName} - Вопрос ${questionNum}`;
  const answers = [];
  
  if (answerCount === 5) {
    // 1 правильный ответ
    for (let i = 1; i <= 5; i++) {
      answers.push({
        text: `Ответ ${i}`,
        isCorrect: i === 1 // Первый ответ правильный
      });
    }
  } else if (answerCount === 8) {
    // 3 правильных ответа
    for (let i = 1; i <= 8; i++) {
      answers.push({
        text: `Ответ ${i}`,
        isCorrect: i <= 3 // Первые 3 ответа правильные
      });
    }
  }
  
  return { text, answers };
}

async function createStructure() {
  try {
    await client.connect();
    console.log('📦 Connected to database');

    // Создаем 10 блоков
    for (let blockIndex = 0; blockIndex < blockPairs.length; blockIndex++) {
      const blockPair = blockPairs[blockIndex];
      console.log(`\n🔹 Creating block ${blockIndex + 1}: ${blockPair.name}`);
      
      // Проверяем, существует ли блок
      const existingBlock = await client.query(
        'SELECT id FROM blocks WHERE name = $1',
        [blockPair.name]
      );
      
      let blockId;
      if (existingBlock.rows.length > 0) {
        blockId = existingBlock.rows[0].id;
        console.log(`   ⚠️  Block already exists, skipping: ${blockId}`);
        continue; // Пропускаем этот блок
      }
      
      // Создаем блок
      const blockResult = await client.query(
        'INSERT INTO blocks (id, name, "order") VALUES ($1, $2, $3) RETURNING id',
        [randomUUID(), blockPair.name, blockIndex]
      );
      blockId = blockResult.rows[0].id;
      console.log(`   ✓ Block created: ${blockId}`);

      // Создаем 10 вариантов в блоке
      for (let variantIndex = 1; variantIndex <= 10; variantIndex++) {
        console.log(`   📄 Creating variant ${variantIndex}...`);
        
        const variantResult = await client.query(
          'INSERT INTO variants (id, name, "block_id", "order", "is_free") VALUES ($1, $2, $3, $4, $5) RETURNING id',
          [randomUUID(), `Вариант ${variantIndex}`, blockId, variantIndex - 1, false]
        );
        const variantId = variantResult.rows[0].id;

        let subjectOrder = 0;

        // 1. История Казахстана (20 вопросов)
        const historySubjectResult = await client.query(
          'INSERT INTO subjects (id, name, "variant_id", "order") VALUES ($1, $2, $3, $4) RETURNING id',
          [randomUUID(), "История Казахстана", variantId, subjectOrder++]
        );
        const historySubjectId = historySubjectResult.rows[0].id;
        
        for (let q = 1; q <= 20; q++) {
          const question = generateQuestion("История Казахстана", q, 5);
          const questionResult = await client.query(
            'INSERT INTO questions (id, text, "subject_id", "order") VALUES ($1, $2, $3, $4) RETURNING id',
            [randomUUID(), question.text, historySubjectId, q - 1]
          );
          const questionId = questionResult.rows[0].id;
          
          for (let a = 0; a < question.answers.length; a++) {
            await client.query(
              'INSERT INTO answers (id, text, "is_correct", "question_id", "order") VALUES ($1, $2, $3, $4, $5)',
              [randomUUID(), question.answers[a].text, question.answers[a].isCorrect, questionId, a]
            );
          }
        }

        // 2. Математическая грамотность (10 вопросов)
        const mathSubjectResult = await client.query(
          'INSERT INTO subjects (id, name, "variant_id", "order") VALUES ($1, $2, $3, $4) RETURNING id',
          [randomUUID(), "Математическая грамотность", variantId, subjectOrder++]
        );
        const mathSubjectId = mathSubjectResult.rows[0].id;
        
        for (let q = 1; q <= 10; q++) {
          const question = generateQuestion("Математическая грамотность", q, 5);
          const questionResult = await client.query(
            'INSERT INTO questions (id, text, "subject_id", "order") VALUES ($1, $2, $3, $4) RETURNING id',
            [randomUUID(), question.text, mathSubjectId, q - 1]
          );
          const questionId = questionResult.rows[0].id;
          
          for (let a = 0; a < question.answers.length; a++) {
            await client.query(
              'INSERT INTO answers (id, text, "is_correct", "question_id", "order") VALUES ($1, $2, $3, $4, $5)',
              [randomUUID(), question.answers[a].text, question.answers[a].isCorrect, questionId, a]
            );
          }
        }

        // 3. Грамотность чтения (10 вопросов)
        const readingSubjectResult = await client.query(
          'INSERT INTO subjects (id, name, "variant_id", "order") VALUES ($1, $2, $3, $4) RETURNING id',
          [randomUUID(), "Грамотность чтения", variantId, subjectOrder++]
        );
        const readingSubjectId = readingSubjectResult.rows[0].id;
        
        for (let q = 1; q <= 10; q++) {
          const question = generateQuestion("Грамотность чтения", q, 5);
          const questionResult = await client.query(
            'INSERT INTO questions (id, text, "subject_id", "order") VALUES ($1, $2, $3, $4) RETURNING id',
            [randomUUID(), question.text, readingSubjectId, q - 1]
          );
          const questionId = questionResult.rows[0].id;
          
          for (let a = 0; a < question.answers.length; a++) {
            await client.query(
              'INSERT INTO answers (id, text, "is_correct", "question_id", "order") VALUES ($1, $2, $3, $4, $5)',
              [randomUUID(), question.answers[a].text, question.answers[a].isCorrect, questionId, a]
            );
          }
        }

        // 4-5. Профильные предметы (по 40 вопросов каждый: 30 простых + 10 сложных)
        for (let profIndex = 0; profIndex < 2; profIndex++) {
          const profSubjectName = blockPair.subjects[profIndex];
          const profSubjectResult = await client.query(
            'INSERT INTO subjects (id, name, "variant_id", "order") VALUES ($1, $2, $3, $4) RETURNING id',
            [randomUUID(), profSubjectName, variantId, subjectOrder++]
          );
          const profSubjectId = profSubjectResult.rows[0].id;
          
          // 30 простых вопросов (5 ответов)
          for (let q = 1; q <= 30; q++) {
            const question = generateQuestion(profSubjectName, q, 5);
            const questionResult = await client.query(
              'INSERT INTO questions (id, text, "subject_id", "order") VALUES ($1, $2, $3, $4) RETURNING id',
              [randomUUID(), question.text, profSubjectId, q - 1]
            );
            const questionId = questionResult.rows[0].id;
            
            for (let a = 0; a < question.answers.length; a++) {
              await client.query(
                'INSERT INTO answers (id, text, "is_correct", "question_id", "order") VALUES ($1, $2, $3, $4, $5)',
                [randomUUID(), question.answers[a].text, question.answers[a].isCorrect, questionId, a]
              );
            }
          }
          
          // 10 сложных вопросов (8 ответов, 3 правильных)
          for (let q = 31; q <= 40; q++) {
            const question = generateQuestion(profSubjectName, q, 8);
            const questionResult = await client.query(
              'INSERT INTO questions (id, text, "subject_id", "order") VALUES ($1, $2, $3, $4) RETURNING id',
              [randomUUID(), question.text, profSubjectId, q - 1]
            );
            const questionId = questionResult.rows[0].id;
            
            for (let a = 0; a < question.answers.length; a++) {
              await client.query(
                'INSERT INTO answers (id, text, "is_correct", "question_id", "order") VALUES ($1, $2, $3, $4, $5)',
                [randomUUID(), question.answers[a].text, question.answers[a].isCorrect, questionId, a]
              );
            }
          }
        }

        console.log(`   ✓ Variant ${variantIndex} created with 5 subjects and 120 questions (140 points)`);
      }
    }

    console.log('\n✅ All 10 blocks with 10 variants each created successfully!');
    console.log('📊 Total: 10 blocks × 10 variants × 120 questions = 12,000 questions');
    
  } catch (error) {
    console.error('❌ Error:', error);
    process.exit(1);
  } finally {
    await client.end();
  }
}

createStructure();
