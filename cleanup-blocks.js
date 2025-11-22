import 'dotenv/config';
import pg from 'pg';

const client = new pg.Client({
  connectionString: process.env.DATABASE_URL,
});

async function cleanup() {
  try {
    await client.connect();
    console.log('📦 Connected to database');

    // Получаем все блоки
    const blocksResult = await client.query('SELECT id, name FROM blocks ORDER BY "order"');
    console.log(`\n📋 Found ${blocksResult.rows.length} blocks:`);
    
    for (const block of blocksResult.rows) {
      // Считаем варианты в блоке
      const variantsResult = await client.query(
        'SELECT COUNT(*) as count FROM variants WHERE "block_id" = $1',
        [block.id]
      );
      const variantCount = parseInt(variantsResult.rows[0].count);
      
      console.log(`\n🔹 Block: ${block.name}`);
      console.log(`   Variants: ${variantCount}`);
      
      if (variantCount === 0) {
        console.log(`   ❌ Empty block, deleting...`);
        
        // Удаляем payments связанные с subscription_plans этого блока
        await client.query(`
          DELETE FROM payments 
          WHERE "plan_id" IN (
            SELECT id FROM subscription_plans WHERE "block_id" = $1
          )
        `, [block.id]);
        
        // Удаляем user_subscriptions связанные с subscription_plans этого блока
        await client.query(`
          DELETE FROM user_subscriptions 
          WHERE "plan_id" IN (
            SELECT id FROM subscription_plans WHERE "block_id" = $1
          )
        `, [block.id]);
        
        // Удаляем subscription plans
        await client.query('DELETE FROM subscription_plans WHERE "block_id" = $1', [block.id]);
        
        // Теперь удаляем блок
        await client.query('DELETE FROM blocks WHERE id = $1', [block.id]);
        console.log(`   ✓ Deleted`);
      } else {
        // Проверяем первый вариант
        const variantResult = await client.query(
          'SELECT id, name FROM variants WHERE "block_id" = $1 LIMIT 1',
          [block.id]
        );
        
        if (variantResult.rows.length > 0) {
          const variant = variantResult.rows[0];
          
          // Считаем предметы
          const subjectsResult = await client.query(
            'SELECT COUNT(*) as count FROM subjects WHERE "variant_id" = $1',
            [variant.id]
          );
          const subjectCount = parseInt(subjectsResult.rows[0].count);
          
          // Считаем вопросы через предметы
          const questionsResult = await client.query(
            'SELECT COUNT(*) as count FROM questions WHERE "subject_id" IN (SELECT id FROM subjects WHERE "variant_id" = $1)',
            [variant.id]
          );
          const questionCount = parseInt(questionsResult.rows[0].count);
          
          console.log(`   Sample variant: ${variant.name}`);
          console.log(`   Subjects: ${subjectCount}`);
          console.log(`   Questions: ${questionCount}`);
          
          if (questionCount === 0) {
            console.log(`   ⚠️  Block has empty variants`);
          }
        }
      }
    }

    console.log('\n\n🗑️  Do you want to delete ALL blocks? (This will delete everything!)');
    console.log('To delete all, run: node cleanup-blocks.js --delete-all');
    
    if (process.argv.includes('--delete-all')) {
      console.log('\n⚠️  DELETING ALL BLOCKS...');
      
      // Delete in correct order due to foreign key constraints
      const paymentsResult = await client.query('DELETE FROM payments');
      console.log(`✅ Deleted ${paymentsResult.rowCount} payments`);

      const userSubsResult = await client.query('DELETE FROM user_subscriptions');
      console.log(`✅ Deleted ${userSubsResult.rowCount} user subscriptions`);

      const plansResult = await client.query('DELETE FROM subscription_plans');
      console.log(`✅ Deleted ${plansResult.rowCount} subscription plans`);

      const testResultsResult = await client.query('DELETE FROM test_results');
      console.log(`✅ Deleted ${testResultsResult.rowCount} test results`);

      const subjectsResult = await client.query('DELETE FROM subjects');
      console.log(`✅ Deleted ${subjectsResult.rowCount} subjects`);

      const answersResult = await client.query('DELETE FROM answers');
      console.log(`✅ Deleted ${answersResult.rowCount} answers`);

      const questionsResult = await client.query('DELETE FROM questions');
      console.log(`✅ Deleted ${questionsResult.rowCount} questions`);

      const variantsResult = await client.query('DELETE FROM variants');
      console.log(`✅ Deleted ${variantsResult.rowCount} variants`);

      const blocksResult = await client.query('DELETE FROM blocks');
      console.log(`✅ Deleted ${blocksResult.rowCount} blocks`);
      
      console.log('\n✅ All blocks and related data deleted successfully!');
    }
    
  } catch (error) {
    console.error('❌ Error:', error);
    process.exit(1);
  } finally {
    await client.end();
  }
}

cleanup();
