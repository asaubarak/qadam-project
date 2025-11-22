import 'dotenv/config';
import { db } from './server/db.ts';
import { subscriptionPlans, payments, userSubscriptions, blocks } from './shared/schema.ts';

async function createDynamicPlans() {
  try {
    console.log('🗑️ Очищаем старые данные...');
    await db.delete(payments);
    await db.delete(userSubscriptions);
    await db.delete(subscriptionPlans);
    console.log('✅ Старые данные очищены');
    
    // Получаем все блоки из базы данных
    const allBlocks = await db.select().from(blocks);
    console.log(`📋 Найдено блоков: ${allBlocks.length}`);
    
    const plans = [];
    
    // 1. План для одного теста (без привязки к блоку)
    plans.push({
      name: '1 тест',
      description: 'Одна попытка прохождения любого теста',
      price: 50000, // 500 тенге
      currency: 'KZT',
      durationDays: 1,
      features: ['single_test', 'basic_results'],
      planType: 'single_test',
      blockId: null,
      isActive: true,
      sortOrder: 1
    });
    
    // 2. Создаем планы для каждого блока
    allBlocks.forEach((block, index) => {
      plans.push({
        name: `${block.name} - 1 месяц`,
        description: `Полный доступ к блоку "${block.name}" на месяц`,
        price: 100000, // 1000 тенге
        currency: 'KZT', 
        durationDays: 30,
        features: ['block_access', 'unlimited_tests', 'progress_tracking', 'detailed_results'],
        planType: 'block_access',
        blockId: block.id,
        isActive: true,
        sortOrder: index + 2
      });
    });

    console.log('🌱 Добавляем новые тарифные планы...');
    
    for (const plan of plans) {
      await db.insert(subscriptionPlans).values(plan);
      console.log(`✅ План "${plan.name}" добавлен - ${plan.price/100} ${plan.currency}`);
    }
    
    console.log(`🎉 Создано ${plans.length} тарифных планов!`);
    process.exit(0);
  } catch (error) {
    console.error('❌ Ошибка при создании планов:', error);
    process.exit(1);
  }
}

createDynamicPlans();