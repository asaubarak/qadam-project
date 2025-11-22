import 'dotenv/config';
import { db } from './server/db.ts';
import { subscriptionPlans, payments, userSubscriptions } from './shared/schema.ts';

async function updatePlans() {
  try {
    console.log('🗑️ Очищаем связанные данные...');
    await db.delete(payments);
    await db.delete(userSubscriptions);
    console.log('✅ Связанные данные очищены');
    
    console.log('🗑️ Удаляем старые тарифные планы...');
    await db.delete(subscriptionPlans);
    console.log('✅ Старые планы удалены');
    
    const plans = [
      {
        name: '1 тест',
        description: 'Одна попытка прохождения теста',
        price: 50000, // 500 тенге в копейках
        currency: 'KZT',
        durationDays: 1,
        features: ['single_test', 'basic_results'],
        isActive: true, 
        sortOrder: 1
      },
      {
        name: 'Физмат на месяц',
        description: 'Полный доступ к блоку Физико-математическое направление на месяц',
        price: 100000, // 1000 тенге в копейках
        currency: 'KZT',
        durationDays: 30,
        features: ['physics_math_block', 'unlimited_tests', 'progress_tracking', 'detailed_results'],
        isActive: true,
        sortOrder: 2
      }
    ];

    console.log('🌱 Добавляем новые тарифные планы...');
    
    for (const plan of plans) {
      await db.insert(subscriptionPlans).values(plan);
      console.log(`✅ План "${plan.name}" добавлен - ${plan.price/100} ${plan.currency}`);
    }
    
    console.log('🎉 Новые тарифные планы успешно добавлены!');
    process.exit(0);
  } catch (error) {
    console.error('❌ Ошибка при обновлении планов:', error);
    process.exit(1);
  }
}

updatePlans();