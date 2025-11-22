import 'dotenv/config';
import { db } from './server/db.ts';
import { subscriptionPlans } from './shared/schema.ts';

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

async function seedPlans() {
  try {
    console.log('🌱 Заполняем тарифные планы...');
    
    for (const plan of plans) {
      await db.insert(subscriptionPlans)
        .values(plan)
        .onConflictDoNothing();
      console.log(`✅ План "${plan.name}" добавлен`);
    }
    
    console.log('🎉 Все тарифные планы успешно добавлены!');
    process.exit(0);
  } catch (error) {
    console.error('❌ Ошибка при заполнении планов:', error);
    process.exit(1);
  }
}

seedPlans();