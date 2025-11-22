// Script to add test results for today on production
const { db } = require('./server/db.ts');
const { testResults, users } = require('./shared/schema.ts');

async function addProductionTestResults() {
  try {
    console.log('🚀 Adding test results for today on production...');
    
    // Get existing users from production
    const existingUsers = await db.select().from(users).limit(10);
    console.log(`Found ${existingUsers.length} users in production`);
    
    if (existingUsers.length === 0) {
      console.log('❌ No users found. Cannot create test results.');
      return;
    }
    
    // Get current date in Kazakhstan time (UTC+6)
    const now = new Date();
    const kazakhstanOffset = 6 * 60; // UTC+6 in minutes
    const kazakhstanTime = new Date(now.getTime() + (kazakhstanOffset * 60 * 1000));
    
    console.log('🌍 Current Kazakhstan time:', kazakhstanTime.toISOString());
    
    // Create test results for today (in Kazakhstan timezone)
    const todayTestResults = [
      {
        id: `prod-result-${Date.now()}-1`,
        userId: existingUsers[0].id,
        variantId: 'variant-physics-math-1',
        score: 88,
        percentage: 88,
        totalQuestions: 100,
        timeSpent: 7200, // 2 hours
        answers: JSON.stringify({
          'q1': 'answer1',
          'q2': 'answer2',
          'q3': 'answer3'
        }),
        completedAt: new Date() // Current time (will be stored as UTC)
      },
      {
        id: `prod-result-${Date.now()}-2`,
        userId: existingUsers[1]?.id || existingUsers[0].id,
        variantId: 'variant-chemistry-bio-1',
        score: 95,
        percentage: 95,
        totalQuestions: 100,
        timeSpent: 6900, // 1.9 hours
        answers: JSON.stringify({
          'q1': 'answer1',
          'q2': 'answer2',
          'q3': 'answer3'
        }),
        completedAt: new Date() // Current time (will be stored as UTC)
      },
      {
        id: `prod-result-${Date.now()}-3`,
        userId: existingUsers[2]?.id || existingUsers[0].id,
        variantId: 'variant-history-1',
        score: 76,
        percentage: 76,
        totalQuestions: 100,
        timeSpent: 8100, // 2.25 hours
        answers: JSON.stringify({
          'q1': 'answer1',
          'q2': 'answer2'
        }),
        completedAt: new Date() // Current time (will be stored as UTC)
      }
    ];
    
    console.log('📝 Creating test results...');
    for (const result of todayTestResults) {
      await db.insert(testResults).values(result);
      console.log(`✅ Added result with score: ${result.score} for user: ${result.userId}`);
    }
    
    console.log('🎉 Successfully added production test results!');
    
    // Test the API endpoint
    console.log('\n🔍 Testing getTodayBestResult function...');
    const { DatabaseStorage } = require('./server/storage.ts');
    const storage = new DatabaseStorage();
    const bestResult = await storage.getTodayBestResult();
    console.log('🏆 Best result today:', bestResult);
    
    process.exit(0);
    
  } catch (error) {
    console.error('❌ Error adding production test results:', error);
    process.exit(1);
  }
}

// Only run if this is the main module
if (require.main === module) {
  addProductionTestResults();
}

module.exports = { addProductionTestResults };