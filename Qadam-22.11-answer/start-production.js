import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

async function startProduction() {
  try {
    console.log('🔄 Running database migrations...');
    
    // Try to push schema
    try {
      await execAsync('npx drizzle-kit push --force');
      console.log('✅ Database schema updated successfully');
    } catch (error) {
      console.log('⚠️ Schema push failed (might be already up to date):', error.message);
    }
    
    // Try to run SQL migrations if they exist
    try {
      await execAsync('node run-migration.js');
      console.log('✅ SQL migrations completed');
    } catch (error) {
      console.log('⚠️ SQL migrations failed (might not exist):', error.message);
    }
    
    console.log('🚀 Starting application...');
    
    // Start the application
    const app = await import('./dist/index.js');
    
  } catch (error) {
    console.error('❌ Production startup failed:', error);
    process.exit(1);
  }
}

startProduction();
