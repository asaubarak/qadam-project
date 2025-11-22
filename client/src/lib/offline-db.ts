// IndexedDB wrapper for offline test functionality
import { openDB, DBSchema, IDBPDatabase } from 'idb';

export interface ActiveTest {
  id: string;
  variantId: string;
  variant: {
    id: string;
    name: string;
    blockId: string;
    block: {
      id: string;
      name: string;
      hasCalculator: boolean;
      hasPeriodicTable: boolean;
    };
  };
  testData: {
    subject: {
      id: string;
      name: string;
    };
    questions: {
      id: string;
      text: string;
      answers: {
        id: string;
        text: string;
      }[];
    }[];
  }[];
  userAnswers: Record<string, string | string[]>;
  startedAt: number;
  lastSavedAt: number;
  timeSpent: number;
  isCompleted: boolean;
  syncStatus: 'pending' | 'syncing' | 'synced' | 'failed';
  syncAttempts: number;
  lastSyncError?: string;
}

export interface OfflineTestResult {
  id: string;
  testId: string;
  variantId: string;
  answers: Record<string, string | string[]>;
  timeSpent: number;
  completedAt: number;
  syncStatus: 'pending' | 'syncing' | 'synced' | 'failed';
  syncAttempts: number;
  lastSyncError?: string;
}

export interface CachedTestData {
  id: string; // variantId
  data: any;
  cachedAt: number;
  expiresAt: number;
}

interface OfflineDBSchema extends DBSchema {
  activeTests: {
    key: string;
    value: ActiveTest;
    indexes: {
      'by-sync-status': string;
      'by-started-at': number;
    };
  };
  testResults: {
    key: string;
    value: OfflineTestResult;
    indexes: {
      'by-sync-status': string;
      'by-completed-at': number;
    };
  };
  cachedTests: {
    key: string;
    value: CachedTestData;
    indexes: {
      'by-expires-at': number;
    };
  };
}

class OfflineDatabase {
  private db: IDBPDatabase<OfflineDBSchema> | null = null;
  private readonly DB_NAME = 'ProjectEntOffline';
  private readonly DB_VERSION = 1;

  async init(): Promise<void> {
    if (this.db) return;

    try {
      this.db = await openDB<OfflineDBSchema>(this.DB_NAME, this.DB_VERSION, {
        upgrade(db) {
          // Active tests store
          const activeTestStore = db.createObjectStore('activeTests', {
            keyPath: 'id'
          });
          activeTestStore.createIndex('by-sync-status', 'syncStatus');
          activeTestStore.createIndex('by-started-at', 'startedAt');

          // Test results store
          const testResultsStore = db.createObjectStore('testResults', {
            keyPath: 'id'
          });
          testResultsStore.createIndex('by-sync-status', 'syncStatus');
          testResultsStore.createIndex('by-completed-at', 'completedAt');

          // Cached test data store
          const cachedTestsStore = db.createObjectStore('cachedTests', {
            keyPath: 'id'
          });
          cachedTestsStore.createIndex('by-expires-at', 'expiresAt');

          console.log('[OfflineDB] Database initialized with stores');
        },
      });

      console.log('[OfflineDB] Connected to database');
      
      // Clean expired cached tests on init
      await this.cleanExpiredCache();
    } catch (error) {
      console.error('[OfflineDB] Failed to initialize database:', error);
      throw error;
    }
  }

  // Active Tests Management
  async saveActiveTest(test: ActiveTest): Promise<void> {
    if (!this.db) await this.init();
    await this.db!.put('activeTests', test);
    console.log('[OfflineDB] Active test saved:', test.id);
  }

  async getActiveTest(id: string): Promise<ActiveTest | undefined> {
    if (!this.db) await this.init();
    return await this.db!.get('activeTests', id);
  }

  async getAllActiveTests(): Promise<ActiveTest[]> {
    if (!this.db) await this.init();
    return await this.db!.getAll('activeTests');
  }

  async deleteActiveTest(id: string): Promise<void> {
    if (!this.db) await this.init();
    await this.db!.delete('activeTests', id);
    console.log('[OfflineDB] Active test deleted:', id);
  }

  async getTestsBySyncStatus(status: ActiveTest['syncStatus']): Promise<ActiveTest[]> {
    if (!this.db) await this.init();
    return await this.db!.getAllFromIndex('activeTests', 'by-sync-status', status);
  }

  // Test Results Management
  async saveTestResult(result: OfflineTestResult): Promise<void> {
    if (!this.db) await this.init();
    await this.db!.put('testResults', result);
    console.log('[OfflineDB] Test result saved:', result.id);
  }

  async getTestResult(id: string): Promise<OfflineTestResult | undefined> {
    if (!this.db) await this.init();
    return await this.db!.get('testResults', id);
  }

  async getPendingResults(): Promise<OfflineTestResult[]> {
    if (!this.db) await this.init();
    return await this.db!.getAllFromIndex('testResults', 'by-sync-status', 'pending');
  }

  async deleteTestResult(id: string): Promise<void> {
    if (!this.db) await this.init();
    await this.db!.delete('testResults', id);
    console.log('[OfflineDB] Test result deleted:', id);
  }

  // Cached Test Data Management
  async cacheTestData(variantId: string, data: any, ttlHours: number = 24): Promise<void> {
    if (!this.db) await this.init();
    
    const cachedData: CachedTestData = {
      id: variantId,
      data,
      cachedAt: Date.now(),
      expiresAt: Date.now() + (ttlHours * 60 * 60 * 1000)
    };

    await this.db!.put('cachedTests', cachedData);
    console.log('[OfflineDB] Test data cached:', variantId);
  }

  async getCachedTestData(variantId: string): Promise<any | null> {
    if (!this.db) await this.init();
    
    const cached = await this.db!.get('cachedTests', variantId);
    if (!cached) return null;

    // Check if expired
    if (cached.expiresAt < Date.now()) {
      await this.db!.delete('cachedTests', variantId);
      console.log('[OfflineDB] Expired cache removed:', variantId);
      return null;
    }

    console.log('[OfflineDB] Serving cached test data:', variantId);
    return cached.data;
  }

  async cleanExpiredCache(): Promise<void> {
    if (!this.db) await this.init();
    
    const now = Date.now();
    const expired = await this.db!.getAllFromIndex('cachedTests', 'by-expires-at', IDBKeyRange.upperBound(now));
    
    for (const item of expired) {
      await this.db!.delete('cachedTests', item.id);
    }

    if (expired.length > 0) {
      console.log(`[OfflineDB] Cleaned ${expired.length} expired cache entries`);
    }
  }

  // Sync Management
  async updateSyncStatus(testId: string, status: ActiveTest['syncStatus'], error?: string): Promise<void> {
    if (!this.db) await this.init();
    
    // Try updating active test first
    const activeTest = await this.getActiveTest(testId);
    if (activeTest) {
      activeTest.syncStatus = status;
      if (error) activeTest.lastSyncError = error;
      if (status === 'syncing') activeTest.syncAttempts = (activeTest.syncAttempts || 0) + 1;
      await this.saveActiveTest(activeTest);
      return;
    }

    // Try updating test result
    const testResult = await this.getTestResult(testId);
    if (testResult) {
      testResult.syncStatus = status;
      if (error) testResult.lastSyncError = error;
      if (status === 'syncing') testResult.syncAttempts = (testResult.syncAttempts || 0) + 1;
      await this.saveTestResult(testResult);
    }
  }

  // Database maintenance
  async clearAllData(): Promise<void> {
    if (!this.db) await this.init();
    
    const stores = ['activeTests', 'testResults', 'cachedTests'] as const;
    for (const store of stores) {
      await this.db!.clear(store);
    }
    
    console.log('[OfflineDB] All data cleared');
  }

  async getStorageUsage(): Promise<{ activeTests: number; testResults: number; cachedTests: number }> {
    if (!this.db) await this.init();
    
    return {
      activeTests: await this.db!.count('activeTests'),
      testResults: await this.db!.count('testResults'),
      cachedTests: await this.db!.count('cachedTests')
    };
  }
}

// Export singleton instance
export const offlineDB = new OfflineDatabase();
