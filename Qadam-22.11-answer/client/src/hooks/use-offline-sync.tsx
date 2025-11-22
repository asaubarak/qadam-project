import { useState, useEffect, useCallback } from 'react';
import { offlineDB, ActiveTest, OfflineTestResult } from '@/lib/offline-db';
import { apiRequest } from '@/lib/queryClient';
import { useToast } from '@/hooks/use-toast';

interface SyncStatus {
  isOnline: boolean;
  isSyncing: boolean;
  pendingTests: number;
  pendingResults: number;
  lastSync: Date | null;
  errors: string[];
}

interface UseOfflineSyncReturn {
  syncStatus: SyncStatus;
  syncNow: () => Promise<void>;
  saveDraftTest: (test: ActiveTest) => Promise<void>;
  saveCompletedTest: (result: OfflineTestResult) => Promise<void>;
  getOfflineTest: (testId: string) => Promise<ActiveTest | undefined>;
  clearOfflineData: () => Promise<void>;
}

export function useOfflineSync(): UseOfflineSyncReturn {
  const { toast } = useToast();
  const [syncStatus, setSyncStatus] = useState<SyncStatus>({
    isOnline: navigator.onLine,
    isSyncing: false,
    pendingTests: 0,
    pendingResults: 0,
    lastSync: null,
    errors: []
  });

  // Initialize offline database
  useEffect(() => {
    offlineDB.init().catch(error => {
      console.error('[Sync] Failed to initialize offline database:', error);
      toast({
        title: "Ошибка",
        description: "Не удалось инициализировать офлайн режим",
        variant: "destructive"
      });
    });
  }, [toast]);

  // Update sync status periodically
  const updateSyncStatus = useCallback(async () => {
    try {
      const [activeTests, pendingResults] = await Promise.all([
        offlineDB.getTestsBySyncStatus('pending'),
        offlineDB.getPendingResults()
      ]);

      // Only update if values actually changed
      setSyncStatus(prev => {
        const newPending = activeTests.length;
        const newResults = pendingResults.length;
        const newOnline = navigator.onLine;
        
        if (prev.pendingTests === newPending && 
            prev.pendingResults === newResults && 
            prev.isOnline === newOnline &&
            prev.isSyncing === false) {
          return prev; // No change, return same reference to avoid re-render
        }
        
        return {
          ...prev,
          isOnline: newOnline,
          pendingTests: newPending,
          pendingResults: newResults
        };
      });
    } catch (error) {
      console.error('[Sync] Failed to update sync status:', error);
    }
  }, []);

  // Listen for online/offline events
  useEffect(() => {
    const handleOnline = () => {
      setSyncStatus(prev => {
        // Только обновляем если статус изменился
        if (prev.isOnline && prev.errors.length === 0) {
          return prev; // Уже онлайн, не создаём новый объект
        }
        return { ...prev, isOnline: true, errors: [] };
      });
      // Don't auto-sync here to avoid infinite loop
      // User can manually sync or we sync on test completion
    };

    const handleOffline = () => {
      setSyncStatus(prev => {
        // Только обновляем если статус изменился
        if (!prev.isOnline && !prev.isSyncing) {
          return prev; // Уже офлайн, не создаём новый объект
        }
        return { ...prev, isOnline: false, isSyncing: false };
      });
    };

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);
    
    // Update status on mount and periodically
    updateSyncStatus();
    const interval = setInterval(updateSyncStatus, 30000); // Every 30 seconds

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
      clearInterval(interval);
    };
  }, [updateSyncStatus]);

  // Sync active tests to server
  const syncActiveTests = async (): Promise<void> => {
    const pendingTests = await offlineDB.getTestsBySyncStatus('pending');
    
    for (const test of pendingTests) {
      try {
        await offlineDB.updateSyncStatus(test.id, 'syncing');
        
        // Send test progress to server (save draft)
        const response = await apiRequest('POST', '/api/test-progress', {
          testId: test.id,
          variantId: test.variantId,
          answers: test.userAnswers,
          timeSpent: test.timeSpent,
          lastSavedAt: test.lastSavedAt
        });

        if (response.ok) {
          await offlineDB.updateSyncStatus(test.id, 'synced');
          console.log('[Sync] Test progress synced:', test.id);
        } else {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
      } catch (error) {
        console.error('[Sync] Failed to sync test:', test.id, error);
        await offlineDB.updateSyncStatus(test.id, 'failed', error instanceof Error ? error.message : 'Unknown error');
      }
    }
  };

  // Sync completed test results to server
  const syncTestResults = async (): Promise<void> => {
    const pendingResults = await offlineDB.getPendingResults();
    
    for (const result of pendingResults) {
      try {
        await offlineDB.updateSyncStatus(result.id, 'syncing');
        
        // Submit test result to server
        const response = await apiRequest('POST', '/api/test-results', {
          variantId: result.variantId,
          answers: result.answers,
          timeSpent: result.timeSpent
        });

        if (response.ok) {
          await offlineDB.deleteTestResult(result.id);
          console.log('[Sync] Test result synced and deleted:', result.id);
        } else {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
      } catch (error) {
        console.error('[Sync] Failed to sync result:', result.id, error);
        await offlineDB.updateSyncStatus(result.id, 'failed', error instanceof Error ? error.message : 'Unknown error');
      }
    }
  };

  // Manual sync trigger
  const syncNow = useCallback(async (): Promise<void> => {
    if (!navigator.onLine) {
      toast({
        title: "Нет подключения",
        description: "Синхронизация невозможна без интернет-соединения",
        variant: "destructive"
      });
      return;
    }

    setSyncStatus(prev => {
      // Только обновляем если не синхронизируем
      if (prev.isSyncing && prev.errors.length === 0) {
        return prev;
      }
      return { ...prev, isSyncing: true, errors: [] };
    });

    try {
      console.log('[Sync] Starting manual sync...');
      
      await Promise.all([
        syncActiveTests(),
        syncTestResults()
      ]);

      setSyncStatus(prev => {
        // Всегда обновляем тут т.к. isSyncing меняется с true на false
        return {
          ...prev,
          isSyncing: false,
          lastSync: new Date(),
          errors: []
        };
      });

      await updateSyncStatus();

      toast({
        title: "Синхронизация завершена",
        description: "Все данные успешно синхронизированы",
      });

    } catch (error) {
      console.error('[Sync] Sync failed:', error);
      const errorMessage = error instanceof Error ? error.message : 'Неизвестная ошибка';
      
      setSyncStatus(prev => ({
        ...prev,
        isSyncing: false,
        errors: [...prev.errors, errorMessage]
      }));

      toast({
        title: "Ошибка синхронизации",
        description: errorMessage,
        variant: "destructive"
      });
    }
  }, [toast, updateSyncStatus]);

  // Save test progress (draft) to offline storage
  const saveDraftTest = useCallback(async (test: ActiveTest): Promise<void> => {
    try {
      test.lastSavedAt = Date.now();
      test.syncStatus = 'pending';
      await offlineDB.saveActiveTest(test);
      console.log('[Sync] Test draft saved offline:', test.id);
      
      await updateSyncStatus();
    } catch (error) {
      console.error('[Sync] Failed to save test draft:', error);
      throw error;
    }
  }, [updateSyncStatus]);

  // Save completed test result to offline storage
  const saveCompletedTest = useCallback(async (result: OfflineTestResult): Promise<void> => {
    try {
      result.syncStatus = 'pending';
      result.syncAttempts = 0;
      await offlineDB.saveTestResult(result);
      console.log('[Sync] Test result saved offline:', result.id);
      
      // Remove from active tests since it's completed
      await offlineDB.deleteActiveTest(result.testId);
      
      await updateSyncStatus();
      
      // Try immediate sync if online
      if (navigator.onLine) {
        syncNow();
      }
    } catch (error) {
      console.error('[Sync] Failed to save test result:', error);
      throw error;
    }
  }, [updateSyncStatus, syncNow]);

  // Get offline test data
  const getOfflineTest = useCallback(async (testId: string): Promise<ActiveTest | undefined> => {
    return await offlineDB.getActiveTest(testId);
  }, []);

  // Clear all offline data
  const clearOfflineData = useCallback(async (): Promise<void> => {
    try {
      await offlineDB.clearAllData();
      await updateSyncStatus();
      
      toast({
        title: "Данные очищены",
        description: "Все офлайн данные удалены",
      });
    } catch (error) {
      console.error('[Sync] Failed to clear offline data:', error);
      toast({
        title: "Ошибка",
        description: "Не удалось очистить офлайн данные",
        variant: "destructive"
      });
    }
  }, [updateSyncStatus, toast]);

  return {
    syncStatus,
    syncNow,
    saveDraftTest,
    saveCompletedTest,
    getOfflineTest,
    clearOfflineData
  };
}
