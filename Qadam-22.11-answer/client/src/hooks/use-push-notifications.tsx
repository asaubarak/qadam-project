import { useState, useEffect, useCallback } from 'react';
import { useAuth } from '@/hooks/use-auth';
import { apiRequest } from '@/lib/queryClient';
import { useToast } from '@/hooks/use-toast';

interface PushNotificationState {
  isSupported: boolean;
  permission: NotificationPermission;
  isSubscribed: boolean;
  isLoading: boolean;
  error: string | null;
}

interface PushSubscriptionData {
  endpoint: string;
  keys: {
    p256dh: string;
    auth: string;
  };
}

export function usePushNotifications() {
  const { user } = useAuth();
  const { toast } = useToast();
  
  const [state, setState] = useState<PushNotificationState>({
    isSupported: false,
    permission: 'default',
    isSubscribed: false,
    isLoading: false,
    error: null
  });

  // Check if push notifications are supported
  useEffect(() => {
    const isSupported = 'serviceWorker' in navigator && 
                       'PushManager' in window && 
                       'Notification' in window;
    
    setState(prev => ({
      ...prev,
      isSupported,
      permission: isSupported ? Notification.permission : 'denied'
    }));

    if (isSupported && user) {
      checkSubscriptionStatus();
    }
  }, [user]);

  // Check current subscription status
  const checkSubscriptionStatus = useCallback(async () => {
    if (!state.isSupported || !user) return;

    try {
      setState(prev => ({ ...prev, isLoading: true, error: null }));

      const registration = await navigator.serviceWorker.ready;
      const subscription = await registration.pushManager.getSubscription();
      
      setState(prev => ({
        ...prev,
        isSubscribed: !!subscription,
        isLoading: false
      }));
    } catch (error) {
      console.error('[Push] Failed to check subscription status:', error);
      setState(prev => ({
        ...prev,
        isLoading: false,
        error: 'Не удалось проверить статус подписки'
      }));
    }
  }, [state.isSupported, user]);

  // Request notification permission
  const requestPermission = useCallback(async (): Promise<boolean> => {
    if (!state.isSupported) {
      toast({
        title: "Не поддерживается",
        description: "Ваш браузер не поддерживает push-уведомления",
        variant: "destructive"
      });
      return false;
    }

    try {
      const permission = await Notification.requestPermission();
      setState(prev => ({ ...prev, permission }));

      if (permission === 'granted') {
        toast({
          title: "Разрешение получено",
          description: "Теперь вы будете получать уведомления"
        });
        return true;
      } else if (permission === 'denied') {
        toast({
          title: "Разрешение отклонено",
          description: "Включите уведомления в настройках браузера",
          variant: "destructive"
        });
        return false;
      }
      
      return false;
    } catch (error) {
      console.error('[Push] Permission request failed:', error);
      toast({
        title: "Ошибка",
        description: "Не удалось запросить разрешение на уведомления",
        variant: "destructive"
      });
      return false;
    }
  }, [state.isSupported, toast]);

  // Subscribe to push notifications
  const subscribe = useCallback(async (): Promise<boolean> => {
    if (!state.isSupported || !user) return false;

    try {
      setState(prev => ({ ...prev, isLoading: true, error: null }));

      // Request permission if not granted
      if (state.permission !== 'granted') {
        const granted = await requestPermission();
        if (!granted) {
          setState(prev => ({ ...prev, isLoading: false }));
          return false;
        }
      }

      // Get VAPID public key
      const vapidResponse = await apiRequest('GET', '/api/push/vapid-key');
      if (!vapidResponse.ok) {
        throw new Error('Failed to get VAPID key');
      }
      const { publicKey } = await vapidResponse.json();

      // Subscribe with service worker
      const registration = await navigator.serviceWorker.ready;
      const subscription = await registration.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: publicKey
      });

      // Send subscription to server
      const toBase64 = (u8: Uint8Array | null) => {
        if (!u8) return '';
        const arr = Array.from(u8);
        return btoa(String.fromCharCode.apply(null, arr as any));
      };

      const subscriptionData: PushSubscriptionData = {
        endpoint: subscription.endpoint,
        keys: {
          p256dh: toBase64(new Uint8Array(subscription.getKey('p256dh')!)),
          auth: toBase64(new Uint8Array(subscription.getKey('auth')!))
        }
      };

      const response = await apiRequest('POST', '/api/push/subscribe', subscriptionData);
      
      if (!response.ok) {
        throw new Error('Failed to save subscription');
      }

      setState(prev => ({
        ...prev,
        isSubscribed: true,
        isLoading: false
      }));

      toast({
        title: "Подписка активирована",
        description: "Вы будете получать push-уведомления"
      });

      return true;
    } catch (error) {
      console.error('[Push] Subscription failed:', error);
      setState(prev => ({
        ...prev,
        isLoading: false,
        error: 'Не удалось подписаться на уведомления'
      }));

      toast({
        title: "Ошибка подписки",
        description: "Не удалось активировать push-уведомления",
        variant: "destructive"
      });

      return false;
    }
  }, [state.isSupported, state.permission, user, requestPermission, toast]);

  // Unsubscribe from push notifications
  const unsubscribe = useCallback(async (): Promise<boolean> => {
    if (!state.isSupported || !user) return false;

    try {
      setState(prev => ({ ...prev, isLoading: true, error: null }));

      const registration = await navigator.serviceWorker.ready;
      const subscription = await registration.pushManager.getSubscription();

      if (subscription) {
        // Unsubscribe from browser
        await subscription.unsubscribe();

        // Remove from server
        const response = await apiRequest('POST', '/api/push/unsubscribe', {
          endpoint: subscription.endpoint
        });

        if (!response.ok) {
          console.warn('[Push] Failed to remove subscription from server');
        }
      }

      setState(prev => ({
        ...prev,
        isSubscribed: false,
        isLoading: false
      }));

      toast({
        title: "Подписка отменена",
        description: "Вы больше не будете получать push-уведомления"
      });

      return true;
    } catch (error) {
      console.error('[Push] Unsubscription failed:', error);
      setState(prev => ({
        ...prev,
        isLoading: false,
        error: 'Не удалось отменить подписку'
      }));

      toast({
        title: "Ошибка",
        description: "Не удалось отменить подписку на уведомления",
        variant: "destructive"
      });

      return false;
    }
  }, [state.isSupported, user, toast]);

  // Test push notification
  const testNotification = useCallback(async (): Promise<boolean> => {
    if (!state.isSubscribed || !user) return false;

    try {
      const response = await apiRequest('POST', '/api/push/test');
      
      if (response.ok) {
        toast({
          title: "Тестовое уведомление отправлено",
          description: "Проверьте, пришло ли уведомление"
        });
        return true;
      } else {
        throw new Error('Test notification failed');
      }
    } catch (error) {
      console.error('[Push] Test notification failed:', error);
      toast({
        title: "Ошибка",
        description: "Не удалось отправить тестовое уведомление",
        variant: "destructive"
      });
      return false;
    }
  }, [state.isSubscribed, user, toast]);

  return {
    ...state,
    subscribe,
    unsubscribe,
    requestPermission,
    testNotification,
    refresh: checkSubscriptionStatus
  };
}
