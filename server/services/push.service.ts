import webpush from 'web-push';

// VAPID keys for Web Push (in production, store these securely)
const vapidKeys = {
  publicKey: 'BCHhBDxcAj5TrD2Zzg3g3UjgBHO9SjO9SjO9SjO9SjO9SjO9SjO9SjO9SjO9SjO9SjO9SjO9Sj',
  privateKey: 'abcd1234567890abcd1234567890abcd1234567890abcd12'
};

interface PushSubscription {
  endpoint: string;
  keys: {
    p256dh: string;
    auth: string;
  };
}

interface NotificationPayload {
  title: string;
  body: string;
  icon?: string;
  badge?: string;
  tag?: string;
  url?: string;
  data?: any;
}

export class PushService {
  constructor() {
    // Configure web-push with VAPID details
    webpush.setVapidDetails(
      'mailto:admin@projectent.com',
      vapidKeys.publicKey,
      vapidKeys.privateKey
    );
  }

  getVapidPublicKey(): string {
    return vapidKeys.publicKey;
  }

  async sendNotification(
    subscription: PushSubscription, 
    payload: NotificationPayload
  ): Promise<boolean> {
    try {
      const notificationPayload = JSON.stringify({
        title: payload.title,
        body: payload.body,
        icon: payload.icon || '/icon-192x192.png',
        badge: payload.badge || '/icon-96x96.png',
        tag: payload.tag || 'default',
        url: payload.url || '/',
        data: payload.data,
        requireInteraction: true,
        actions: [
          {
            action: 'open',
            title: 'Открыть',
            icon: '/icon-96x96.png'
          }
        ]
      });

      const result = await webpush.sendNotification(
        subscription,
        notificationPayload,
        {
          TTL: 24 * 60 * 60, // 24 hours
          urgency: 'normal'
        }
      );

      console.log('[Push] Notification sent successfully');
      return true;
    } catch (error) {
      console.error('[Push] Failed to send notification:', error);
      
      // Handle expired subscriptions
      if (error && typeof error === 'object' && 'statusCode' in error) {
        const statusCode = (error as any).statusCode;
        if (statusCode === 410 || statusCode === 404) {
          console.log('[Push] Subscription expired or invalid');
          // Return false to indicate subscription should be removed
          return false;
        }
      }
      
      throw error;
    }
  }

  async sendBulkNotifications(
    subscriptions: PushSubscription[],
    payload: NotificationPayload
  ): Promise<{ sent: number; failed: number; expired: string[] }> {
    const results = {
      sent: 0,
      failed: 0,
      expired: [] as string[]
    };

    const promises = subscriptions.map(async (subscription) => {
      try {
        const success = await this.sendNotification(subscription, payload);
        if (success) {
          results.sent++;
        } else {
          results.expired.push(subscription.endpoint);
        }
      } catch (error) {
        results.failed++;
        console.error('[Push] Bulk notification failed for:', subscription.endpoint, error);
      }
    });

    await Promise.all(promises);
    
    console.log(`[Push] Bulk notification results:`, results);
    return results;
  }

  validateSubscription(subscription: any): boolean {
    return (
      subscription &&
      typeof subscription.endpoint === 'string' &&
      subscription.keys &&
      typeof subscription.keys.p256dh === 'string' &&
      typeof subscription.keys.auth === 'string'
    );
  }

  // Notification templates
  getTestCompletedNotification(username: string, score: number, percentage: number): NotificationPayload {
    return {
      title: 'Тест завершен! 🎉',
      body: `${username}, вы набрали ${score} баллов (${percentage.toFixed(1)}%)`,
      tag: 'test-completed',
      url: '/results',
      data: { type: 'TEST_COMPLETED', score, percentage }
    };
  }

  getTestReminderNotification(testName: string, dueInMinutes: number): NotificationPayload {
    return {
      title: 'Напоминание о тесте ⏰',
      body: `${testName} начнется через ${dueInMinutes} минут`,
      tag: 'test-reminder',
      url: '/',
      data: { type: 'TEST_REMINDER', dueInMinutes }
    };
  }

  getSystemMessageNotification(title: string, message: string): NotificationPayload {
    return {
      title: title,
      body: message,
      tag: 'system-message',
      url: '/notifications',
      data: { type: 'SYSTEM_MESSAGE' }
    };
  }

  getAchievementNotification(achievement: string, description: string): NotificationPayload {
    return {
      title: `Достижение разблокировано! 🏆`,
      body: `${achievement}: ${description}`,
      tag: 'achievement',
      url: '/profile',
      data: { type: 'ACHIEVEMENT', achievement }
    };
  }
}

export const pushService = new PushService();