import { usePushNotifications } from "@/hooks/use-push-notifications";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { 
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";

export default function PushNotificationSettings() {
  const {
    isSupported,
    permission,
    isSubscribed,
    isLoading,
    error,
    subscribe,
    unsubscribe,
    requestPermission,
    testNotification
  } = usePushNotifications();

  const getStatusBadge = () => {
    if (!isSupported) {
      return <Badge variant="destructive">Не поддерживается</Badge>;
    }
    
    if (permission === 'denied') {
      return <Badge variant="destructive">Заблокировано</Badge>;
    }
    
    if (isSubscribed) {
      return <Badge variant="default">Активно</Badge>;
    }
    
    return <Badge variant="secondary">Неактивно</Badge>;
  };

  const getPermissionText = () => {
    switch (permission) {
      case 'granted':
        return 'Разрешено';
      case 'denied':
        return 'Заблокировано';
      default:
        return 'Не запрошено';
    }
  };

  if (!isSupported) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <i className="fas fa-bell"></i>
            <span>Push-уведомления</span>
          </CardTitle>
          <CardDescription>
            Получайте уведомления о завершении тестов и важных событиях
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center space-x-2 p-4 rounded-lg bg-muted">
            <i className="fas fa-exclamation-triangle text-muted-foreground"></i>
            <div>
              <p className="text-sm font-medium">Не поддерживается</p>
              <p className="text-xs text-muted-foreground">
                Ваш браузер не поддерживает push-уведомления
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card data-testid="push-notification-settings">
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <i className="fas fa-bell"></i>
            <span>Push-уведомления</span>
          </div>
          {getStatusBadge()}
        </CardTitle>
        <CardDescription>
          Получайте уведомления о завершении тестов, напоминания и важные сообщения
        </CardDescription>
      </CardHeader>
      
      <CardContent className="space-y-6">
        {error && (
          <div className="p-3 rounded-lg bg-destructive/10 border border-destructive/20">
            <div className="flex items-center space-x-2">
              <i className="fas fa-exclamation-circle text-destructive"></i>
              <p className="text-sm text-destructive">{error}</p>
            </div>
          </div>
        )}

        {/* Status Information */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <Label className="text-sm">Разрешение браузера:</Label>
            <span className="text-sm text-muted-foreground">
              {getPermissionText()}
            </span>
          </div>
          
          <div className="flex items-center justify-between">
            <Label className="text-sm">Статус подписки:</Label>
            <span className="text-sm text-muted-foreground">
              {isSubscribed ? 'Активна' : 'Неактивна'}
            </span>
          </div>
        </div>

        <Separator />

        {/* Main Controls */}
        <div className="space-y-4">
          {permission === 'denied' && (
            <div className="p-4 rounded-lg bg-amber-50 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-800">
              <div className="flex items-start space-x-3">
                <i className="fas fa-info-circle text-amber-600 mt-0.5"></i>
                <div>
                  <p className="text-sm font-medium text-amber-800 dark:text-amber-200">
                    Push-уведомления заблокированы
                  </p>
                  <p className="text-xs text-amber-700 dark:text-amber-300 mt-1">
                    Чтобы включить уведомления, разрешите их в настройках браузера
                  </p>
                </div>
              </div>
            </div>
          )}

          {permission !== 'granted' && permission !== 'denied' && (
            <Button 
              onClick={requestPermission}
              disabled={isLoading}
              className="w-full"
              data-testid="button-request-permission"
            >
              <i className="fas fa-bell mr-2"></i>
              Разрешить уведомления
            </Button>
          )}

          {permission === 'granted' && (
            <div className="space-y-3">
              <div className="flex items-center space-x-2">
                <Switch
                  id="push-notifications"
                  checked={isSubscribed}
                  onCheckedChange={(checked) => {
                    if (checked) {
                      subscribe();
                    } else {
                      unsubscribe();
                    }
                  }}
                  disabled={isLoading}
                  data-testid="switch-push-notifications"
                />
                <Label htmlFor="push-notifications" className="flex-1">
                  Получать push-уведомления
                </Label>
              </div>

              {isSubscribed && (
                <div className="pl-6 space-y-2">
                  <p className="text-xs text-muted-foreground">
                    Вы будете получать уведомления о:
                  </p>
                  <ul className="text-xs text-muted-foreground space-y-1">
                    <li>• Завершении тестов и результатах</li>
                    <li>• Напоминаниях о запланированных тестах</li>
                    <li>• Важных системных сообщениях</li>
                    <li>• Достижениях и успехах</li>
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Test Button */}
        {isSubscribed && (
          <>
            <Separator />
            <div className="space-y-3">
              <Label className="text-sm font-medium">Тестирование</Label>
              <Button
                variant="outline"
                onClick={testNotification}
                disabled={isLoading}
                className="w-full"
                data-testid="button-test-notification"
              >
                <i className="fas fa-paper-plane mr-2"></i>
                Отправить тестовое уведомление
              </Button>
            </div>
          </>
        )}

        {/* Advanced Actions */}
        {isSubscribed && (
          <>
            <Separator />
            <div className="space-y-3">
              <Label className="text-sm font-medium">Управление</Label>
              <AlertDialog>
                <AlertDialogTrigger asChild>
                  <Button 
                    variant="outline" 
                    className="w-full text-destructive hover:text-destructive"
                    data-testid="button-unsubscribe"
                  >
                    <i className="fas fa-times mr-2"></i>
                    Отключить push-уведомления
                  </Button>
                </AlertDialogTrigger>
                <AlertDialogContent>
                  <AlertDialogHeader>
                    <AlertDialogTitle>Отключить push-уведомления?</AlertDialogTitle>
                    <AlertDialogDescription>
                      Вы больше не будете получать push-уведомления на этом устройстве.
                      Вы всегда можете включить их снова в настройках.
                    </AlertDialogDescription>
                  </AlertDialogHeader>
                  <AlertDialogFooter>
                    <AlertDialogCancel>Отмена</AlertDialogCancel>
                    <AlertDialogAction 
                      onClick={unsubscribe}
                      className="bg-destructive hover:bg-destructive/90"
                    >
                      Отключить
                    </AlertDialogAction>
                  </AlertDialogFooter>
                </AlertDialogContent>
              </AlertDialog>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}
