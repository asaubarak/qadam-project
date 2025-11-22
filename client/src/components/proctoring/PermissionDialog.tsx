import { useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { 
  VideoIcon, 
  MicIcon, 
  ShieldCheckIcon, 
  AlertTriangleIcon,
  CheckCircleIcon,
  XCircleIcon 
} from "lucide-react";

interface PermissionDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onPermissionGranted: () => void;
  onPermissionDenied: () => void;
  permissionStatus?: "pending" | "granted" | "denied" | "error";
  errorMessage?: string;
}

export default function PermissionDialog({
  isOpen,
  onClose,
  onPermissionGranted,
  onPermissionDenied,
  permissionStatus = "pending",
  errorMessage
}: PermissionDialogProps) {
  const [isRequesting, setIsRequesting] = useState(false);

  const handleRequestPermission = async () => {
    setIsRequesting(true);
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: {
          width: { ideal: 1280, max: 1920 },
          height: { ideal: 720, max: 1080 },
          frameRate: { ideal: 30, max: 30 }
        },
        audio: {
          echoCancellation: true,
          noiseSuppression: true,
          autoGainControl: true
        }
      });
      
      // Stop the stream immediately as this is just for permission
      stream.getTracks().forEach(track => track.stop());
      onPermissionGranted();
    } catch (error) {
      console.error('Permission request failed:', error);
      onPermissionDenied();
    } finally {
      setIsRequesting(false);
    }
  };

  const getStatusIcon = () => {
    switch (permissionStatus) {
      case "granted":
        return <CheckCircleIcon className="h-6 w-6 text-green-500" />;
      case "denied":
      case "error":
        return <XCircleIcon className="h-6 w-6 text-red-500" />;
      default:
        return <VideoIcon className="h-6 w-6 text-blue-500" />;
    }
  };

  const getStatusBadge = () => {
    switch (permissionStatus) {
      case "granted":
        return <Badge variant="default" className="bg-green-500">Разрешено</Badge>;
      case "denied":
        return <Badge variant="destructive">Отклонено</Badge>;
      case "error":
        return <Badge variant="destructive">Ошибка</Badge>;
      default:
        return <Badge variant="secondary">Ожидание</Badge>;
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-[500px]" data-testid="permission-dialog">
        <DialogHeader>
          <div className="flex items-center space-x-3">
            {getStatusIcon()}
            <div>
              <DialogTitle data-testid="dialog-title">
                Разрешение на видео-прокторинг
              </DialogTitle>
              {getStatusBadge()}
            </div>
          </div>
          <DialogDescription data-testid="dialog-description">
            Для проведения экзамена требуется доступ к камере и микрофону для видео-прокторинга.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {/* Requirements */}
          <div className="space-y-3">
            <h4 className="text-sm font-medium text-gray-900 dark:text-gray-100">
              Необходимые разрешения:
            </h4>
            <div className="space-y-2">
              <div className="flex items-center space-x-3 p-2 rounded-lg bg-gray-50 dark:bg-gray-800">
                <VideoIcon className="h-5 w-5 text-blue-500" />
                <div>
                  <p className="text-sm font-medium">Доступ к камере</p>
                  <p className="text-xs text-gray-600 dark:text-gray-400">
                    Для записи видео во время экзамена
                  </p>
                </div>
              </div>
              <div className="flex items-center space-x-3 p-2 rounded-lg bg-gray-50 dark:bg-gray-800">
                <MicIcon className="h-5 w-5 text-green-500" />
                <div>
                  <p className="text-sm font-medium">Доступ к микрофону</p>
                  <p className="text-xs text-gray-600 dark:text-gray-400">
                    Для записи аудио во время экзамена
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Privacy Notice */}
          <Alert>
            <ShieldCheckIcon className="h-4 w-4" />
            <AlertDescription className="text-sm">
              <strong>Политика конфиденциальности:</strong> Видео и аудио записи используются 
              исключительно для целей прокторинга экзамена. Данные хранятся в защищенном облачном 
              хранилище и удаляются после завершения процедуры оценки.
            </AlertDescription>
          </Alert>

          {/* Error Message */}
          {(permissionStatus === "denied" || permissionStatus === "error") && (
            <Alert variant="destructive">
              <AlertTriangleIcon className="h-4 w-4" />
              <AlertDescription data-testid="error-message">
                {errorMessage || "Не удалось получить доступ к камере и микрофону. Убедитесь, что разрешения предоставлены в настройках браузера."}
              </AlertDescription>
            </Alert>
          )}

          {permissionStatus === "denied" && (
            <div className="p-3 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg border border-yellow-200 dark:border-yellow-800">
              <h5 className="text-sm font-medium text-yellow-800 dark:text-yellow-200 mb-1">
                Как разрешить доступ:
              </h5>
              <ul className="text-sm text-yellow-700 dark:text-yellow-300 space-y-1">
                <li>• Нажмите на значок замка в адресной строке</li>
                <li>• Выберите "Разрешить" для камеры и микрофона</li>
                <li>• Обновите страницу</li>
              </ul>
            </div>
          )}
        </div>

        <DialogFooter>
          {permissionStatus === "pending" && (
            <>
              <Button 
                variant="outline" 
                onClick={onClose}
                data-testid="button-cancel"
              >
                Отмена
              </Button>
              <Button 
                onClick={handleRequestPermission}
                disabled={isRequesting}
                data-testid="button-grant-permission"
              >
                {isRequesting ? "Запрос разрешения..." : "Разрешить доступ"}
              </Button>
            </>
          )}
          
          {permissionStatus === "granted" && (
            <Button 
              onClick={onClose}
              data-testid="button-continue"
            >
              Продолжить
            </Button>
          )}
          
          {(permissionStatus === "denied" || permissionStatus === "error") && (
            <>
              <Button 
                variant="outline" 
                onClick={onClose}
                data-testid="button-cancel-exam"
              >
                Отменить экзамен
              </Button>
              <Button 
                onClick={handleRequestPermission}
                disabled={isRequesting}
                data-testid="button-retry-permission"
              >
                {isRequesting ? "Повторный запрос..." : "Попробовать снова"}
              </Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
