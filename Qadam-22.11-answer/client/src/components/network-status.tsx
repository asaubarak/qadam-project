import { useState, useEffect } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { 
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

interface NetworkStatusProps {
  className?: string;
  showDetails?: boolean;
}

export default function NetworkStatus({ className = "", showDetails = false }: NetworkStatusProps) {
  const [isOnline, setIsOnline] = useState(navigator.onLine);
  const [connectionType, setConnectionType] = useState<string>('unknown');
  const [syncStatus, setSyncStatus] = useState<'idle' | 'syncing' | 'error'>('idle');

  useEffect(() => {
    const updateOnlineStatus = () => {
      setIsOnline(navigator.onLine);
      
      // Get connection info if available
      const connection = (navigator as any).connection || 
                        (navigator as any).mozConnection || 
                        (navigator as any).webkitConnection;
      
      if (connection) {
        setConnectionType(connection.effectiveType || connection.type || 'unknown');
      }
    };

    const handleOnline = () => {
      updateOnlineStatus();
      // Trigger sync when coming online
      if ('serviceWorker' in navigator && navigator.serviceWorker.controller) {
        navigator.serviceWorker.controller.postMessage({ type: 'SYNC_REQUEST' });
        setSyncStatus('syncing');
        setTimeout(() => setSyncStatus('idle'), 3000); // Reset after 3s
      }
    };

    const handleOffline = () => {
      updateOnlineStatus();
      setSyncStatus('idle');
    };

    // Listen for online/offline events
    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    // Listen for connection changes
    const connection = (navigator as any).connection;
    if (connection) {
      connection.addEventListener('change', updateOnlineStatus);
    }

    // Listen for sync status updates from service worker
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.addEventListener('message', (event) => {
        if (event.data?.type === 'SYNC_STATUS') {
          setSyncStatus(event.data.status);
        }
      });
    }

    // Initial update
    updateOnlineStatus();

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
      if (connection) {
        connection.removeEventListener('change', updateOnlineStatus);
      }
    };
  }, []);

  const getStatusInfo = () => {
    if (!isOnline) {
      return {
        variant: 'destructive' as const,
        icon: 'fas fa-wifi-slash',
        text: 'Офлайн',
        description: 'Нет подключения к интернету'
      };
    }

    if (syncStatus === 'syncing') {
      return {
        variant: 'secondary' as const,
        icon: 'fas fa-sync fa-spin',
        text: 'Синхронизация',
        description: 'Синхронизация данных...'
      };
    }

    if (syncStatus === 'error') {
      return {
        variant: 'destructive' as const,
        icon: 'fas fa-exclamation-triangle',
        text: 'Ошибка синхронизации',
        description: 'Не удалось синхронизировать данные'
      };
    }

    return {
      variant: 'default' as const,
      icon: 'fas fa-wifi',
      text: 'Онлайн',
      description: `Подключение: ${connectionType}`
    };
  };

  const statusInfo = getStatusInfo();

  const forceSyncHandler = () => {
    if (isOnline && 'serviceWorker' in navigator && navigator.serviceWorker.controller) {
      navigator.serviceWorker.controller.postMessage({ type: 'FORCE_SYNC' });
      setSyncStatus('syncing');
      setTimeout(() => setSyncStatus('idle'), 5000);
    }
  };

  const CompactIndicator = () => (
    <Tooltip>
      <TooltipTrigger asChild>
        <Badge 
          variant={statusInfo.variant} 
          className={`cursor-help transition-all duration-200 ${className}`}
          data-testid="network-status-indicator"
        >
          <i className={`${statusInfo.icon} text-xs`}></i>
          {showDetails && (
            <span className="ml-1 text-xs">
              {statusInfo.text}
            </span>
          )}
        </Badge>
      </TooltipTrigger>
      <TooltipContent>
        <div className="text-sm">
          <div className="font-medium">{statusInfo.text}</div>
          <div className="text-muted-foreground">{statusInfo.description}</div>
          {syncStatus === 'error' && (
            <Button 
              size="sm" 
              variant="outline" 
              className="mt-2"
              onClick={forceSyncHandler}
              data-testid="button-force-sync"
            >
              <i className="fas fa-sync mr-1"></i>
              Повторить синхронизацию
            </Button>
          )}
        </div>
      </TooltipContent>
    </Tooltip>
  );

  const DetailedIndicator = () => (
    <div className={`flex items-center space-x-2 ${className}`}>
      <Badge variant={statusInfo.variant} data-testid="network-status-detailed">
        <i className={`${statusInfo.icon} mr-1`}></i>
        {statusInfo.text}
      </Badge>
      
      {connectionType !== 'unknown' && isOnline && (
        <span className="text-xs text-muted-foreground">
          {connectionType.toUpperCase()}
        </span>
      )}
      
      {syncStatus === 'error' && (
        <Button 
          size="sm" 
          variant="outline"
          onClick={forceSyncHandler}
          data-testid="button-retry-sync"
        >
          <i className="fas fa-sync mr-1"></i>
          Повторить
        </Button>
      )}
    </div>
  );

  return showDetails ? <DetailedIndicator /> : <CompactIndicator />;
}
