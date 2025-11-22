import { useState, useEffect } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { AlertTriangleIcon, CheckCircleIcon, CloudIcon, WifiOffIcon, VideoIcon } from "lucide-react";
import { cn } from "@/lib/utils";

interface RecordingStatusProps {
  isRecording: boolean;
  recordingDuration: number; // in milliseconds
  uploadProgress: {
    uploaded: number;
    total: number;
    pending: number;
    failed: number;
  };
  connectionStatus: "online" | "offline" | "reconnecting";
  onRetryUploads?: () => void;
  className?: string;
}

export default function RecordingStatus({
  isRecording,
  recordingDuration,
  uploadProgress,
  connectionStatus,
  onRetryUploads,
  className
}: RecordingStatusProps) {
  const [displayTime, setDisplayTime] = useState("00:00:00");

  useEffect(() => {
    const formatTime = (ms: number) => {
      const totalSeconds = Math.floor(ms / 1000);
      const hours = Math.floor(totalSeconds / 3600);
      const minutes = Math.floor((totalSeconds % 3600) / 60);
      const seconds = totalSeconds % 60;
      
      return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
    };

    setDisplayTime(formatTime(recordingDuration));
  }, [recordingDuration]);

  const uploadPercentage = uploadProgress.total > 0 
    ? Math.round((uploadProgress.uploaded / uploadProgress.total) * 100)
    : 0;

  const getConnectionIcon = () => {
    switch (connectionStatus) {
      case "online":
        return <CloudIcon className="h-4 w-4 text-green-500" />;
      case "offline":
        return <WifiOffIcon className="h-4 w-4 text-red-500" />;
      case "reconnecting":
        return <CloudIcon className="h-4 w-4 text-yellow-500 animate-pulse" />;
    }
  };

  const getConnectionText = () => {
    switch (connectionStatus) {
      case "online":
        return "Онлайн";
      case "offline":
        return "Оффлайн";
      case "reconnecting":
        return "Переподключение...";
    }
  };

  return (
    <Card className={cn("fixed bottom-4 right-4 z-40 w-80", className)} data-testid="recording-status">
      <CardContent className="p-4">
        {/* Recording Status Header */}
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center space-x-2">
            <div className={cn(
              "flex items-center space-x-1",
              isRecording && "animate-pulse"
            )}>
              <VideoIcon className={cn(
                "h-4 w-4",
                isRecording ? "text-red-500" : "text-gray-400"
              )} />
              <Badge 
                variant={isRecording ? "destructive" : "secondary"}
                data-testid="badge-recording-status"
              >
                {isRecording ? "ЗАПИСЬ" : "ОСТАНОВЛЕНО"}
              </Badge>
            </div>
          </div>
          
          <div className="flex items-center space-x-1 text-sm text-gray-600 dark:text-gray-400">
            {getConnectionIcon()}
            <span data-testid="text-connection-status">{getConnectionText()}</span>
          </div>
        </div>

        {/* Recording Timer */}
        <div className="text-center mb-4">
          <div className="text-2xl font-mono font-bold text-gray-900 dark:text-gray-100" data-testid="text-recording-timer">
            {displayTime}
          </div>
          <p className="text-xs text-gray-500">Время записи</p>
        </div>

        {/* Upload Progress */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-sm">
            <span className="text-gray-600 dark:text-gray-400">Загрузка сегментов:</span>
            <span className="font-medium" data-testid="text-upload-progress">
              {uploadProgress.uploaded}/{uploadProgress.total}
            </span>
          </div>
          
          <Progress 
            value={uploadPercentage} 
            className="h-2"
            data-testid="progress-upload"
          />
          
          <div className="flex items-center justify-between text-xs text-gray-500">
            <span>{uploadPercentage}% завершено</span>
            {uploadProgress.pending > 0 && (
              <span data-testid="text-pending-uploads">
                {uploadProgress.pending} в очереди
              </span>
            )}
          </div>
        </div>

        {/* Error Handling */}
        {uploadProgress.failed > 0 && (
          <div className="mt-3 p-2 bg-red-50 dark:bg-red-900/20 rounded-lg border border-red-200 dark:border-red-800">
            <div className="flex items-center space-x-2 text-red-700 dark:text-red-400">
              <AlertTriangleIcon className="h-4 w-4" />
              <span className="text-sm" data-testid="text-failed-uploads">
                {uploadProgress.failed} сегментов не загружены
              </span>
            </div>
            {onRetryUploads && connectionStatus === "online" && (
              <Button
                variant="outline"
                size="sm"
                onClick={onRetryUploads}
                className="mt-2 w-full text-red-700 border-red-200 hover:bg-red-50"
                data-testid="button-retry-uploads"
              >
                Повторить загрузку
              </Button>
            )}
          </div>
        )}

        {/* Success Message */}
        {uploadProgress.total > 0 && uploadProgress.uploaded === uploadProgress.total && uploadProgress.failed === 0 && (
          <div className="mt-3 p-2 bg-green-50 dark:bg-green-900/20 rounded-lg border border-green-200 dark:border-green-800">
            <div className="flex items-center space-x-2 text-green-700 dark:text-green-400">
              <CheckCircleIcon className="h-4 w-4" />
              <span className="text-sm" data-testid="text-upload-complete">
                Все сегменты успешно загружены
              </span>
            </div>
          </div>
        )}

        {/* Privacy Notice */}
        <div className="mt-3 text-xs text-gray-500 text-center">
          <p>
            Видео используется только для целей прокторинга экзамена
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
