import { useEffect, useRef, useState } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { VideoIcon, VideoOffIcon, Volume2Icon, VolumeXIcon } from "lucide-react";
import { cn } from "@/lib/utils";

interface CameraPreviewProps {
  stream: MediaStream | null;
  isRecording: boolean;
  isMinimized?: boolean;
  onToggleMinimize?: () => void;
  className?: string;
}

export default function CameraPreview({
  stream,
  isRecording,
  isMinimized = false,
  onToggleMinimize,
  className
}: CameraPreviewProps) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const [isVideoEnabled, setIsVideoEnabled] = useState(true);
  const [isAudioEnabled, setIsAudioEnabled] = useState(true);

  useEffect(() => {
    if (videoRef.current && stream) {
      videoRef.current.srcObject = stream;
    }
  }, [stream]);

  const toggleVideo = () => {
    if (stream) {
      const videoTrack = stream.getVideoTracks()[0];
      if (videoTrack) {
        videoTrack.enabled = !videoTrack.enabled;
        setIsVideoEnabled(videoTrack.enabled);
      }
    }
  };

  const toggleAudio = () => {
    if (stream) {
      const audioTrack = stream.getAudioTracks()[0];
      if (audioTrack) {
        audioTrack.enabled = !audioTrack.enabled;
        setIsAudioEnabled(audioTrack.enabled);
      }
    }
  };

  if (isMinimized) {
    return (
      <Card 
        className={cn(
          "fixed top-4 right-4 z-50 w-16 h-16 cursor-pointer border-2",
          isRecording ? "border-red-500" : "border-gray-300",
          className
        )}
        onClick={onToggleMinimize}
        data-testid="camera-preview-minimized"
      >
        <div className="w-full h-full relative overflow-hidden rounded-lg">
          {stream ? (
            <video
              ref={videoRef}
              autoPlay
              muted
              playsInline
              className="w-full h-full object-cover"
            />
          ) : (
            <div className="w-full h-full bg-gray-800 flex items-center justify-center">
              <VideoOffIcon className="h-6 w-6 text-gray-400" />
            </div>
          )}
          {isRecording && (
            <div className="absolute top-1 left-1 w-2 h-2 bg-red-500 rounded-full animate-pulse" />
          )}
        </div>
      </Card>
    );
  }

  return (
    <Card 
      className={cn(
        "fixed top-4 right-4 z-50 w-80 bg-white dark:bg-gray-800 shadow-lg border-2",
        isRecording ? "border-red-500" : "border-gray-300",
        className
      )}
      data-testid="camera-preview-expanded"
    >
      <div className="p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100">
            Камера прокторинга
          </h3>
          {onToggleMinimize && (
            <Button
              variant="ghost"
              size="sm"
              onClick={onToggleMinimize}
              data-testid="button-minimize-camera"
            >
              _
            </Button>
          )}
        </div>
        
        <div className="relative rounded-lg overflow-hidden bg-gray-800 mb-3">
          {stream ? (
            <video
              ref={videoRef}
              autoPlay
              muted
              playsInline
              className="w-full h-48 object-cover"
              data-testid="camera-video-preview"
            />
          ) : (
            <div 
              className="w-full h-48 bg-gray-800 flex items-center justify-center"
              data-testid="camera-no-stream"
            >
              <VideoOffIcon className="h-12 w-12 text-gray-400" />
              <p className="text-gray-400 ml-2">Камера недоступна</p>
            </div>
          )}
          
          {isRecording && (
            <div className="absolute top-2 left-2 flex items-center space-x-1">
              <div className="w-3 h-3 bg-red-500 rounded-full animate-pulse" />
              <span className="text-white text-xs font-medium">REC</span>
            </div>
          )}
        </div>

        <div className="flex items-center justify-center space-x-2">
          <Button
            variant="outline"
            size="sm"
            onClick={toggleVideo}
            disabled={!stream}
            className={cn(
              "flex items-center space-x-1",
              !isVideoEnabled && "bg-red-50 border-red-200 hover:bg-red-100"
            )}
            data-testid="button-toggle-video"
          >
            {isVideoEnabled ? (
              <VideoIcon className="h-4 w-4" />
            ) : (
              <VideoOffIcon className="h-4 w-4 text-red-500" />
            )}
          </Button>
          
          <Button
            variant="outline"
            size="sm"
            onClick={toggleAudio}
            disabled={!stream}
            className={cn(
              "flex items-center space-x-1",
              !isAudioEnabled && "bg-red-50 border-red-200 hover:bg-red-100"
            )}
            data-testid="button-toggle-audio"
          >
            {isAudioEnabled ? (
              <Volume2Icon className="h-4 w-4" />
            ) : (
              <VolumeXIcon className="h-4 w-4 text-red-500" />
            )}
          </Button>
        </div>

        {isRecording && (
          <div className="mt-3 text-center">
            <p className="text-xs text-gray-600 dark:text-gray-400">
              Видео записывается в соответствии с требованиями прокторинга
            </p>
          </div>
        )}
      </div>
    </Card>
  );
}
