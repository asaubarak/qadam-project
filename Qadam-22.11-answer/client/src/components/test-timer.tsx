import { useState, useEffect } from "react";
import { Card, CardContent } from "@/components/ui/card";

interface TestTimerProps {
  initialTime: number; // Time in seconds
  onTimeUp: () => void;
  onTick?: (timeLeft: number) => void;
}

export default function TestTimer({ initialTime, onTimeUp, onTick }: TestTimerProps) {
  const [timeLeft, setTimeLeft] = useState(initialTime);

  useEffect(() => {
    if (timeLeft <= 0) {
      onTimeUp();
      return;
    }

    const timer = setInterval(() => {
      setTimeLeft((prev) => {
        const newTime = prev - 1;
        onTick?.(newTime);
        return newTime;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [timeLeft, onTimeUp, onTick]);

  const formatTime = (seconds: number) => {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  };

  const getTimeColor = () => {
    const percentage = (timeLeft / initialTime) * 100;
    if (percentage > 50) return "text-accent";
    if (percentage > 20) return "text-yellow-600";
    return "text-destructive";
  };

  const getProgressColor = () => {
    const percentage = (timeLeft / initialTime) * 100;
    if (percentage > 50) return "bg-accent";
    if (percentage > 20) return "bg-yellow-500";
    return "bg-destructive";
  };

  return (
    <Card className="w-fit">
      <CardContent className="p-4">
        <div className="flex items-center space-x-3">
          <div className="h-10 w-10 rounded-full bg-primary/10 flex items-center justify-center">
            <i className="fas fa-clock text-primary"></i>
          </div>
          <div>
            <div className="text-sm text-muted-foreground">Осталось времени</div>
            <div className={`text-xl font-bold ${getTimeColor()}`} data-testid="timer-display">
              {formatTime(timeLeft)}
            </div>
          </div>
        </div>
        
        {/* Progress bar */}
        <div className="w-full bg-muted rounded-full h-2 mt-3">
          <div 
            className={`h-2 rounded-full transition-all duration-1000 ${getProgressColor()}`}
            style={{ width: `${(timeLeft / initialTime) * 100}%` }}
          ></div>
        </div>
        
        {/* Warning messages */}
        {timeLeft <= 300 && timeLeft > 60 && (
          <div className="flex items-center space-x-2 mt-2 text-yellow-600">
            <i className="fas fa-exclamation-triangle text-xs"></i>
            <span className="text-xs">Осталось менее 5 минут!</span>
          </div>
        )}
        
        {timeLeft <= 60 && (
          <div className="flex items-center space-x-2 mt-2 text-destructive">
            <i className="fas fa-exclamation-circle text-xs"></i>
            <span className="text-xs font-medium">Последняя минута!</span>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
