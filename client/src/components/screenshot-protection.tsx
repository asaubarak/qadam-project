import { useEffect, useState, useCallback, useRef } from 'react';
import { useToast } from '@/hooks/use-toast';
import AdvancedScreenshotProtection from '@/lib/advanced-screenshot-protection';

interface ScreenshotProtectionProps {
  children: React.ReactNode;
  enabled?: boolean;
  showWarnings?: boolean;
}

export default function ScreenshotProtection({ 
  children, 
  enabled = true, 
  showWarnings = true 
}: ScreenshotProtectionProps) {
  const { toast } = useToast();
  const [isBlurred, setIsBlurred] = useState(false);
  const [watermarkText, setWatermarkText] = useState('');
  const alertShown = useRef(false);
  const lastActivity = useRef(Date.now());
  const intervalRef = useRef<NodeJS.Timeout>();
  const advancedProtection = useRef<AdvancedScreenshotProtection>();

  // Генерируем уникальный watermark с информацией о пользователе
  useEffect(() => {
    if (!enabled) return;
    
    const user = localStorage.getItem('username') || 'Анонимный';
    const timestamp = new Date().toLocaleString('ru-RU');
    const sessionId = Math.random().toString(36).substring(2, 8);
    setWatermarkText(`${user} • ${timestamp} • ID: ${sessionId}`);

    // Initialize advanced protection
    advancedProtection.current = new AdvancedScreenshotProtection({
      onScreenshotAttempt: () => {
        setIsBlurred(true);
        toast({
          title: "Нарушение безопасности",
          description: "Попытка создания скриншота заблокирована",
          variant: "destructive",
          duration: 5000,
        });
        setTimeout(() => setIsBlurred(false), 3000);
      },
      onSuspiciousActivity: (activity) => {
        console.warn('Подозрительная активность:', activity);
        toast({
          title: "Предупреждение",
          description: `Обнаружена подозрительная активность: ${activity}`,
          variant: "destructive",
        });
      }
    });

    // Активируем защиту
    advancedProtection.current.activate();

    return () => {
      if (advancedProtection.current) {
        advancedProtection.current.destroy();
      }
    };
  }, [enabled, toast]);

  // Детекция попыток скриншотов через клавиши
  const handleKeyDown = useCallback((e: KeyboardEvent) => {
    if (!enabled) return;

    // Print Screen и его комбинации
    if (e.key === 'PrintScreen' || 
        (e.ctrlKey && e.key === 'p') ||
        (e.ctrlKey && e.shiftKey && e.key === 'S') ||
        (e.metaKey && e.shiftKey && (e.key === '3' || e.key === '4' || e.key === '5'))) {
      
      e.preventDefault();
      e.stopPropagation();
      
      if (showWarnings && !alertShown.current) {
        toast({
          title: "⚠️ Скриншоты запрещены",
          description: "Создание скриншотов во время тестирования недопустимо",
          variant: "destructive",
          duration: 5000,
        });
        alertShown.current = true;
        setTimeout(() => { alertShown.current = false; }, 3000);
      }
      
      // Временно размываем контент
      setIsBlurred(true);
      setTimeout(() => setIsBlurred(false), 2000);
      
      return false;
    }

    // F12, Ctrl+Shift+I (DevTools)
    if (e.key === 'F12' || 
        (e.ctrlKey && e.shiftKey && e.key === 'I') ||
        (e.ctrlKey && e.shiftKey && e.key === 'C') ||
        (e.ctrlKey && e.key === 'u')) {
      e.preventDefault();
      
      if (showWarnings) {
        toast({
          title: "🔒 Инструменты разработчика заблокированы",
          description: "Доступ к DevTools ограничен во время тестирования",
          variant: "destructive",
        });
      }
      return false;
    }

    lastActivity.current = Date.now();
  }, [enabled, showWarnings, toast]);

  // Детекция потери фокуса (переключение приложений)
  const handleVisibilityChange = useCallback(() => {
    if (!enabled) return;
    
    if (document.hidden) {
      setIsBlurred(true);
      if (showWarnings) {
        toast({
          title: "👀 Внимание!",
          description: "Обнаружено переключение между приложениями",
          variant: "destructive",
        });
      }
    } else {
      // Задержка перед снятием размытия
      setTimeout(() => setIsBlurred(false), 1000);
    }
  }, [enabled, showWarnings, toast]);

  // Детекция потери фокуса окна
  const handleWindowBlur = useCallback(() => {
    if (!enabled) return;
    setIsBlurred(true);
  }, [enabled]);

  const handleWindowFocus = useCallback(() => {
    if (!enabled) return;
    setTimeout(() => setIsBlurred(false), 500);
  }, [enabled]);

  // Блокировка правой кнопки мыши
  const handleContextMenu = useCallback((e: MouseEvent) => {
    if (!enabled) return;
    e.preventDefault();
    if (showWarnings) {
      toast({
        title: "🚫 Контекстное меню заблокировано",
        description: "Правая кнопка мыши недоступна во время тестирования",
        variant: "destructive",
      });
    }
    return false;
  }, [enabled, showWarnings, toast]);

  // Детекция инактивности (возможные попытки скриншотов)
  useEffect(() => {
    if (!enabled) return;

    intervalRef.current = setInterval(() => {
      const now = Date.now();
      const inactive = now - lastActivity.current;
      
      // Если более 30 секунд бездействия, показываем предупреждение
      if (inactive > 30000 && showWarnings) {
        setIsBlurred(true);
        toast({
          title: "⏱️ Длительное бездействие",
          description: "Обнаружена подозрительная активность. Нажмите любую клавишу для продолжения",
          variant: "destructive",
        });
      }
    }, 10000);

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, [enabled, showWarnings, toast]);

  // Регистрация обработчиков событий
  useEffect(() => {
    if (!enabled) return;

    document.addEventListener('keydown', handleKeyDown, true);
    document.addEventListener('contextmenu', handleContextMenu, true);
    document.addEventListener('visibilitychange', handleVisibilityChange);
    window.addEventListener('blur', handleWindowBlur);
    window.addEventListener('focus', handleWindowFocus);

    // Блокируем drag & drop
    const handleDragStart = (e: DragEvent) => e.preventDefault();
    document.addEventListener('dragstart', handleDragStart);

    // Блокируем выделение при тройном клике
    const handleSelectStart = (e: Event) => e.preventDefault();
    document.addEventListener('selectstart', handleSelectStart);

    return () => {
      document.removeEventListener('keydown', handleKeyDown, true);
      document.removeEventListener('contextmenu', handleContextMenu, true);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      window.removeEventListener('blur', handleWindowBlur);
      window.removeEventListener('focus', handleWindowFocus);
      document.removeEventListener('dragstart', handleDragStart);
      document.removeEventListener('selectstart', handleSelectStart);
    };
  }, [enabled, handleKeyDown, handleContextMenu, handleVisibilityChange, handleWindowBlur, handleWindowFocus]);

  if (!enabled) {
    return <>{children}</>;
  }

  return (
    <div className="relative min-h-screen">
      {/* Водяной знак */}
      <div className="fixed inset-0 pointer-events-none z-50 select-none">
        <div className="absolute inset-0 opacity-10">
          {Array.from({ length: 20 }, (_, i) => (
            <div
              key={i}
              className="absolute text-gray-500 text-sm font-mono transform -rotate-45 select-none"
              style={{
                left: `${(i % 4) * 25 + 10}%`,
                top: `${Math.floor(i / 4) * 20 + 10}%`,
              }}
            >
              {watermarkText}
            </div>
          ))}
        </div>
      </div>

      {/* Основной контент с защитой */}
      <div 
        className={`
          no-select no-drag content-protected
          ${isBlurred ? 'blur-lg brightness-50' : ''}
          transition-all duration-300
        `}
        onMouseMove={() => { lastActivity.current = Date.now(); }}
        onClick={() => { lastActivity.current = Date.now(); }}
      >
        {children}
      </div>

      {/* Оверлей при размытии */}
      {isBlurred && (
        <div className="fixed inset-0 bg-black/30 flex items-center justify-center z-40 backdrop-blur-sm">
          <div className="text-white text-center p-8">
            <div className="text-6xl mb-4">🔒</div>
            <h2 className="text-2xl font-bold mb-2">Контент временно скрыт</h2>
            <p className="text-lg opacity-80">Нажмите любую клавишу для продолжения</p>
          </div>
        </div>
      )}
    </div>
  );
}
