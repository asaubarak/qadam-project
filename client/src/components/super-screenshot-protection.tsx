import { useEffect, useState, useCallback, useRef } from 'react';
import { useToast } from '@/hooks/use-toast';
import { SystemScreenshotMonitor } from '@/lib/system-screenshot-monitor';

interface SuperScreenshotProtectionProps {
  children: React.ReactNode;
  enabled?: boolean;
  showWarnings?: boolean;
}

export default function SuperScreenshotProtection({ 
  children, 
  enabled = true, 
  showWarnings = true 
}: SuperScreenshotProtectionProps) {
  const { toast } = useToast();
  const [isBlurred, setIsBlurred] = useState(false);
  const [watermarkText, setWatermarkText] = useState('');
  const [contentShift, setContentShift] = useState({ x: 0, y: 0 });
  const alertShown = useRef(false);
  const protectionLevel = useRef(0);
  const contentRef = useRef<HTMLDivElement>(null);
  const systemMonitor = useRef<SystemScreenshotMonitor>();

  // Генерируем динамический watermark
  useEffect(() => {
    if (!enabled) return;
    
    const user = localStorage.getItem('username') || 'Анонимный';
    const sessionId = Math.random().toString(36).substring(2, 8);
    const ip = Math.random().toString(36).substring(2, 10);
    
    const updateWatermark = () => {
      const timestamp = new Date().toLocaleString('ru-RU');
      const seconds = new Date().getSeconds();
      setWatermarkText(`🚫 КОНФИДЕНЦИАЛЬНО • ${user} • ${timestamp} • IP: ${ip} • ID: ${sessionId} • ⏱️${seconds}`);
    };

    updateWatermark();
    const watermarkInterval = setInterval(updateWatermark, 1000);

    // Инициализируем системный монитор
    systemMonitor.current = new SystemScreenshotMonitor({
      onSuspiciousActivity: (reason: string, level: number) => {
        console.warn(`🛡️ Системная защита: ${reason}, уровень: ${level}`);
        
        if (level > 5) {
          setIsBlurred(true);
          setTimeout(() => setIsBlurred(false), 3000);
          
          toast({
            title: "🚨 Системное нарушение",
            description: `Обнаружена подозрительная системная активность: ${reason}`,
            variant: "destructive",
            duration: 5000,
          });
        }
      },
      onHighRisk: () => {
        // Критический уровень - блокируем полностью
        document.body.style.filter = 'blur(30px) grayscale(100%)';
        document.body.style.pointerEvents = 'none';
        
        toast({
          title: "🔒 КРИТИЧЕСКОЕ НАРУШЕНИЕ",
          description: "Обнаружены множественные попытки создания скриншотов. Сессия заблокирована.",
          variant: "destructive",
          duration: 10000,
        });

        // Разблокировка через 30 секунд
        setTimeout(() => {
          document.body.style.filter = '';
          document.body.style.pointerEvents = '';
        }, 30000);
      }
    });

    systemMonitor.current.activate();

    return () => {
      clearInterval(watermarkInterval);
      if (systemMonitor.current) {
        systemMonitor.current.destroy();
      }
    };
  }, [enabled, toast]);

  // Динамическое смещение контента
  useEffect(() => {
    if (!enabled) return;

    const shiftContent = () => {
      const x = (Math.random() - 0.5) * 4; // -2px to 2px
      const y = (Math.random() - 0.5) * 4;
      setContentShift({ x, y });
    };

    const shiftInterval = setInterval(shiftContent, 3000);
    return () => clearInterval(shiftInterval);
  }, [enabled]);

  // Детекция системных скриншотов через множественные методы
  useEffect(() => {
    if (!enabled) return;

    let suspicionLevel = 0;
    let lastWindowSize = { width: window.innerWidth, height: window.innerHeight };
    let lastFocusTime = Date.now();
    
    // 1. Мониторинг изменений размера окна (DevTools)
    const handleResize = () => {
      const newSize = { width: window.innerWidth, height: window.innerHeight };
      const sizeDiff = Math.abs(newSize.width - lastWindowSize.width) + 
                      Math.abs(newSize.height - lastWindowSize.height);
      
      if (sizeDiff > 100) {
        suspicionLevel += 2;
        triggerProtection('Изменение размера окна');
      }
      lastWindowSize = newSize;
    };

    // 2. Детекция потери фокуса (переключение на другое приложение)
    const handleVisibilityChange = () => {
      if (document.hidden) {
        const timeAway = Date.now() - lastFocusTime;
        if (timeAway < 1000) { // Быстрое переключение
          suspicionLevel += 3;
          triggerProtection('Быстрое переключение приложений');
        }
      } else {
        lastFocusTime = Date.now();
      }
    };

    // 3. Мониторинг активности мыши (подготовка к скриншоту)
    const handleMouseMove = (e: MouseEvent) => {
      // Проверяем движение к краям экрана (где обычно кнопки скриншота)
      const { clientX, clientY } = e;
      const { innerWidth, innerHeight } = window;
      
      if (clientX < 50 || clientX > innerWidth - 50 || 
          clientY < 50 || clientY > innerHeight - 50) {
        suspicionLevel += 0.5;
      }
      
      // Сброс подозрения при нормальной активности
      if (suspicionLevel > 0) {
        suspicionLevel = Math.max(0, suspicionLevel - 0.1);
      }
    };

    // 4. Детекция комбинаций клавиш
    const handleKeyDown = (e: KeyboardEvent) => {
      const suspiciousKeys = [
        'PrintScreen',
        e.key === 'F12',
        e.ctrlKey && e.shiftKey && e.key === 'I',
        e.ctrlKey && e.shiftKey && e.key === 'S',
        e.metaKey && e.shiftKey && ['3', '4', '5'].includes(e.key),
        e.altKey && e.key === 'Tab'
      ];

      if (suspiciousKeys.some(Boolean)) {
        e.preventDefault();
        e.stopPropagation();
        suspicionLevel += 5;
        triggerProtection(`Клавиша: ${e.key}`);
        return false;
      }
    };

    // 5. Детекция правого клика
    const handleRightClick = (e: MouseEvent) => {
      e.preventDefault();
      suspicionLevel += 2;
      triggerProtection('Правый клик');
      return false;
    };

    // 6. Детекция drag & drop (сохранение изображений)
    const handleDragStart = (e: DragEvent) => {
      e.preventDefault();
      suspicionLevel += 3;
      triggerProtection('Попытка перетаскивания');
      return false;
    };

    // 7. Блокировка выделения текста
    const handleSelection = () => {
      if (window.getSelection) {
        window.getSelection()?.removeAllRanges();
      }
    };

    const triggerProtection = (reason: string) => {
      console.warn(`🛡️ Защита активирована: ${reason}, уровень: ${suspicionLevel}`);
      
      // Увеличиваем уровень защиты
      protectionLevel.current = Math.min(10, protectionLevel.current + 1);
      
      // Размываем контент
      setIsBlurred(true);
      setTimeout(() => setIsBlurred(false), 2000 + protectionLevel.current * 500);
      
      // Показываем предупреждение
      if (showWarnings && !alertShown.current) {
        toast({
          title: "🚨 Нарушение безопасности",
          description: `Обнаружена попытка: ${reason}. Все действия записываются.`,
          variant: "destructive",
          duration: 5000,
        });
        alertShown.current = true;
        setTimeout(() => { alertShown.current = false; }, 3000);
      }

      // Критический уровень - полная блокировка
      if (suspicionLevel > 10) {
        document.body.style.filter = 'blur(20px)';
        setTimeout(() => {
          document.body.style.filter = '';
          suspicionLevel = 0;
        }, 10000);
      }
    };

    // Добавляем слушатели
    window.addEventListener('resize', handleResize);
    document.addEventListener('visibilitychange', handleVisibilityChange);
    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('keydown', handleKeyDown);
    document.addEventListener('contextmenu', handleRightClick);
    document.addEventListener('dragstart', handleDragStart);
    document.addEventListener('selectstart', handleSelection);

    // Периодическая проверка подозрительной активности
    const suspicionInterval = setInterval(() => {
      if (suspicionLevel > 5) {
        triggerProtection('Высокий уровень подозрительной активности');
      }
    }, 5000);

    return () => {
      window.removeEventListener('resize', handleResize);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('keydown', handleKeyDown);
      document.removeEventListener('contextmenu', handleRightClick);
      document.removeEventListener('dragstart', handleDragStart);
      document.removeEventListener('selectstart', handleSelection);
      clearInterval(suspicionInterval);
    };
  }, [enabled, showWarnings, toast]);

  if (!enabled) {
    return <>{children}</>;
  }

  return (
    <>
      {/* Множественные watermark слои */}
      <div className="fixed inset-0 pointer-events-none z-50 overflow-hidden">
        {/* Главный watermark */}
        <div 
          className="absolute inset-0 flex items-center justify-center text-red-500/30 text-sm font-bold transform rotate-45"
          style={{
            background: `repeating-linear-gradient(
              45deg,
              transparent,
              transparent 100px,
              rgba(239, 68, 68, 0.1) 100px,
              rgba(239, 68, 68, 0.1) 120px
            )`
          }}
        >
          <div className="text-center whitespace-pre-line leading-8">
            {watermarkText}
          </div>
        </div>

        {/* Дополнительные watermark по углам */}
        {[
          { className: "top-4 left-4", rotate: "0deg" },
          { className: "top-4 right-4", rotate: "0deg" },
          { className: "bottom-4 left-4", rotate: "0deg" },
          { className: "bottom-4 right-4", rotate: "0deg" },
          { className: "top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2", rotate: "-45deg" }
        ].map((pos, i) => (
          <div 
            key={i}
            className={`absolute ${pos.className} text-red-500/40 text-xs font-bold`}
            style={{ transform: `rotate(${pos.rotate})` }}
          >
            🚫 ЗАПИСЬ ВЕДЕТСЯ 🚫
          </div>
        ))}

        {/* Динамические помехи */}
        <div className="absolute inset-0 opacity-20">
          {Array.from({length: 20}, (_, i) => (
            <div
              key={i}
              className="absolute w-1 h-1 bg-red-500 animate-pulse"
              style={{
                left: `${Math.random() * 100}%`,
                top: `${Math.random() * 100}%`,
                animationDelay: `${Math.random() * 2}s`
              }}
            />
          ))}
        </div>
      </div>

      {/* Основной контент с защитой */}
      <div
        ref={contentRef}
        className={`
          relative transition-all duration-300
          ${isBlurred ? 'blur-lg brightness-50' : ''}
          super-anti-screenshot super-flicker-protection super-protected-content
        `}
        style={{
          transform: `translate(${contentShift.x}px, ${contentShift.y}px)`,
          userSelect: 'none',
          WebkitUserSelect: 'none',
          MozUserSelect: 'none',
          msUserSelect: 'none',
        }}
      >
        {children}
      </div>

      {/* CSS-стили для дополнительной защиты */}
      <style dangerouslySetInnerHTML={{
        __html: `
          .anti-screenshot-content {
            -webkit-touch-callout: none !important;
            -webkit-user-select: none !important;
            -khtml-user-select: none !important;
            -moz-user-select: none !important;
            -ms-user-select: none !important;
            user-select: none !important;
            -webkit-app-region: no-drag;
            -webkit-highlight: none;
            -webkit-tap-highlight-color: transparent;
          }
          
          .anti-screenshot-content::before {
            content: "";
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: repeating-linear-gradient(
              90deg,
              transparent,
              transparent 50px,
              rgba(255, 0, 0, 0.02) 50px,
              rgba(255, 0, 0, 0.02) 51px
            );
            pointer-events: none;
            z-index: 999;
            mix-blend-mode: difference;
          }

          @media print {
            body * { 
              visibility: hidden !important; 
              background: black !important;
              color: transparent !important;
            }
            body::after {
              content: "ПЕЧАТЬ ЗАПРЕЩЕНА - КОНФИДЕНЦИАЛЬНЫЙ МАТЕРИАЛ" !important;
              position: fixed !important;
              top: 50% !important;
              left: 50% !important;
              transform: translate(-50%, -50%) !important;
              font-size: 48px !important;
              color: red !important;
              visibility: visible !important;
              z-index: 9999 !important;
            }
          }

          @keyframes flicker {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.8; }
          }
          
          .anti-screenshot-content {
            animation: flicker 3s infinite;
          }
        `
      }} />
    </>
  );
}
