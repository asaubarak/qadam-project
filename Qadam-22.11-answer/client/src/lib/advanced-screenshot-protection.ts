/**
 * Продвинутая защита от скриншотов
 * Дополнительный уровень защиты для предотвращения копирования контента
 */

interface ProtectionCallbacks {
  onScreenshotAttempt?: () => void;
  onSuspiciousActivity?: (activity: string) => void;
}

class AdvancedScreenshotProtection {
  private isProtectionActive = false;
  private observers: MutationObserver[] = [];
  private intervals: NodeJS.Timeout[] = [];
  private callbacks: ProtectionCallbacks;

  constructor(callbacks: ProtectionCallbacks = {}) {
    this.callbacks = callbacks;
    this.setupAdvancedProtection();
  }

  public activate() {
    this.isProtectionActive = true;
    this.startProtection();
  }

  public deactivate() {
    this.isProtectionActive = false;
    this.stopProtection();
  }

  private setupAdvancedProtection() {
    // Защита от отладки через DevTools
    this.setupDevToolsDetection();
    
    // Защита от автоматических скриншотов
    this.setupAutomatedScreenshotDetection();
    
    // Защита от расширений браузера
    this.setupBrowserExtensionDetection();
    
    // Мониторинг подозрительной активности
    this.setupSuspiciousActivityDetection();
  }

  private setupDevToolsDetection() {
    // Детекция открытия DevTools через размеры окна
    let devtools = { open: false };
    
    const threshold = 160;
    
    const checkDevTools = () => {
      if (window.outerHeight - window.innerHeight > threshold || 
          window.outerWidth - window.innerWidth > threshold) {
        if (!devtools.open) {
          devtools.open = true;
          this.triggerProtection('DevTools обнаружены');
        }
      } else {
        devtools.open = false;
      }
    };

    if (this.isProtectionActive) {
      const interval = setInterval(checkDevTools, 500);
      this.intervals.push(interval);
    }

    // Защита от console
    const originalConsole = console;
    const protectionScope = this;
    ['log', 'warn', 'error', 'info', 'debug'].forEach(method => {
      (console as any)[method] = function(...args: any[]) {
        protectionScope.triggerProtection(`Попытка доступа к console.${method}`);
        return originalConsole[method as keyof Console];
      };
    });
  }

  private setupAutomatedScreenshotDetection() {
    // Детекция API для скриншотов
    if (navigator.mediaDevices && navigator.mediaDevices.getDisplayMedia) {
      const originalGetDisplayMedia = navigator.mediaDevices.getDisplayMedia;
      navigator.mediaDevices.getDisplayMedia = () => {
        this.triggerProtection('Попытка захвата экрана через API');
        return Promise.reject(new Error('Screen capture blocked'));
      };
    }

    // Блокировка Canvas API (часто используется для скриншотов)
    const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function() {
      this.dispatchEvent(new Event('screenshot-attempt'));
      return 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==';
    };
  }

  private setupBrowserExtensionDetection() {
    // Детекция попыток доступа к DOM через расширения
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.type === 'childList') {
          mutation.addedNodes.forEach((node) => {
            if (node.nodeType === Node.ELEMENT_NODE) {
              const element = node as Element;
              
              // Проверяем на подозрительные классы/ID от расширений
              if (element.id && (
                element.id.includes('screenshot') ||
                element.id.includes('capture') ||
                element.id.includes('extension')
              )) {
                this.triggerProtection('Обнаружено подозрительное расширение');
              }
            }
          });
        }
      });
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true
    });

    this.observers.push(observer);
  }

  private setupSuspiciousActivityDetection() {
    let suspiciousActivityCount = 0;
    
    // Детекция быстрых клавишных комбинаций
    document.addEventListener('keydown', (e) => {
      const suspiciousKeys = [
        'PrintScreen', 'F12', 'F1', 'F2', 'F3', 'F4', 'F5', 'F6', 'F7', 'F8', 'F9', 'F10', 'F11'
      ];
      
      if (suspiciousKeys.includes(e.key) || 
          (e.ctrlKey && (e.key === 'i' || e.key === 'u' || e.key === 's' || e.key === 'p'))) {
        suspiciousActivityCount++;
        
        if (suspiciousActivityCount > 3) {
          this.triggerProtection('Множественные подозрительные нажатия клавиш');
        }
      }
    });

    // Сброс счетчика через время
    if (this.isProtectionActive) {
      const interval = setInterval(() => {
        suspiciousActivityCount = Math.max(0, suspiciousActivityCount - 1);
      }, 10000);
      this.intervals.push(interval);
    }
  }

  private triggerProtection(reason: string) {
    console.warn('🚫 Защита активирована:', reason);
    
    // Вызываем callback для попытки скриншота
    if (this.callbacks.onScreenshotAttempt) {
      this.callbacks.onScreenshotAttempt();
    }
    
    // Вызываем callback для подозрительной активности
    if (this.callbacks.onSuspiciousActivity) {
      this.callbacks.onSuspiciousActivity(reason);
    }
    
    // Размываем контент как дополнительная защита
    document.body.style.filter = 'blur(5px)';
    document.body.style.transition = 'filter 0.3s ease';
    
    // Показываем предупреждение
    this.showWarning(reason);
    
    // Восстанавливаем контент через некоторое время
    setTimeout(() => {
      document.body.style.filter = 'none';
    }, 3000);

    // Отправляем событие в приложение
    window.dispatchEvent(new CustomEvent('screenshot-protection-triggered', {
      detail: { reason }
    }));
  }

  private showWarning(reason: string) {
    const overlay = document.createElement('div');
    overlay.className = 'screenshot-warning-overlay';
    overlay.innerHTML = `
      <div style="
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.9);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 99999;
        color: white;
        text-align: center;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      ">
        <div>
          <div style="font-size: 4rem; margin-bottom: 1rem;">🚫</div>
          <h2 style="font-size: 1.5rem; margin-bottom: 1rem;">Нарушение безопасности обнаружено</h2>
          <p style="font-size: 1rem; opacity: 0.8;">${reason}</p>
          <p style="font-size: 0.9rem; margin-top: 1rem; opacity: 0.6;">Контент будет восстановлен через несколько секунд</p>
        </div>
      </div>
    `;
    
    document.body.appendChild(overlay);
    
    setTimeout(() => {
      if (overlay.parentNode) {
        overlay.parentNode.removeChild(overlay);
      }
    }, 3000);
  }

  private startProtection() {
    // Дополнительные проверки при активации
    this.setupDevToolsDetection();
    
    // Блокировка правой кнопки мыши на уровне window
    window.addEventListener('contextmenu', this.blockContextMenu);
    
    // Блокировка Drag & Drop
    window.addEventListener('dragstart', this.blockDragStart);
    
    // Блокировка выделения
    window.addEventListener('selectstart', this.blockSelect);
  }

  private stopProtection() {
    // Очищаем все интервалы
    this.intervals.forEach(interval => clearInterval(interval));
    this.intervals = [];
    
    // Отключаем наблюдателей
    this.observers.forEach(observer => observer.disconnect());
    this.observers = [];
    
    // Убираем слушатели событий
    window.removeEventListener('contextmenu', this.blockContextMenu);
    window.removeEventListener('dragstart', this.blockDragStart);
    window.removeEventListener('selectstart', this.blockSelect);
  }

  private blockContextMenu = (e: Event) => {
    e.preventDefault();
    this.triggerProtection('Попытка вызова контекстного меню');
    return false;
  };

  private blockDragStart = (e: Event) => {
    e.preventDefault();
    return false;
  };

  private blockSelect = (e: Event) => {
    e.preventDefault();
    return false;
  };

  public destroy() {
    // Останавливаем все интервалы
    this.intervals.forEach(interval => clearInterval(interval));
    this.intervals = [];
    
    // Отключаем все наблюдатели
    this.observers.forEach(observer => observer.disconnect());
    this.observers = [];
    
    // Деактивируем защиту
    this.deactivate();
    
    // Очищаем стили
    document.body.style.filter = 'none';
  }
}

// Создаем глобальный экземпляр
(window as any).screenshotProtection = new AdvancedScreenshotProtection();

export default AdvancedScreenshotProtection;
