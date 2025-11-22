// Системный монитор для детекции программ создания скриншотов
export class SystemScreenshotMonitor {
  private active = false;
  private suspicionLevel = 0;
  private callbacks: {
    onSuspiciousActivity: (reason: string, level: number) => void;
    onHighRisk: () => void;
  };

  constructor(callbacks: {
    onSuspiciousActivity: (reason: string, level: number) => void;
    onHighRisk: () => void;
  }) {
    this.callbacks = callbacks;
  }

  activate() {
    if (this.active) return;
    this.active = true;

    // 1. Мониторинг фокуса окна (переключение на программы скриншотов)
    this.monitorWindowFocus();
    
    // 2. Детекция изменений в буфере обмена
    this.monitorClipboard();
    
    // 3. Мониторинг активности мыши (движение к системным кнопкам)
    this.monitorMouseActivity();
    
    // 4. Детекция временных файлов скриншотов
    this.monitorTemporaryFiles();
    
    // 5. Проверка запущенных процессов (через косвенные признаки)
    this.monitorSystemProcesses();

    console.log('🔒 Системный монитор скриншотов активирован');
  }

  private monitorWindowFocus() {
    let focusLostTime: number | null = null;
    let rapidSwitches = 0;

    const handleVisibilityChange = () => {
      const now = Date.now();

      if (document.hidden) {
        focusLostTime = now;
        this.suspicionLevel += 1;
        
        // Проверяем заголовок документа (некоторые программы меняют его)
        if (document.title !== document.title) {
          this.reportSuspiciousActivity('Изменение заголовка документа', 3);
        }
      } else {
        if (focusLostTime) {
          const timeAway = now - focusLostTime;
          
          // Быстрое переключение (менее 2 секунд) - подозрительно
          if (timeAway < 2000) {
            rapidSwitches++;
            this.suspicionLevel += 2;
            
            if (rapidSwitches > 3) {
              this.reportSuspiciousActivity('Множественные быстрые переключения', 5);
              rapidSwitches = 0;
            }
          }
          
          focusLostTime = null;
        }
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    window.addEventListener('focus', handleVisibilityChange);
    window.addEventListener('blur', handleVisibilityChange);
  }

  private monitorClipboard() {
    // Детекция попыток чтения/записи буфера обмена
    let lastClipboardLength = 0;

    const checkClipboard = async () => {
      try {
        if (navigator.clipboard && navigator.clipboard.readText) {
          const text = await navigator.clipboard.readText();
          
          if (text.length !== lastClipboardLength) {
            // Новое содержимое в буфере - возможно скриншот
            if (text.length === 0 && lastClipboardLength > 0) {
              this.reportSuspiciousActivity('Очистка буфера обмена', 2);
            }
            lastClipboardLength = text.length;
          }
        }
      } catch (e) {
        // Ошибка доступа к буферу может означать попытку его использования
        this.suspicionLevel += 1;
      }
    };

    // Проверяем буфер каждые 5 секунд
    setInterval(checkClipboard, 5000);

    // Мониторим события копирования/вставки
    document.addEventListener('copy', () => {
      this.reportSuspiciousActivity('Команда копирования', 1);
    });

    document.addEventListener('paste', () => {
      this.suspicionLevel += 0.5;
    });
  }

  private monitorMouseActivity() {
    let edgeMovements = 0;
    let cornerTime = 0;

    const handleMouseMove = (e: MouseEvent) => {
      const { clientX, clientY } = e;
      const { innerWidth, innerHeight } = window;
      
      // Проверяем движение к краям экрана (где обычно кнопки скриншота)
      const nearEdge = clientX < 100 || clientX > innerWidth - 100 || 
                      clientY < 100 || clientY > innerHeight - 100;
      
      if (nearEdge) {
        edgeMovements++;
        
        // Движение к углам экрана особенно подозрительно
        const nearCorner = (clientX < 50 || clientX > innerWidth - 50) &&
                          (clientY < 50 || clientY > innerHeight - 50);
        
        if (nearCorner) {
          cornerTime = Date.now();
          this.suspicionLevel += 2;
          
          // Длительное нахождение в углу
          setTimeout(() => {
            if (Date.now() - cornerTime > 2000) {
              this.reportSuspiciousActivity('Длительное нахождение курсора в углу', 3);
            }
          }, 2000);
        }
      } else {
        edgeMovements = Math.max(0, edgeMovements - 0.1);
      }

      // Много движений к краям экрана
      if (edgeMovements > 10) {
        this.reportSuspiciousActivity('Множественные движения к краям экрана', 4);
        edgeMovements = 0;
      }
    };

    document.addEventListener('mousemove', handleMouseMove);
  }

  private monitorTemporaryFiles() {
    // Пытаемся детектировать создание временных файлов скриншотов
    // через изменения в LocalStorage/IndexedDB (косвенные признаки)
    
    let lastStorageSize = localStorage.length;
    
    const checkStorage = () => {
      const currentSize = localStorage.length;
      
      if (currentSize !== lastStorageSize) {
        // Проверяем, не добавились ли подозрительные ключи
        for (let i = 0; i < localStorage.length; i++) {
          const key = localStorage.key(i);
          if (key && (key.includes('screenshot') || key.includes('image') || 
                     key.includes('capture') || key.includes('snip'))) {
            this.reportSuspiciousActivity('Подозрительные данные в LocalStorage', 4);
            break;
          }
        }
        lastStorageSize = currentSize;
      }
    };

    setInterval(checkStorage, 3000);
  }

  private monitorSystemProcesses() {
    // Детекция через косвенные признаки активности программ скриншотов
    
    // Проверяем изменения в navigator объекте
    const originalNavigator = { ...navigator };
    
    const checkNavigatorChanges = () => {
      const currentKeys = Object.keys(navigator);
      const originalKeys = Object.keys(originalNavigator);
      
      if (currentKeys.length !== originalKeys.length) {
        this.reportSuspiciousActivity('Изменения в объекте navigator', 3);
      }
    };

    setInterval(checkNavigatorChanges, 10000);

    // Мониторим изменения в performance API
    let lastResourceCount = performance.getEntriesByType('resource').length;
    
    const checkPerformance = () => {
      const currentResourceCount = performance.getEntriesByType('resource').length;
      
      if (currentResourceCount > lastResourceCount + 5) {
        this.reportSuspiciousActivity('Подозрительная сетевая активность', 2);
      }
      
      lastResourceCount = currentResourceCount;
    };

    setInterval(checkPerformance, 5000);

    // Детекция через WebRTC (некоторые программы используют его)
    if (window.RTCPeerConnection) {
      const originalRTC = window.RTCPeerConnection;
      
      window.RTCPeerConnection = function(...args: any[]) {
        // Если кто-то пытается создать RTC соединение - подозрительно
        this.reportSuspiciousActivity('Попытка создания RTC соединения', 4);
        return new originalRTC(...args);
      }.bind(this);
    }
  }

  private reportSuspiciousActivity(reason: string, severity: number) {
    this.suspicionLevel += severity;
    
    console.warn(`🚨 Подозрительная активность: ${reason}, уровень: ${this.suspicionLevel}`);
    
    this.callbacks.onSuspiciousActivity(reason, this.suspicionLevel);
    
    // Критический уровень подозрения
    if (this.suspicionLevel > 15) {
      this.callbacks.onHighRisk();
      
      // Сброс после критического уровня
      setTimeout(() => {
        this.suspicionLevel = Math.max(5, this.suspicionLevel - 10);
      }, 30000);
    }

    // Постепенное снижение уровня подозрения
    setTimeout(() => {
      this.suspicionLevel = Math.max(0, this.suspicionLevel - 1);
    }, 60000);
  }

  destroy() {
    this.active = false;
    console.log('🔓 Системный монитор скриншотов деактивирован');
  }
}
