import { useEffect } from 'react';

const ScreenshotProtection = () => {
  useEffect(() => {
    // ЗАЩИТА ПОЛНОСТЬЮ ОТКЛЮЧЕНА для отладки
    console.log('Screenshot protection is DISABLED');
    return;
    // Блокируем контекстное меню
    const handleContextMenu = (e: Event) => {
      e.preventDefault();
      return false;
    };

    // Блокируем горячие клавиши для скриншотов
    const handleKeyDown = (e: KeyboardEvent) => {
      // Блокируем Print Screen
      if (e.key === 'PrintScreen') {
        e.preventDefault();
        return false;
      }
      
      // Блокируем Ctrl+Shift+S (Chrome screenshot)
      if (e.ctrlKey && e.shiftKey && e.key === 'S') {
        e.preventDefault();
        return false;
      }
      
      // Блокируем F12 (DevTools)
      if (e.key === 'F12') {
        e.preventDefault();
        return false;
      }
      
      // Блокируем Ctrl+Shift+I (DevTools)
      if (e.ctrlKey && e.shiftKey && e.key === 'I') {
        e.preventDefault();
        return false;
      }
      
      // Блокируем Ctrl+U (View Source)
      if (e.ctrlKey && e.key === 'u') {
        e.preventDefault();
        return false;
      }
      
      // Блокируем Ctrl+S (Save page)
      if (e.ctrlKey && e.key === 's') {
        e.preventDefault();
        return false;
      }
    };

    // Добавляем обработчики
    document.addEventListener('contextmenu', handleContextMenu);
    document.addEventListener('keydown', handleKeyDown);
    
    // Отключаем drag & drop
    document.addEventListener('dragstart', (e) => e.preventDefault());
    document.addEventListener('drop', (e) => e.preventDefault());
    
    // Отключаем выделение текста
    document.addEventListener('selectstart', (e) => e.preventDefault());
    
    // Блокируем копирование
    document.addEventListener('copy', (e) => e.preventDefault());
    
  }, []); // Защита отключена

  return null; // Компонент не рендерит ничего видимого
};

export default ScreenshotProtection;
