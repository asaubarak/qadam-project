import { useState, useEffect, useRef, memo } from "react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";

interface PeriodicTableProps {
  isOpen: boolean;
  onClose: () => void;
}

interface Element {
  symbol: string;
  name: string;
  atomicNumber: number;
  atomicMass: string;
  group?: number;
  period: number;
  category: string;
}

function PeriodicTable({ isOpen, onClose }: PeriodicTableProps) {
  // Инициализируем состояние напрямую без useEffect
  const [selectedElement, setSelectedElement] = useState<Element | null>(null);
  const onCloseRef = useRef(onClose);

  // Обновляем ref напрямую БЕЗ useEffect
  onCloseRef.current = onClose;

  // ОТЛАДКА: логируем каждый рендер
  // console.log('🧪 PeriodicTable render - isOpen:', isOpen);

  // Закрытие по ESC
  useEffect(() => {
    if (!isOpen) return;
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onCloseRef.current();
    };
    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [isOpen]);

  // Simplified periodic table data (first few periods)
  const elements: Element[] = [
    // Period 1
    { symbol: "H", name: "Водород", atomicNumber: 1, atomicMass: "1.008", group: 1, period: 1, category: "nonmetal" },
    { symbol: "He", name: "Гелий", atomicNumber: 2, atomicMass: "4.003", group: 18, period: 1, category: "noble-gas" },
    
    // Period 2
    { symbol: "Li", name: "Литий", atomicNumber: 3, atomicMass: "6.941", group: 1, period: 2, category: "alkali-metal" },
    { symbol: "Be", name: "Бериллий", atomicNumber: 4, atomicMass: "9.012", group: 2, period: 2, category: "alkaline-earth" },
    { symbol: "B", name: "Бор", atomicNumber: 5, atomicMass: "10.81", group: 13, period: 2, category: "metalloid" },
    { symbol: "C", name: "Углерод", atomicNumber: 6, atomicMass: "12.01", group: 14, period: 2, category: "nonmetal" },
    { symbol: "N", name: "Азот", atomicNumber: 7, atomicMass: "14.01", group: 15, period: 2, category: "nonmetal" },
    { symbol: "O", name: "Кислород", atomicNumber: 8, atomicMass: "16.00", group: 16, period: 2, category: "nonmetal" },
    { symbol: "F", name: "Фтор", atomicNumber: 9, atomicMass: "19.00", group: 17, period: 2, category: "halogen" },
    { symbol: "Ne", name: "Неон", atomicNumber: 10, atomicMass: "20.18", group: 18, period: 2, category: "noble-gas" },
    
    // Period 3
    { symbol: "Na", name: "Натрий", atomicNumber: 11, atomicMass: "22.99", group: 1, period: 3, category: "alkali-metal" },
    { symbol: "Mg", name: "Магний", atomicNumber: 12, atomicMass: "24.31", group: 2, period: 3, category: "alkaline-earth" },
    { symbol: "Al", name: "Алюминий", atomicNumber: 13, atomicMass: "26.98", group: 13, period: 3, category: "post-transition" },
    { symbol: "Si", name: "Кремний", atomicNumber: 14, atomicMass: "28.09", group: 14, period: 3, category: "metalloid" },
    { symbol: "P", name: "Фосфор", atomicNumber: 15, atomicMass: "30.97", group: 15, period: 3, category: "nonmetal" },
    { symbol: "S", name: "Сера", atomicNumber: 16, atomicMass: "32.07", group: 16, period: 3, category: "nonmetal" },
    { symbol: "Cl", name: "Хлор", atomicNumber: 17, atomicMass: "35.45", group: 17, period: 3, category: "halogen" },
    { symbol: "Ar", name: "Аргон", atomicNumber: 18, atomicMass: "39.95", group: 18, period: 3, category: "noble-gas" },
    
    // Period 4 (partial)
    { symbol: "K", name: "Калий", atomicNumber: 19, atomicMass: "39.10", group: 1, period: 4, category: "alkali-metal" },
    { symbol: "Ca", name: "Кальций", atomicNumber: 20, atomicMass: "40.08", group: 2, period: 4, category: "alkaline-earth" },
    { symbol: "Fe", name: "Железо", atomicNumber: 26, atomicMass: "55.85", period: 4, category: "transition-metal" },
    { symbol: "Cu", name: "Медь", atomicNumber: 29, atomicMass: "63.55", period: 4, category: "transition-metal" },
    { symbol: "Zn", name: "Цинк", atomicNumber: 30, atomicMass: "65.38", period: 4, category: "transition-metal" },
  ];

  const getCategoryColor = (category: string) => {
    const colors = {
      "alkali-metal": "bg-red-100 hover:bg-red-200 text-red-800 border-red-300",
      "alkaline-earth": "bg-orange-100 hover:bg-orange-200 text-orange-800 border-orange-300",
      "transition-metal": "bg-yellow-100 hover:bg-yellow-200 text-yellow-800 border-yellow-300",
      "post-transition": "bg-green-100 hover:bg-green-200 text-green-800 border-green-300",
      "metalloid": "bg-blue-50 hover:bg-blue-100 text-blue-500 border-blue-500",
      "nonmetal": "bg-purple-100 hover:bg-purple-200 text-purple-800 border-purple-300",
      "halogen": "bg-pink-100 hover:bg-pink-200 text-pink-800 border-pink-300",
      "noble-gas": "bg-gray-100 hover:bg-gray-200 text-gray-800 border-gray-300",
    };
    return colors[category as keyof typeof colors] || "bg-gray-100 hover:bg-gray-200 text-gray-800 border-gray-300";
  };

  const getCategoryName = (category: string) => {
    const names = {
      "alkali-metal": "Щелочные металлы",
      "alkaline-earth": "Щелочноземельные",
      "transition-metal": "Переходные металлы",
      "post-transition": "Постпереходные",
      "metalloid": "Металлоиды",
      "nonmetal": "Неметаллы",
      "halogen": "Галогены",
      "noble-gas": "Благородные газы",
    };
    return names[category as keyof typeof names] || category;
  };

  const getElementPosition = (element: Element) => {
    // Simplified grid positioning for demonstration
    const row = element.period;
    let col = element.group || 1;
    
    // Special positioning for transition metals
    if (element.category === "transition-metal" && !element.group) {
      if (element.atomicNumber === 26) col = 8; // Fe
      if (element.atomicNumber === 29) col = 11; // Cu
      if (element.atomicNumber === 30) col = 12; // Zn
    }
    
    return { row, col };
  };

  return (
    <Dialog open={isOpen} onOpenChange={(open) => !open && onCloseRef.current()}>
      <DialogContent className="max-w-7xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center space-x-2">
            <i className="fas fa-table text-primary"></i>
            <span>Периодическая таблица элементов</span>
          </DialogTitle>
        </DialogHeader>
        
        <div className="space-y-6">
          {/* Legend */}
          <div className="flex flex-wrap gap-2">
            {["alkali-metal", "alkaline-earth", "transition-metal", "nonmetal", "halogen", "noble-gas", "metalloid"].map((category) => (
              <div key={category} className="flex items-center space-x-2">
                <div className={`h-4 w-4 rounded ${getCategoryColor(category)}`}></div>
                <span className="text-xs text-muted-foreground">{getCategoryName(category)}</span>
              </div>
            ))}
          </div>
          
          {/* Periodic Table Grid */}
          <div className="grid grid-cols-18 gap-1 text-xs">
            {Array.from({ length: 4 * 18 }, (_, index) => {
              const row = Math.floor(index / 18) + 1;
              const col = (index % 18) + 1;
              
              const element = elements.find(el => {
                const pos = getElementPosition(el);
                return pos.row === row && pos.col === col;
              });
              
              if (!element) {
                return <div key={index} className="aspect-square"></div>;
              }
              
              return (
                <button
                  key={element.atomicNumber}
                  className={`aspect-square border p-1 rounded transition-colors cursor-pointer ${getCategoryColor(element.category)}`}
                  onClick={() => setSelectedElement(element)}
                  data-testid={`element-${element.symbol}`}
                >
                  <div className="flex flex-col items-center justify-center h-full">
                    <div className="text-[8px] font-bold">{element.atomicNumber}</div>
                    <div className="text-sm font-bold">{element.symbol}</div>
                  </div>
                </button>
              );
            })}
          </div>
          
          {/* Element Details */}
          {selectedElement && (
            <Card className="border-primary">
              <CardContent className="p-4">
                <div className="flex items-start justify-between">
                  <div className="space-y-2">
                    <div className="flex items-center space-x-3">
                      <div className={`h-16 w-16 rounded-lg border-2 flex items-center justify-center ${getCategoryColor(selectedElement.category)}`}>
                        <span className="text-2xl font-bold">{selectedElement.symbol}</span>
                      </div>
                      <div>
                        <h3 className="text-xl font-bold text-foreground">{selectedElement.name}</h3>
                        <p className="text-muted-foreground">{selectedElement.symbol}</p>
                        <Badge variant="outline">{getCategoryName(selectedElement.category)}</Badge>
                      </div>
                    </div>
                    
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-4">
                      <div>
                        <div className="text-sm text-muted-foreground">Атомный номер</div>
                        <div className="text-lg font-semibold text-foreground">{selectedElement.atomicNumber}</div>
                      </div>
                      <div>
                        <div className="text-sm text-muted-foreground">Атомная масса</div>
                        <div className="text-lg font-semibold text-foreground">{selectedElement.atomicMass}</div>
                      </div>
                      <div>
                        <div className="text-sm text-muted-foreground">Период</div>
                        <div className="text-lg font-semibold text-foreground">{selectedElement.period}</div>
                      </div>
                      {selectedElement.group && (
                        <div>
                          <div className="text-sm text-muted-foreground">Группа</div>
                          <div className="text-lg font-semibold text-foreground">{selectedElement.group}</div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
          
          {!selectedElement && (
            <div className="text-center text-muted-foreground py-8">
              <i className="fas fa-mouse-pointer text-2xl mb-2"></i>
              <p>Нажмите на элемент, чтобы увидеть подробную информацию</p>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

export default memo(PeriodicTable);
