import { useState, useEffect, useRef, memo } from "react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";

interface CalculatorProps {
  isOpen: boolean;
  onClose: () => void;
}

function Calculator({ isOpen, onClose }: CalculatorProps) {
  // Инициализируем состояние напрямую без useEffect
  const [display, setDisplay] = useState("0");
  const [previousValue, setPreviousValue] = useState<number | null>(null);
  const [operation, setOperation] = useState<string | null>(null);
  const [waitingForNewValue, setWaitingForNewValue] = useState(false);
  const onCloseRef = useRef(onClose);

  // Обновляем ref напрямую БЕЗ useEffect
  onCloseRef.current = onClose;

  // ОТЛАДКА: логируем каждый рендер
  // console.log('🧮 Calculator render - isOpen:', isOpen);

  // Закрытие по ESC
  useEffect(() => {
    if (!isOpen) return;
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onCloseRef.current();
    };
    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [isOpen]);

  // Предотвращаем всплытие события клика на модальном окне
  const handleModalClick = (e: React.MouseEvent) => {
    e.stopPropagation();
  };

  const inputNumber = (num: string) => {
    if (waitingForNewValue) {
      setDisplay(num);
      setWaitingForNewValue(false);
    } else {
      setDisplay(display === "0" ? num : display + num);
    }
  };

  const inputDecimal = () => {
    if (waitingForNewValue) {
      setDisplay("0.");
      setWaitingForNewValue(false);
    } else if (display.indexOf(".") === -1) {
      setDisplay(display + ".");
    }
  };

  const clear = () => {
    setDisplay("0");
    setPreviousValue(null);
    setOperation(null);
    setWaitingForNewValue(false);
  };

  const performOperation = (nextOperation: string) => {
    const inputValue = parseFloat(display);

    if (previousValue === null) {
      setPreviousValue(inputValue);
    } else if (operation) {
      const currentValue = previousValue || 0;
      const newValue = calculate(currentValue, inputValue, operation);

      setDisplay(`${parseFloat(newValue.toFixed(7))}`);
      setPreviousValue(newValue);
    }

    setWaitingForNewValue(true);
    setOperation(nextOperation);
  };

  const calculate = (firstValue: number, secondValue: number, operation: string): number => {
    switch (operation) {
      case "+":
        return firstValue + secondValue;
      case "-":
        return firstValue - secondValue;
      case "×":
        return firstValue * secondValue;
      case "÷":
        return firstValue / secondValue;
      case "=":
        return secondValue;
      default:
        return secondValue;
    }
  };

  const handleEquals = () => {
    const inputValue = parseFloat(display);

    if (previousValue !== null && operation) {
      const newValue = calculate(previousValue, inputValue, operation);
      setDisplay(`${parseFloat(newValue.toFixed(7))}`);
      setPreviousValue(null);
      setOperation(null);
      setWaitingForNewValue(true);
    }
  };

  const buttons = [
    ["C", "±", "%", "÷"],
    ["7", "8", "9", "×"],
    ["4", "5", "6", "-"],
    ["1", "2", "3", "+"],
    ["0", "", ".", "="]
  ];

  const getButtonStyle = (button: string) => {
    if (button === "") return "invisible";
    if (["÷", "×", "-", "+", "="].includes(button)) {
      return operation === button ? "bg-primary text-primary-foreground" : "bg-primary/10 hover:bg-primary/20 text-primary";
    }
    if (["C", "±", "%"].includes(button)) {
      return "bg-muted hover:bg-muted/80 text-muted-foreground";
    }
    return "bg-background hover:bg-accent hover:text-accent-foreground border border-border";
  };

  const handleButtonClick = (button: string) => {
    switch (button) {
      case "C":
        clear();
        break;
      case "±":
        setDisplay((parseFloat(display) * -1).toString());
        break;
      case "%":
        setDisplay((parseFloat(display) / 100).toString());
        break;
      case ".":
        inputDecimal();
        break;
      case "=":
        handleEquals();
        break;
      case "+":
      case "-":
      case "×":
      case "÷":
        performOperation(button);
        break;
      default:
        if (!isNaN(parseInt(button))) {
          inputNumber(button);
        }
        break;
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={(open) => !open && onCloseRef.current()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center space-x-2">
            <i className="fas fa-calculator text-primary"></i>
            <span>Калькулятор</span>
          </DialogTitle>
        </DialogHeader>
        
        <div className="space-y-4">
          {/* Display */}
          <div className="bg-muted rounded-lg p-4">
            <div 
              className="text-right text-3xl font-mono font-bold text-foreground min-h-[2.5rem] flex items-center justify-end"
              data-testid="calculator-display"
            >
              {display}
            </div>
          </div>
          
          {/* Button Grid */}
          <div className="grid grid-cols-4 gap-2">
            {buttons.flat().map((button, index) => (
              <Button
                key={index}
                variant="ghost"
                size="lg"
                className={`h-14 text-lg font-semibold ${getButtonStyle(button)} ${
                  button === "0" ? "col-span-2" : ""
                }`}
                onClick={() => handleButtonClick(button)}
                disabled={button === ""}
                data-testid={`calculator-button-${button}`}
              >
                {button}
              </Button>
            ))}
          </div>
          
          {/* Scientific Functions */}
          <div className="grid grid-cols-3 gap-2 pt-2 border-t border-border">
            <Button
              variant="ghost"
              size="sm"
              className="text-sm bg-muted hover:bg-muted/80"
              onClick={() => setDisplay(Math.sin(parseFloat(display) * Math.PI / 180).toString())}
              data-testid="calculator-sin"
            >
              sin
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="text-sm bg-muted hover:bg-muted/80"
              onClick={() => setDisplay(Math.cos(parseFloat(display) * Math.PI / 180).toString())}
              data-testid="calculator-cos"
            >
              cos
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="text-sm bg-muted hover:bg-muted/80"
              onClick={() => setDisplay(Math.tan(parseFloat(display) * Math.PI / 180).toString())}
              data-testid="calculator-tan"
            >
              tan
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="text-sm bg-muted hover:bg-muted/80"
              onClick={() => setDisplay(Math.sqrt(parseFloat(display)).toString())}
              data-testid="calculator-sqrt"
            >
              √
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="text-sm bg-muted hover:bg-muted/80"
              onClick={() => setDisplay(Math.pow(parseFloat(display), 2).toString())}
              data-testid="calculator-square"
            >
              x²
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="text-sm bg-muted hover:bg-muted/80"
              onClick={() => setDisplay(Math.log(parseFloat(display)).toString())}
              data-testid="calculator-ln"
            >
              ln
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

export default memo(Calculator);
