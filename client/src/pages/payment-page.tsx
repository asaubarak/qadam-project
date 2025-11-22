import { useEffect, useState } from "react";
import { useLocation, useRoute } from "wouter";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Check, CreditCard, Loader2 } from "lucide-react";

export default function PaymentPage() {
  const [location] = useLocation();
  const [match, params] = useRoute("/payment/:paymentId");
  const [isProcessing, setIsProcessing] = useState(false);
  const [isCompleted, setIsCompleted] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const paymentId = params?.paymentId;
  const urlParams = new URLSearchParams(location.split('?')[1]);
  const isMock = urlParams.get('mock') === 'true';

  const handlePayment = async () => {
    if (!paymentId) return;
    
    setIsProcessing(true);
    setError(null);

    try {
      // Симуляция процесса оплаты
      await new Promise(resolve => setTimeout(resolve, 2000));

      // Завершаем платеж через API
      const response = await fetch(`/api/payments/${paymentId}/complete`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });

      if (!response.ok) {
        throw new Error("Ошибка обработки платежа");
      }

      setIsCompleted(true);
    } catch (error) {
      setError("Произошла ошибка при обработке платежа. Попробуйте еще раз.");
      console.error("Payment error:", error);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleReturnToHome = () => {
    window.location.href = "/";
  };

  if (!paymentId) {
    return (
      <div className="container mx-auto px-4 py-8">
        <Card className="max-w-md mx-auto">
          <CardHeader>
            <CardTitle className="text-red-600">Ошибка</CardTitle>
            <CardDescription>Неверная ссылка для оплаты</CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="max-w-md mx-auto">
        {isCompleted ? (
          // Успешная оплата
          <Card className="border-green-200 bg-green-50">
            <CardHeader className="text-center">
              <div className="mx-auto mb-4 p-3 rounded-full bg-green-100 w-fit">
                <Check className="w-8 h-8 text-green-600" />
              </div>
              <CardTitle className="text-green-800">Оплата успешна!</CardTitle>
              <CardDescription className="text-green-600">
                Ваша подписка активирована. Теперь у вас есть доступ ко всем функциям.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Button 
                onClick={handleReturnToHome}
                className="w-full"
              >
                Вернуться на главную
              </Button>
            </CardContent>
          </Card>
        ) : (
          // Форма оплаты
          <Card>
            <CardHeader className="text-center">
              <div className="mx-auto mb-4 p-3 rounded-full bg-primary/10 w-fit">
                <CreditCard className="w-8 h-8 text-primary" />
              </div>
              <CardTitle>Оплата подписки</CardTitle>
              <CardDescription>
                {isMock ? "Тестовая оплата" : "Завершите оплату для активации подписки"}
              </CardDescription>
            </CardHeader>
            
            <CardContent className="space-y-4">
              {isMock && (
                <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
                  <p className="text-yellow-800 text-sm">
                    🧪 <strong>Тестовый режим</strong><br />
                    Это демонстрация платежной системы. Никакие деньги не списываются.
                  </p>
                </div>
              )}

              {error && (
                <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                  <p className="text-red-800 text-sm">{error}</p>
                </div>
              )}

              <div className="space-y-3">
                <div className="bg-gray-50 rounded-lg p-4">
                  <h4 className="font-semibold mb-2">Детали платежа:</h4>
                  <p className="text-sm text-gray-600">ID платежа: {paymentId}</p>
                  <p className="text-sm text-gray-600">Статус: Ожидает оплаты</p>
                </div>

                <Button
                  onClick={handlePayment}
                  disabled={isProcessing}
                  className="w-full"
                  size="lg"
                >
                  {isProcessing ? (
                    <>
                      <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                      Обработка платежа...
                    </>
                  ) : (
                    <>
                      <CreditCard className="w-4 h-4 mr-2" />
                      {isMock ? "Завершить тестовую оплату" : "Оплатить"}
                    </>
                  )}
                </Button>
              </div>

              <div className="text-center">
                <p className="text-xs text-gray-500">
                  Нажимая "Оплатить", вы соглашаетесь с условиями использования
                </p>
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}