import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Check, Crown, Star, Zap } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface SubscriptionPlan {
  id: string;
  name: string;
  description: string;
  price: number;
  currency: string;
  durationDays: number;
  features: string[];
  isActive: boolean;
  sortOrder: number;
}

interface UserSubscription {
  id: string;
  planId: string;
  status: string;
  startDate: string;
  endDate: string;
  autoRenew: boolean;
}

const featureLabels: Record<string, string> = {
  single_test: "Бір тест өту",
  basic_results: "Негізгі нәтижелер", 
  block_access: "Блокқа толық қол жеткізу",
  unlimited_tests: "Шексіз тестер",
  progress_tracking: "Прогресті бақылау",
  detailed_results: "Толық нәтижелер",
  // Старые labels для совместимости
  physics_math_block: "Физика-математика блогы",
  basic_tests: "Негізгі тестер",
  all_tests: "Барлық тестер",
  detailed_analytics: "Толық аналитика",
  export_results: "Нәтижелерді экспорттау",
  priority_support: "Басымдықты қолдау",
  unlimited_attempts: "Шексіз әрекеттер",
};

const getIconForPlan = (planName: string) => {
  if (planName.includes("1 тест")) return Star;
  if (planName.includes("месяц") || planName.includes("month")) return Crown;
  return Zap;
};

export default function SubscriptionPage() {
  const [isLoading, setIsLoading] = useState<string | null>(null);
  const { toast } = useToast();
  const queryClient = useQueryClient();

  // Получаем планы подписки
  const { data: plans = [] } = useQuery<SubscriptionPlan[]>({
    queryKey: ["/api/subscription/plans"],
    queryFn: async () => {
      const response = await fetch("/api/subscription/plans");
      if (!response.ok) throw new Error("Failed to fetch plans");
      return response.json();
    },
  });

  // Получаем текущую подписку пользователя
  const { data: currentSubscription } = useQuery<UserSubscription | null>({
    queryKey: ["/api/subscription/current"],
    queryFn: async () => {
      const response = await fetch("/api/subscription/current");
      if (response.status === 404) return null;
      if (!response.ok) throw new Error("Failed to fetch subscription");
      return response.json();
    },
  });

  // Мутация для создания платежа
  const createPayment = useMutation({
    mutationFn: async (planId: string) => {
      const response = await fetch("/api/payments/create", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ planId }),
      });
      if (!response.ok) throw new Error("Failed to create payment");
      return response.json();
    },
    onSuccess: (data) => {
      // Перенаправляем на страницу оплаты
      if (data.paymentUrl) {
        window.location.href = data.paymentUrl;
      }
    },
    onError: (error) => {
      toast({
        title: "Ошибка",
        description: "Не удалось создать платеж. Попробуйте еще раз.",
        variant: "destructive",
      });
    },
    onSettled: () => {
      setIsLoading(null);
    },
  });

  const handleSubscribe = (planId: string) => {
    setIsLoading(planId);
    createPayment.mutate(planId);
  };

  const formatPrice = (price: number, currency: string) => {
    if (currency === "KZT") {
      return `${(price / 100).toLocaleString("kk-KZ")} ₸`;
    }
    return new Intl.NumberFormat("ru-RU", {
      style: "currency",
      currency: currency,
    }).format(price / 100);
  };

  const isCurrentPlan = (planId: string) => {
    return currentSubscription?.planId === planId && currentSubscription?.status === "ACTIVE";
  };

  const isSubscriptionActive = currentSubscription?.status === "ACTIVE";

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="text-center mb-12">
        <h1 className="text-4xl font-bold mb-4">Тарифтік жоспарды таңдаңыз</h1>
        <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
          Бір тест өтіңіз немесе кез келген блокқа 1 айға толық қол жеткізу алыңыз
        </p>
      </div>

      {/* Текущая подписка */}
      {isSubscriptionActive && (
        <div className="mb-8">
          <Card className="border-green-200 bg-green-50">
            <CardHeader>
              <CardTitle className="text-green-800">Белсенді жазылым</CardTitle>
              <CardDescription className="text-green-600">
                Жазылымыңыз мерзімі{" "}
                {new Date(currentSubscription!.endDate).toLocaleDateString("kk-KZ")} дейін
              </CardDescription>
            </CardHeader>
          </Card>
        </div>
      )}

      {/* Планы подписки */}
      <div className="grid md:grid-cols-3 gap-8 max-w-6xl mx-auto">
        {plans
          .sort((a, b) => a.sortOrder - b.sortOrder)
          .map((plan) => {
            const Icon = getIconForPlan(plan.name);
            const isPopular = plan.name.includes("месяц") && plan.sortOrder === 2;
            const isCurrent = isCurrentPlan(plan.id);
            
            return (
              <Card
                key={plan.id}
                className={`relative transition-all duration-200 hover:shadow-lg ${
                  isPopular ? "border-primary scale-105 shadow-lg" : ""
                } ${isCurrent ? "border-green-500 bg-green-50" : ""}`}
              >
                {isPopular && (
                  <Badge className="absolute -top-3 left-1/2 transform -translate-x-1/2 bg-primary">
                    Танымал
                  </Badge>
                )}
                
                {isCurrent && (
                  <Badge className="absolute -top-3 left-1/2 transform -translate-x-1/2 bg-green-500">
                    Белсенді
                  </Badge>
                )}

                <CardHeader className="text-center">
                  <div className="mx-auto mb-4 p-3 rounded-full bg-primary/10 w-fit">
                    <Icon className="w-8 h-8 text-primary" />
                  </div>
                  <CardTitle className="text-2xl">{plan.name}</CardTitle>
                  <CardDescription>{plan.description}</CardDescription>
                  <div className="mt-4">
                    <span className="text-4xl font-bold">
                      {formatPrice(plan.price, plan.currency)}
                    </span>
                    <span className="text-muted-foreground">/{plan.durationDays} дней</span>
                  </div>
                </CardHeader>

                <CardContent>
                  <ul className="space-y-3">
                    {plan.features.map((feature) => (
                      <li key={feature} className="flex items-center gap-3">
                        <Check className="w-5 h-5 text-green-500 flex-shrink-0" />
                        <span>{featureLabels[feature] || feature}</span>
                      </li>
                    ))}
                  </ul>
                </CardContent>

                <CardFooter>
                  <Button
                    className="w-full"
                    variant={isPopular ? "default" : "outline"}
                    disabled={isCurrent || isLoading === plan.id}
                    onClick={() => handleSubscribe(plan.id)}
                  >
                    {isLoading === plan.id ? (
                      "Төлем жасалуда..."
                    ) : isCurrent ? (
                      "Белсенді"
                    ) : (
                      "Сатып алу"
                    )}
                  </Button>
                </CardFooter>
              </Card>
            );
          })}
      </div>

      {/* Дополнительная информация */}
      <div className="mt-16 text-center">
        <h3 className="text-2xl font-semibold mb-4">Жиі қойылатын сұрақтар</h3>
        <div className="max-w-2xl mx-auto space-y-4 text-left">
          <details className="bg-muted/50 rounded-lg p-4">
            <summary className="font-semibold cursor-pointer">
              1 тест дегеніміз не?
            </summary>
            <p className="mt-2 text-muted-foreground">
              Бұл кез келген бір тестті 1 рет өтуге мүмкіндік береді. Тест аяқталғаннан кейін 
              нәтижеңізді көре аласыз.
            </p>
          </details>
          
          <details className="bg-muted/50 rounded-lg p-4">
            <summary className="font-semibold cursor-pointer">
              Блокқа жазылсам не болады?
            </summary>
            <p className="mt-2 text-muted-foreground">
              1 ай бойы таңдаған блоктағы барлық тестерді шексіз өте аласыз. 
              Детальды нәтижелер мен прогресс көрсету қолжетімді. Кез келген блокты таңдауға болады.
            </p>
          </details>
          
          <details className="bg-muted/50 rounded-lg p-4">
            <summary className="font-semibold cursor-pointer">
              Қалай төлеуге болады?
            </summary>
            <p className="mt-2 text-muted-foreground">
              Қазақстандық банк карталары, Kaspi QR, Apple Pay, Google Pay арқылы төлеуге болады.
            </p>
          </details>
        </div>
      </div>
    </div>
  );
}