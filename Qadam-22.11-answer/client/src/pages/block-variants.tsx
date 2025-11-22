import { useQuery } from "@tanstack/react-query";
import { useRoute, useLocation } from "wouter";
import { useState, useEffect } from "react";
import Header from "@/components/layout/header";
import Footer from "@/components/layout/footer";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import type { Block, Variant } from "@shared/schema";

export default function BlockVariantsPage() {
  const [match, params] = useRoute("/block/:blockId");
  const [, setLocation] = useLocation();
  const blockId = params?.blockId;

  const { data: block, isLoading: blockLoading } = useQuery<Block>({
    queryKey: ["/api/blocks", blockId],
    enabled: !!blockId,
  });

  const { data: variants, isLoading: variantsLoading } = useQuery<Variant[]>({
    queryKey: ["/api/blocks", blockId, "variants"],
    enabled: !!blockId,
  });

  // Запрос лучшего результата дня
  const { data: bestTodayResult } = useQuery<{score: number}>({
    queryKey: ["/api/rankings/today-best"],
    enabled: !!blockId,
  });

  // Запрос моего последнего результата  
  const { data: myLastResult } = useQuery<{score: number}>({
    queryKey: ["/api/profile/latest-result"],
    enabled: !!blockId,
  });

  // Запрос даты ЕНТ из настроек
  const { data: entDateSetting } = useQuery<{key: string, value: string}>({
    queryKey: ["/api/settings/ent_exam_date"],
  });

  // Состояние для обратного отсчета
  const [timeLeft, setTimeLeft] = useState({
    days: 0,
    hours: 0,
    minutes: 0,
    seconds: 0
  });

  // Обновление обратного отсчета каждую секунду
  useEffect(() => {
    // Не запускаем таймер пока не загрузится дата
    if (!entDateSetting?.value) {
      return;
    }

    const updateTimer = () => {
      const entDateString = entDateSetting?.value || '2025-01-16T00:00:00.000Z';
      const entDate = new Date(entDateString).getTime();
      const now = new Date().getTime();
      const difference = entDate - now;

      if (difference > 0) {
        setTimeLeft({
          days: Math.floor(difference / (1000 * 60 * 60 * 24)),
          hours: Math.floor((difference % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60)),
          minutes: Math.floor((difference % (1000 * 60 * 60)) / (1000 * 60)),
          seconds: Math.floor((difference % (1000 * 60)) / 1000)
        });
      } else {
        // Если время прошло, показываем нули
        setTimeLeft({ days: 0, hours: 0, minutes: 0, seconds: 0 });
      }
    };

    updateTimer(); // Вызываем сразу
    const timer = setInterval(updateTimer, 1000);

    return () => clearInterval(timer);
  }, [entDateSetting]);

  if (!match || !blockId) {
    setLocation("/");
    return null;
  }

  if (blockLoading || variantsLoading) {
    return (
      <div className="min-h-screen relative">
        {/* Custom two-tone background */}
        <div className="absolute inset-0 z-0">
          <div className="h-1/2 bg-blue-300 border-b-2 border-gray-400"></div>
          <div className="h-1/2 bg-blue-200"></div>
        </div>
        <div className="relative z-10">
          <Header />
          <main className="container mx-auto px-4 lg:px-6 py-8">
          <div className="space-y-6">
            <Skeleton className="h-20 w-full" />
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {[...Array(8)].map((_, i) => (
                <Skeleton key={i} className="h-48" />
              ))}
            </div>
          </div>
          </main>
        </div>
      </div>
    );
  }

  if (!block || !variants) {
    return (
      <div className="min-h-screen relative">
        {/* Custom two-tone background */}
        <div className="absolute inset-0 z-0">
          <div className="h-1/2 bg-blue-300 border-b-2 border-gray-400"></div>
          <div className="h-1/2 bg-blue-200"></div>
        </div>
        <div className="relative z-10">
          <Header />
          <main className="container mx-auto px-4 lg:px-6 py-8">
          <div className="text-center">
            <h1 className="text-2xl font-bold text-foreground mb-4">Блок не найден</h1>
            <Button onClick={() => setLocation("/dashboard")} data-testid="button-back-home">
              Вернуться на главную
            </Button>
          </div>
          </main>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen relative">
      {/* Custom two-tone background */}
      <div className="absolute inset-0 z-0">
        <div className="h-1/2 bg-blue-300 border-b-2 border-gray-400"></div>
        <div className="h-1/2 bg-blue-200"></div>
      </div>
      <div className="relative z-10">
        <Header />
        <main className="container mx-auto px-4 lg:px-6 py-8">
        {/* Navigation */}
        <div className="mb-4">
          <Button 
            variant="ghost" 
            onClick={() => setLocation("/dashboard")}
            className="mb-4 text-base px-4 py-2"
            data-testid="button-back"
          >
            <i className="fas fa-arrow-left mr-2"></i>
            Назад к блокам
          </Button>
        </div>

        {/* Main Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
          {/* Variants List - Left Panel (2 из 3 колонок = 66.67%) */}
          <div className="lg:col-span-2">
            {/* Block Title */}
            <div className="mb-6">
              <h1 className="text-3xl font-bold text-foreground">{block?.name}</h1>
            </div>
            
            <div className="space-y-[15px] h-[480px] overflow-y-auto scrollbar-hide">
              {variants.map((variant, index) => (
                <Card 
                  key={variant.id} 
                  className="hover:shadow-lg transition-all duration-200 cursor-pointer border-2 hover:border-blue-300"
                  onClick={() => setLocation(`/test/${variant.id}`)}
                  data-testid={`card-variant-${variant.id}`}
                >
                  <CardContent className="py-[15px] px-6">
                    <div className="flex items-center justify-between">
                      <h3 className="text-2xl font-bold text-foreground">
                        {variant.name}
                      </h3>
                      
                      <div className="text-base font-medium text-muted-foreground">
                        4 сағат 140балл
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
          
          {/* Right Panel - Information Cards (1 из 3 колонок = 33.33%) */}
          <div className="lg:col-span-1 h-[540px]">
            <div className="h-full flex flex-col justify-between">
            {/* 1. Обратный отсчет до ЕНТ */}
            <Card className="flex-1 mb-3">
              <CardContent className="p-4 h-full flex flex-col justify-center">
                <div className="flex items-center space-x-2 mb-2">
                  <i className="fas fa-calendar-alt text-black"></i>
                  <h3 className="text-sm font-semibold text-black">ҰБТ-ға дейін</h3>
                </div>
                <div className="text-black">
                  <div className="grid grid-cols-4 gap-0.5 text-center">
                    <div>
                      <div className="text-lg font-bold">{timeLeft.days}</div>
                      <div className="text-xs">күн</div>
                    </div>
                    <div>
                      <div className="text-lg font-bold">{timeLeft.hours}</div>
                      <div className="text-xs">сағат</div>
                    </div>
                    <div>
                      <div className="text-lg font-bold">{timeLeft.minutes}</div>
                      <div className="text-xs">мин</div>
                    </div>
                    <div>
                      <div className="text-lg font-bold">{timeLeft.seconds}</div>
                      <div className="text-xs">сек</div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* 2. Лучший сегодняшний результат */}
            <Card className="flex-1 mb-3">
              <CardContent className="p-4 h-full flex flex-col justify-center">
                <div className="flex items-center space-x-2 mb-2">
                  <i className="fas fa-trophy text-black"></i>
                  <h3 className="text-sm font-semibold text-black">Бүгінгі ең жақсы нәтиже</h3>
                </div>
                <p className="text-xl font-bold text-black">
                  {bestTodayResult?.score !== undefined ? bestTodayResult.score : '—'} ұпай
                </p>
                <p className="text-xs text-black">Барлық пайдаланушылар арасында</p>
              </CardContent>
            </Card>

            {/* 3. Мой последний результат */}
            <Card className="flex-1 mb-3">
              <CardContent className="p-4 h-full flex flex-col justify-center">
                <div className="flex items-center space-x-2 mb-2">
                  <i className="fas fa-user-chart text-black"></i>
                  <h3 className="text-sm font-semibold text-black">Менің соңғы нәтижем</h3>
                </div>
                <p className="text-xl font-bold text-black">
                  {myLastResult?.score !== undefined ? myLastResult.score : '—'} ұпай
                </p>
                <p className="text-xs text-black">Соңғы тапсыру</p>
              </CardContent>
            </Card>

            {/* 4. Цитата */}
            <Card className="flex-1">
              <CardContent className="p-4 h-full flex flex-col justify-center">
                <div className="flex items-center space-x-2 mb-2">
                  <i className="fas fa-quote-left text-black"></i>
                  <h3 className="text-sm font-semibold text-black">Бүгінгі дәйексөз</h3>
                </div>
                <blockquote className="text-sm text-black italic mb-2">
                  "Табысқа жету үшін алдымен оған сену керек."
                </blockquote>
                <p className="text-xs text-black">- Уолт Дисней</p>
              </CardContent>
            </Card>
            </div>
          </div>
        </div>


        </main>
        <Footer />
      </div>
    </div>
  );
}