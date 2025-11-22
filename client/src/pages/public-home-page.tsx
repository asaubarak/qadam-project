import { useQuery } from "@tanstack/react-query";
import { useAuth } from "@/hooks/use-auth";
import { useLocation } from "wouter";
import { useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { BookOpen, Users, Trophy, Calculator, Atom } from "lucide-react";
import { Link } from "wouter";
import type { Block, Variant } from "@shared/schema";

interface FreeVariant extends Variant {
  block: Block;
  isFree: boolean;
}

export default function PublicHomePage() {
  const { user, isLoading: authLoading } = useAuth();
  const [, setLocation] = useLocation();
  
  // Redirect to dashboard if user is authenticated
  useEffect(() => {
    if (!authLoading && user) {
      setLocation("/dashboard");
    }
  }, [user, authLoading, setLocation]);

  const { data: freeVariants, isLoading } = useQuery<FreeVariant[]>({
    queryKey: ['/api/public/free-variants'],
  });

  if (isLoading || authLoading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 dark:from-gray-900 dark:to-gray-800">
        <div className="container mx-auto px-4 py-8">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className="h-48 bg-gray-200 dark:bg-gray-700 rounded-lg animate-pulse"></div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 dark:from-gray-900 dark:to-gray-800">
      {/* Header */}
      <header className="bg-blue-500 backdrop-blur-md border-b border-blue-700 sticky top-0 z-50 shadow-lg">
        <div className="container mx-auto px-4 py-4">
          <div className="flex justify-between items-center">
            <div className="flex items-center space-x-3">
              <div className="bg-white/20 text-white p-2 rounded-lg">
                <BookOpen className="h-6 w-6" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-white">Qadam</h1>
                <p className="text-sm text-blue-50">ҰБТ тестілеу жүйесі</p>
              </div>
            </div>
            
            <div className="hidden md:flex items-center space-x-6">
              <Link href="/public-ranking">
                <Button variant="ghost" className="text-white hover:bg-white/10 font-medium" data-testid="button-ranking">
                  Рейтинг
                </Button>
              </Link>
              
              <Link href="/public-tests">
                <Button variant="ghost" className="text-white hover:bg-white/10 font-medium" data-testid="button-tests">
                  Тесттер
                </Button>
              </Link>
              
              <Link href="/about">
                <Button variant="ghost" className="text-white hover:bg-white/10 font-medium" data-testid="button-about">
                  Біз туралы
                </Button>
              </Link>
            </div>
            
            <div className="flex space-x-2 md:space-x-3">
              <Link href="/auth">
                <Button className="bg-white/90 text-blue-500 hover:bg-white border border-white font-medium text-sm md:text-base px-3 md:px-4" data-testid="button-login">
                  Кіру
                </Button>
              </Link>
            </div>
          </div>
        </div>
      </header>

      {/* Hero Section - reduced height */}
      <section className="py-8 md:py-16 lg:py-20 min-h-[50vh] md:min-h-[60vh] relative w-full">
        {/* Background with glass effect */}
        <div className="absolute inset-0 bg-cover bg-center bg-no-repeat" style={{backgroundImage: 'url("/1234.jpg")'}}></div>
        <div className="absolute inset-0 bg-black/20 backdrop-blur-[1px]"></div>
        <div className="absolute inset-0 bg-gradient-to-br from-white/10 via-transparent to-blue-700/30"></div>
        
        <div className="container mx-auto px-4 lg:px-6 relative z-20 h-full flex flex-col justify-between">
          {/* Text aligned left on mobile */}
          <div className="text-left pt-4 md:pt-12">
            <h1 className="text-3xl sm:text-4xl md:text-5xl lg:text-6xl xl:text-7xl font-bold text-white mb-4 md:mb-6 leading-tight">
              ҰБТ-ға дайындық
            </h1>
            <p className="text-base sm:text-lg md:text-xl lg:text-2xl text-blue-50 mb-6 md:mb-8 max-w-2xl leading-relaxed">
              ҰБТ тесттерінің тегін нұсқаларын тапсырыңыз. Бейімделгіш тестілеу жүйесі 
              сіздің білім деңгейіңізді анықтап, емтиханға дайындалуға көмектеседі.
            </p>
          </div>
          
          {/* Button with 120px gap and slight rounding */}
          <div className="text-left pb-4 md:pb-8" style={{ marginTop: '120px' }}>
            <Link href="/auth">
              <Button size="lg" className="bg-blue-500 text-white hover:bg-blue-700 font-medium px-8 py-3 md:px-12 md:py-5 text-sm md:text-lg rounded-[2px] h-11 md:h-14 w-auto">
                Тегін тіркелу
              </Button>
            </Link>
          </div>
        </div>
      </section>

      {/* Features Cards - almost square */}
      <section className="relative -mt-8 md:-mt-16 z-20 mb-8 md:mb-16">
        <div className="container mx-auto px-4 md:px-8">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 md:gap-8 lg:gap-12 max-w-6xl mx-auto">
            <Link href="/public-ranking">
              <div className="bg-white shadow-lg rounded-sm p-3 md:p-6 hover:shadow-xl hover:bg-blue-50 transition-all cursor-pointer min-h-[140px] md:min-h-[224px]">
                <div className="flex items-start gap-2 md:gap-4 mb-2 md:mb-4">
                  <Trophy className="h-6 w-6 md:h-12 md:w-12 text-blue-500 flex-shrink-0" />
                  <span className="text-gray-800 font-semibold text-lg md:text-2xl lg:text-3xl">Рейтингтер</span>
                </div>
                <p className="text-gray-600 text-xs md:text-base leading-relaxed">
                  Барлық қатысушылардың рейтингін көріп, студенттер арасындағы өз орныңызды біліңіз.
                </p>
              </div>
            </Link>
            <Link href="/public-tests">
              <div className="bg-white shadow-lg rounded-sm p-3 md:p-6 hover:shadow-xl hover:bg-blue-50 transition-all cursor-pointer min-h-[140px] md:min-h-[224px]">
                <div className="flex items-start gap-2 md:gap-4 mb-2 md:mb-4">
                  <BookOpen className="h-6 w-6 md:h-12 md:w-12 text-blue-500 flex-shrink-0" />
                  <span className="text-gray-800 font-semibold text-lg md:text-2xl lg:text-3xl">Тесттер</span>
                </div>
                <p className="text-gray-600 text-xs md:text-base leading-relaxed">
                  Әртүрлі пәндер бойынша тесттерден өтіп, толық нәтижелер мен талдауды алыңыз.
                </p>
              </div>
            </Link>
            <Link href="/about">
              <div className="bg-white shadow-lg rounded-sm p-3 md:p-6 hover:shadow-xl hover:bg-blue-50 transition-all cursor-pointer min-h-[140px] md:min-h-[224px]">
                <div className="flex items-start gap-2 md:gap-4 mb-2 md:mb-4">
                  <Users className="h-6 w-6 md:h-12 md:w-12 text-blue-500 flex-shrink-0" />
                  <span className="text-gray-800 font-semibold text-lg md:text-2xl lg:text-3xl">Біз туралы</span>
                </div>
                <p className="text-gray-600 text-xs md:text-base leading-relaxed">
                  Онлайн тестілеу және студенттерді білімдендіру платформамыз туралы көбірек біліңіз.
                </p>
              </div>
            </Link>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-16 bg-white">
        <div className="container mx-auto px-4 text-center">
          <h2 className="text-3xl font-bold mb-4 text-gray-900">
            Готовы к более серьезной подготовке?
          </h2>
          <p className="text-xl mb-8 text-gray-600">
            Зарегистрируйтесь для доступа ко всем тестам, аналитике и рейтингам
          </p>

        </div>
      </section>

      {/* Footer */}
      <footer className="bg-gray-900 text-gray-300 py-8">
        <div className="container mx-auto px-4 text-center">
          <div className="flex items-center justify-center space-x-3 mb-4">
            <div className="bg-blue-500 text-white p-2 rounded-lg">
              <BookOpen className="h-5 w-5" />
            </div>
            <span className="text-lg font-semibold">Qadam</span>
          </div>
          <p className="text-sm text-gray-400">
            © 2025 Qadam. Система подготовки к ЕНТ.
          </p>
        </div>
      </footer>
    </div>
  );
}
