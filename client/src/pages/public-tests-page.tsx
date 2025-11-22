import { useQuery } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { BookOpen, ArrowLeft, FileText, Clock, Users } from "lucide-react";
import { Link } from "wouter";
import type { Block } from "@shared/schema";

interface PublicBlock extends Block {
  variantCount: number;
  totalQuestions: number;
}

export default function PublicTestsPage() {
  const { data: blocks, isLoading, error } = useQuery<PublicBlock[]>({
    queryKey: ["/api/public/blocks"],
    queryFn: async () => {
      const res = await fetch("/api/public/blocks");
      if (!res.ok) {
        throw new Error("Failed to fetch blocks");
      }
      return res.json();
    },
  });

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 dark:from-gray-900 dark:to-gray-800">
        {/* Header */}
        <header className="bg-blue-500 backdrop-blur-md border-b border-blue-700 sticky top-0 z-50 shadow-lg">
          <div className="container mx-auto px-4 py-4">
            <div className="flex justify-between items-center">
              <div className="flex items-center space-x-6">
                <div className="flex items-center space-x-3">
                  <div className="bg-white/20 text-white p-2 rounded-lg">
                    <BookOpen className="h-6 w-6" />
                  </div>
                  <div>
                    <h1 className="text-xl font-bold text-white">Qadam</h1>
                    <p className="text-sm text-blue-50">Система тестирования ЕНТ</p>
                  </div>
                </div>
                
                <Link href="/public-ranking">
                  <Button variant="ghost" className="text-white hover:bg-white/10 font-medium">
                    Рейтинг
                  </Button>
                </Link>
                
                <Link href="/public-tests">
                  <Button variant="ghost" className="text-white hover:bg-white/10 font-medium bg-white/10">
                    Тесты
                  </Button>
                </Link>
              </div>
              
              <div className="flex space-x-3">
                <Link href="/">
                  <Button variant="ghost" className="text-white hover:bg-white/10 font-medium">
                    <ArrowLeft className="h-4 w-4 mr-2" />
                    Назад
                  </Button>
                </Link>
                <Link href="/auth">
                  <Button className="bg-white/90 text-blue-500 hover:bg-white border border-white font-medium">
                    Вход
                  </Button>
                </Link>
              </div>
            </div>
          </div>
        </header>

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

  if (error) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 dark:from-gray-900 dark:to-gray-800">
        {/* Header */}
        <header className="bg-blue-500 backdrop-blur-md border-b border-blue-700 sticky top-0 z-50 shadow-lg">
          <div className="container mx-auto px-4 py-4">
            <div className="flex justify-between items-center">
              <div className="flex items-center space-x-6">
                <div className="flex items-center space-x-3">
                  <div className="bg-white/20 text-white p-2 rounded-lg">
                    <BookOpen className="h-6 w-6" />
                  </div>
                  <div>
                    <h1 className="text-xl font-bold text-white">Qadam</h1>
                    <p className="text-sm text-blue-50">Система тестирования ЕНТ</p>
                  </div>
                </div>
                
                <Link href="/public-ranking">
                  <Button variant="ghost" className="text-white hover:bg-white/10 font-medium">
                    Рейтинг
                  </Button>
                </Link>
                
                <Link href="/public-tests">
                  <Button variant="ghost" className="text-white hover:bg-white/10 font-medium bg-white/10">
                    Тесты
                  </Button>
                </Link>
              </div>
              
              <div className="flex space-x-3">
                <Link href="/">
                  <Button variant="ghost" className="text-white hover:bg-white/10 font-medium">
                    <ArrowLeft className="h-4 w-4 mr-2" />
                    Назад
                  </Button>
                </Link>
                <Link href="/auth">
                  <Button className="bg-white/90 text-blue-500 hover:bg-white border border-white font-medium">
                    Вход
                  </Button>
                </Link>
              </div>
            </div>
          </div>
        </header>

        <div className="container mx-auto px-4 py-12">
          <div className="text-center">
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-4">
              Ошибка загрузки
            </h1>
            <p className="text-gray-600 dark:text-gray-400 mb-8">
              Не удалось загрузить список тестов. Попробуйте позже.
            </p>
            <Link href="/">
              <Button className="bg-blue-500 hover:bg-blue-700 text-white">
                Вернуться на главную
              </Button>
            </Link>
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
            <div className="flex items-center space-x-6">
              <div className="flex items-center space-x-3">
                <div className="bg-white/20 text-white p-2 rounded-lg">
                  <BookOpen className="h-6 w-6" />
                </div>
                <div>
                  <h1 className="text-xl font-bold text-white">Qadam</h1>
                  <p className="text-sm text-blue-50">Система тестирования ЕНТ</p>
                </div>
              </div>
              
              <Link href="/public-ranking">
                <Button variant="ghost" className="text-white hover:bg-white/10 font-medium">
                  Рейтинг
                </Button>
              </Link>
              
              <Link href="/public-tests">
                <Button variant="ghost" className="text-white hover:bg-white/10 font-medium bg-white/10">
                  Тесты
                </Button>
              </Link>
            </div>
            
            <div className="flex space-x-3">
              <Link href="/">
                <Button variant="ghost" className="text-white hover:bg-white/10 font-medium">
                  <ArrowLeft className="h-4 w-4 mr-2" />
                  Назад
                </Button>
              </Link>
              <Link href="/auth">
                <Button className="bg-white/90 text-blue-500 hover:bg-white border border-white font-medium">
                  Вход
                </Button>
              </Link>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="container mx-auto px-4 py-12">
        <div className="text-center mb-12">
          <h1 className="text-4xl md:text-5xl font-bold text-gray-900 dark:text-white mb-4">
            Тесты ЕНТ
          </h1>
          <p className="text-xl text-gray-600 dark:text-gray-400 max-w-2xl mx-auto">
            Выберите предмет для подготовки к Единому национальному тестированию
          </p>
        </div>

        {!blocks || blocks.length === 0 ? (
          <div className="text-center py-12">
            <FileText className="h-16 w-16 text-gray-400 mx-auto mb-4" />
            <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
              Тесты пока не добавлены
            </h3>
            <p className="text-gray-600 dark:text-gray-400">
              Скоро здесь появятся тесты для подготовки к ЕНТ
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {blocks.map((block) => (
              <Card key={block.id} className="hover:shadow-lg transition-shadow duration-200 bg-white dark:bg-gray-800 border-0 shadow-md">
                <CardHeader className="pb-4">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <CardTitle className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
                        {block.name}
                      </CardTitle>
                      <CardDescription className="text-sm text-gray-600 dark:text-gray-400 line-clamp-2">
                        Тестирование по предмету {block.name}
                      </CardDescription>
                    </div>
                    <Badge variant="secondary" className="bg-blue-50 text-blue-500 dark:bg-blue-700 dark:text-blue-50">
                      Предмет
                    </Badge>
                  </div>
                </CardHeader>
                
                <CardContent className="pt-0">
                  <div className="flex items-center justify-between text-sm text-gray-500 dark:text-gray-400 mb-4">
                    <div className="flex items-center space-x-4">
                      <div className="flex items-center">
                        <FileText className="h-4 w-4 mr-1" />
                        <span>{block.variantCount || 0} вариантов</span>
                      </div>
                      <div className="flex items-center">
                        <Clock className="h-4 w-4 mr-1" />
                        <span>{block.totalQuestions || 0} вопросов</span>
                      </div>
                    </div>
                  </div>
                  
                  <Link href="/auth">
                    <Button className="w-full bg-blue-500 hover:bg-blue-700 text-white font-medium">
                      Начать тест
                    </Button>
                  </Link>
                </CardContent>
              </Card>
            ))}
          </div>
        )}

        {/* Call to Action */}
        <div className="text-center mt-16">
          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-8 max-w-3xl mx-auto">
            <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-4">
              Готовы начать подготовку?
            </h2>
            <p className="text-gray-600 dark:text-gray-400 mb-6">
              Зарегистрируйтесь, чтобы получить доступ ко всем тестам и отслеживать свой прогресс
            </p>
            <div className="flex flex-col sm:flex-row gap-3 justify-center">
              <Link href="/auth">
                <Button size="lg" className="bg-blue-500 hover:bg-blue-700 text-white font-medium px-8">
                  Зарегистрироваться
                </Button>
              </Link>
              <Link href="/public-ranking">
                <Button size="lg" variant="outline" className="border-blue-500 text-blue-500 hover:bg-blue-50 font-medium px-8">
                  Посмотреть рейтинг
                </Button>
              </Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

