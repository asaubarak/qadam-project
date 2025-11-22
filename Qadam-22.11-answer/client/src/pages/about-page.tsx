import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { BookOpen, ArrowLeft, Users, Target, Award, Clock, Shield, TrendingUp } from "lucide-react";
import { Link } from "wouter";

export default function AboutPage() {
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
                <p className="text-sm text-blue-50">Система тестирования ЕНТ</p>
              </div>
            </div>
            
            <div className="flex items-center space-x-6">
              <Link href="/public-ranking">
                <Button variant="ghost" className="text-white hover:bg-white/10 font-medium">
                  Рейтинг
                </Button>
              </Link>
              
              <Link href="/public-tests">
                <Button variant="ghost" className="text-white hover:bg-white/10 font-medium">
                  Тесты
                </Button>
              </Link>
              
              <Link href="/about">
                <Button variant="ghost" className="text-white hover:bg-white/10 font-medium bg-white/10">
                  О нас
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
        {/* Hero Section */}
        <div className="text-center mb-16">
          <h1 className="text-4xl md:text-5xl font-bold text-gray-900 dark:text-white mb-6">
            О проекте Qadam
          </h1>
          <p className="text-xl text-gray-600 dark:text-gray-400 max-w-3xl mx-auto leading-relaxed">
            Современная платформа для подготовки к Единому национальному тестированию, 
            разработанная с использованием передовых технологий и методик обучения
          </p>
        </div>

        {/* Mission Section */}
        <div className="mb-16">
          <Card className="max-w-4xl mx-auto bg-white dark:bg-gray-800 shadow-lg">
            <CardHeader className="text-center pb-6">
              <div className="mx-auto mb-4 p-3 bg-blue-50 dark:bg-blue-700 rounded-full w-fit">
                <Target className="h-8 w-8 text-blue-500 dark:text-blue-400" />
              </div>
              <CardTitle className="text-2xl text-gray-900 dark:text-white">Наша миссия</CardTitle>
            </CardHeader>
            <CardContent className="text-center">
              <p className="text-lg text-gray-600 dark:text-gray-400 leading-relaxed">
                Предоставить каждому абитуриенту Казахстана равные возможности для качественной подготовки 
                к ЕНТ через бесплатную, доступную и эффективную онлайн-платформу. Мы верим, что образование 
                должно быть доступным для всех, независимо от социального и материального положения.
              </p>
            </CardContent>
          </Card>
        </div>

        {/* Features Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8 mb-16">
          <Card className="bg-white dark:bg-gray-800 shadow-md hover:shadow-lg transition-shadow">
            <CardHeader className="text-center pb-4">
              <div className="mx-auto mb-3 p-2 bg-green-100 dark:bg-green-900 rounded-lg w-fit">
                <BookOpen className="h-6 w-6 text-green-600 dark:text-green-400" />
              </div>
              <CardTitle className="text-lg text-gray-900 dark:text-white">Бесплатные тесты</CardTitle>
            </CardHeader>
            <CardContent>
              <CardDescription className="text-center">
                Полный доступ к тестовым заданиям по всем предметам ЕНТ без регистрации и оплаты
              </CardDescription>
            </CardContent>
          </Card>

          <Card className="bg-white dark:bg-gray-800 shadow-md hover:shadow-lg transition-shadow">
            <CardHeader className="text-center pb-4">
              <div className="mx-auto mb-3 p-2 bg-purple-100 dark:bg-purple-900 rounded-lg w-fit">
                <TrendingUp className="h-6 w-6 text-purple-600 dark:text-purple-400" />
              </div>
              <CardTitle className="text-lg text-gray-900 dark:text-white">Аналитика прогресса</CardTitle>
            </CardHeader>
            <CardContent>
              <CardDescription className="text-center">
                Детальная статистика результатов, отслеживание прогресса и выявление слабых мест
              </CardDescription>
            </CardContent>
          </Card>

          <Card className="bg-white dark:bg-gray-800 shadow-md hover:shadow-lg transition-shadow">
            <CardHeader className="text-center pb-4">
              <div className="mx-auto mb-3 p-2 bg-orange-100 dark:bg-orange-900 rounded-lg w-fit">
                <Users className="h-6 w-6 text-orange-600 dark:text-orange-400" />
              </div>
              <CardTitle className="text-lg text-gray-900 dark:text-white">Рейтинги</CardTitle>
            </CardHeader>
            <CardContent>
              <CardDescription className="text-center">
                Сравнение результатов с другими участниками и мотивация к улучшению показателей
              </CardDescription>
            </CardContent>
          </Card>

          <Card className="bg-white dark:bg-gray-800 shadow-md hover:shadow-lg transition-shadow">
            <CardHeader className="text-center pb-4">
              <div className="mx-auto mb-3 p-2 bg-blue-50 dark:bg-blue-700 rounded-lg w-fit">
                <Clock className="h-6 w-6 text-blue-500 dark:text-blue-400" />
              </div>
              <CardTitle className="text-lg text-gray-900 dark:text-white">24/7 доступность</CardTitle>
            </CardHeader>
            <CardContent>
              <CardDescription className="text-center">
                Круглосуточный доступ к платформе с любого устройства в удобное для вас время
              </CardDescription>
            </CardContent>
          </Card>

          <Card className="bg-white dark:bg-gray-800 shadow-md hover:shadow-lg transition-shadow">
            <CardHeader className="text-center pb-4">
              <div className="mx-auto mb-3 p-2 bg-red-100 dark:bg-red-900 rounded-lg w-fit">
                <Shield className="h-6 w-6 text-red-600 dark:text-red-400" />
              </div>
              <CardTitle className="text-lg text-gray-900 dark:text-white">Безопасность</CardTitle>
            </CardHeader>
            <CardContent>
              <CardDescription className="text-center">
                Защита персональных данных и результатов тестирования на высочайшем уровне
              </CardDescription>
            </CardContent>
          </Card>

          <Card className="bg-white dark:bg-gray-800 shadow-md hover:shadow-lg transition-shadow">
            <CardHeader className="text-center pb-4">
              <div className="mx-auto mb-3 p-2 bg-yellow-100 dark:bg-yellow-900 rounded-lg w-fit">
                <Award className="h-6 w-6 text-yellow-600 dark:text-yellow-400" />
              </div>
              <CardTitle className="text-lg text-gray-900 dark:text-white">Качество заданий</CardTitle>
            </CardHeader>
            <CardContent>
              <CardDescription className="text-center">
                Тщательно отобранные и проверенные тестовые задания, соответствующие стандартам ЕНТ
              </CardDescription>
            </CardContent>
          </Card>
        </div>

        {/* Technology Section */}
        <div className="mb-16">
          <Card className="bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-blue-950 dark:to-indigo-950 border-blue-500 dark:border-blue-500">
            <CardHeader className="text-center">
              <CardTitle className="text-2xl text-gray-900 dark:text-white mb-4">
                Современные технологии
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h4 className="font-semibold text-gray-900 dark:text-white mb-2">Frontend</h4>
                  <p className="text-gray-600 dark:text-gray-400 text-sm">
                    React 18, TypeScript, Tailwind CSS, Vite - для быстрого и отзывчивого интерфейса
                  </p>
                </div>
                <div>
                  <h4 className="font-semibold text-gray-900 dark:text-white mb-2">Backend</h4>
                  <p className="text-gray-600 dark:text-gray-400 text-sm">
                    Node.js, Express, PostgreSQL, Drizzle ORM - для надежной обработки данных
                  </p>
                </div>
                <div>
                  <h4 className="font-semibold text-gray-900 dark:text-white mb-2">Безопасность</h4>
                  <p className="text-gray-600 dark:text-gray-400 text-sm">
                    Аутентификация, CORS, rate limiting, валидация данных
                  </p>
                </div>
                <div>
                  <h4 className="font-semibold text-gray-900 dark:text-white mb-2">Производительность</h4>
                  <p className="text-gray-600 dark:text-gray-400 text-sm">
                    Кэширование, оптимизация запросов, PWA для офлайн работы
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Statistics Section */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-16">
          <div className="text-center">
            <div className="text-4xl font-bold text-blue-500 dark:text-blue-400 mb-2">50+</div>
            <div className="text-gray-600 dark:text-gray-400">API endpoints</div>
          </div>
          <div className="text-center">
            <div className="text-4xl font-bold text-green-600 dark:text-green-400 mb-2">15+</div>
            <div className="text-gray-600 dark:text-gray-400">Страниц приложения</div>
          </div>
          <div className="text-center">
            <div className="text-4xl font-bold text-purple-600 dark:text-purple-400 mb-2">100%</div>
            <div className="text-gray-600 dark:text-gray-400">Бесплатно</div>
          </div>
        </div>

        {/* Contact/CTA Section */}
        <div className="text-center">
          <Card className="max-w-2xl mx-auto bg-white dark:bg-gray-800 shadow-lg">
            <CardHeader>
              <CardTitle className="text-2xl text-gray-900 dark:text-white mb-4">
                Присоединяйтесь к нам!
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-gray-600 dark:text-gray-400 mb-6">
                Начните подготовку к ЕНТ уже сегодня. Зарегистрируйтесь для получения 
                персональной статистики и дополнительных возможностей.
              </p>
              <div className="flex flex-col sm:flex-row gap-3 justify-center">
                <Link href="/auth">
                  <Button size="lg" className="bg-blue-500 hover:bg-blue-700 text-white font-medium px-8">
                    Начать тестирование
                  </Button>
                </Link>
                <Link href="/public-tests">
                  <Button size="lg" variant="outline" className="border-blue-500 text-blue-500 hover:bg-blue-50 font-medium px-8">
                    Просмотреть тесты
                  </Button>
                </Link>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
