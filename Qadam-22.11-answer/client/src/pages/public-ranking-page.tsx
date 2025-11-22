import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Trophy, Medal, Award, Users, TrendingUp, BookOpen } from "lucide-react";
import { Link } from "wouter";

interface RankingUser {
  userId: string;
  username: string;
  totalScore: number;
  testsCompleted: number;
  averagePercentage: number;
}

export default function PublicRankingPage() {
  // Получаем реальные данные рейтинга
  const { data: rankings, isLoading } = useQuery<RankingUser[]>({
    queryKey: ["/api/rankings"],
  });

  // Состояние для сортировки
  const [sortBy, setSortBy] = useState<'totalScore' | 'averagePercentage' | 'testsCompleted'>('totalScore');

  // Используем реальные данные из API
  const rawRankings = rankings || [];
  
  // Сортируем данные в зависимости от выбранного критерия
  const displayRankings = [...rawRankings].sort((a, b) => {
    switch (sortBy) {
      case 'totalScore':
        return b.totalScore - a.totalScore;
      case 'averagePercentage':
        return b.averagePercentage - a.averagePercentage;
      case 'testsCompleted':
        return b.testsCompleted - a.testsCompleted;
      default:
        return b.totalScore - a.totalScore;
    }
  });
  
  // Вычисляем статистику из реальных данных
  const displayStats = {
    totalUsers: displayRankings.length,
    totalTests: displayRankings.reduce((sum, user) => sum + user.testsCompleted, 0),
    averageScore: displayRankings.length > 0 
      ? displayRankings.reduce((sum, user) => sum + user.averagePercentage, 0) / displayRankings.length
      : 0,
  };

  if (isLoading) {
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
              <div className="flex space-x-3">
                <Link href="/">
                  <Button variant="ghost" className="text-white hover:bg-white/10 font-medium">
                    Главная
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
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {Array.from({ length: 10 }).map((_, i) => (
              <div key={i} className="h-20 bg-gray-200 dark:bg-gray-700 rounded-lg animate-pulse"></div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  const topThree = displayRankings.slice(0, 3);
  const restRankings = displayRankings.slice(3);

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
            <div className="flex space-x-3">
              <Link href="/">
                <Button variant="ghost" className="text-white hover:bg-white/10 font-medium">
                  Главная
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
        {/* Page Title */}
        <div className="text-center mb-12">
          <h1 className="text-4xl font-bold text-gray-900 dark:text-white mb-4">
            🏆 Рейтинг участников
          </h1>
          <p className="text-xl text-gray-600 dark:text-gray-400">
            Лучшие результаты по тестированию ЕНТ
          </p>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-12">
          <Card>
            <CardContent className="p-6 text-center">
              <Users className="h-12 w-12 text-blue-500 mx-auto mb-4" />
              <div className="text-3xl font-bold text-gray-900 dark:text-white mb-2">
                {displayStats.totalUsers.toLocaleString()}
              </div>
              <p className="text-gray-600 dark:text-gray-400">Участников</p>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-6 text-center">
              <BookOpen className="h-12 w-12 text-blue-500 mx-auto mb-4" />
              <div className="text-3xl font-bold text-gray-900 dark:text-white mb-2">
                {displayStats.totalTests.toLocaleString()}
              </div>
              <p className="text-gray-600 dark:text-gray-400">Пройдено тестов</p>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-6 text-center">
              <TrendingUp className="h-12 w-12 text-blue-500 mx-auto mb-4" />
              <div className="text-3xl font-bold text-gray-900 dark:text-white mb-2">
                {displayStats.averageScore.toFixed(1)}%
              </div>
              <p className="text-gray-600 dark:text-gray-400">Средний балл</p>
            </CardContent>
          </Card>
        </div>

        {/* Top 3 Winners */}
        {topThree.length > 0 && (
          <div className="mb-12">
            <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-8 text-center">
              🥇 Топ 3 лидера
            </h2>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {topThree.map((user, index) => (
                <Card 
                  key={user.userId} 
                  className={`relative overflow-hidden ${
                    index === 0 ? 'border-yellow-400 bg-gradient-to-b from-yellow-50 to-white dark:from-yellow-950/20 dark:to-background' :
                    index === 1 ? 'border-gray-400 bg-gradient-to-b from-gray-50 to-white dark:from-gray-950/20 dark:to-background' :
                    'border-orange-400 bg-gradient-to-b from-orange-50 to-white dark:from-orange-950/20 dark:to-background'
                  }`}
                >
                  <CardContent className="p-6 text-center">
                    <div className="relative mb-4">
                      <Avatar className="h-20 w-20 mx-auto">
                        <AvatarFallback className={
                          index === 0 ? "bg-yellow-100 text-yellow-600 text-2xl font-bold" :
                          index === 1 ? "bg-gray-100 text-gray-600 text-2xl font-bold" :
                          "bg-orange-100 text-orange-600 text-2xl font-bold"
                        }>
                          {user.username.charAt(0).toUpperCase()}
                        </AvatarFallback>
                      </Avatar>
                      <div className={`absolute -top-2 -right-2 h-10 w-10 rounded-full flex items-center justify-center ${
                        index === 0 ? 'bg-yellow-500' : index === 1 ? 'bg-gray-500' : 'bg-orange-500'
                      }`}>
                        {index === 0 ? <Trophy className="h-6 w-6 text-white" /> :
                         index === 1 ? <Medal className="h-6 w-6 text-white" /> :
                         <Award className="h-6 w-6 text-white" />}
                      </div>
                    </div>
                    
                    <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-2">
                      {user.username}
                    </h3>
                    <div className={`text-2xl font-bold mb-2 ${
                      index === 0 ? 'text-yellow-600' : index === 1 ? 'text-gray-600' : 'text-orange-600'
                    }`}>
                      {user.totalScore} баллов
                    </div>
                    <Badge className={
                      index === 0 ? "bg-yellow-500 hover:bg-yellow-600" :
                      index === 1 ? "bg-gray-500 hover:bg-gray-600" :
                      "bg-orange-500 hover:bg-orange-600"
                    }>
                      {user.averagePercentage.toFixed(1)}%
                    </Badge>
                    <p className="text-sm text-gray-600 dark:text-gray-400 mt-2">
                      {user.testsCompleted} тестов пройдено
                    </p>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        )}

        {/* Full Ranking Table */}
        {displayRankings && displayRankings.length > 0 && (
          <Card>
            <CardHeader>
              <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
                <CardTitle className="text-2xl font-bold text-gray-900 dark:text-white">
                  📊 Полный рейтинг
                </CardTitle>
                
                {/* Sorting Buttons */}
                <div className="flex flex-wrap gap-2">
                  <Button
                    variant={sortBy === 'totalScore' ? 'default' : 'outline'}
                    size="sm"
                    onClick={() => setSortBy('totalScore')}
                    className={sortBy === 'totalScore' ? 'bg-blue-500 hover:bg-blue-700' : ''}
                  >
                    📊 Баллы
                  </Button>
                  <Button
                    variant={sortBy === 'averagePercentage' ? 'default' : 'outline'}
                    size="sm"
                    onClick={() => setSortBy('averagePercentage')}
                    className={sortBy === 'averagePercentage' ? 'bg-blue-500 hover:bg-blue-700' : ''}
                  >
                    📈 Процент
                  </Button>
                  <Button
                    variant={sortBy === 'testsCompleted' ? 'default' : 'outline'}
                    size="sm"
                    onClick={() => setSortBy('testsCompleted')}
                    className={sortBy === 'testsCompleted' ? 'bg-blue-500 hover:bg-blue-700' : ''}
                  >
                    📝 Тесты
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {displayRankings.map((user, index) => (
                  <div 
                    key={user.userId} 
                    className={`flex items-center justify-between p-4 rounded-lg transition-colors ${
                      index < 3 ? 'bg-blue-50 dark:bg-blue-950/20 border border-blue-500 dark:border-blue-500' : 'hover:bg-gray-50 dark:hover:bg-gray-800'
                    }`}
                  >
                    <div className="flex items-center space-x-4">
                      <div className={`flex items-center justify-center w-10 h-10 rounded-full font-bold text-white ${
                        index === 0 ? "bg-yellow-500" :
                        index === 1 ? "bg-gray-500" :
                        index === 2 ? "bg-orange-500" :
                        "bg-blue-500"
                      }`}>
                        {index + 1}
                      </div>
                      
                      <Avatar className="h-12 w-12">
                        <AvatarFallback className="bg-blue-50 text-blue-500 font-medium">
                          {user.username.charAt(0).toUpperCase()}
                        </AvatarFallback>
                      </Avatar>
                      
                      <div>
                        <h3 className="font-semibold text-gray-900 dark:text-white">
                          {user.username}
                        </h3>
                        <p className="text-sm text-gray-600 dark:text-gray-400">
                          {user.testsCompleted} тестов пройдено
                        </p>
                      </div>
                    </div>
                    
                    <div className="text-right">
                      <div className={`text-2xl font-bold ${
                        sortBy === 'totalScore' ? 'text-blue-500' : 'text-gray-900 dark:text-white'
                      }`}>
                        {user.totalScore}
                      </div>
                      <div className="flex flex-col gap-1">
                        <Badge 
                          variant="outline" 
                          className={`text-xs ${
                            sortBy === 'averagePercentage' ? 'border-blue-500 text-blue-500' : ''
                          }`}
                        >
                          {user.averagePercentage.toFixed(1)}%
                        </Badge>
                        <Badge 
                          variant="secondary" 
                          className={`text-xs ${
                            sortBy === 'testsCompleted' ? 'border-blue-500 text-blue-500 bg-blue-50' : ''
                          }`}
                        >
                          {user.testsCompleted} тестов
                        </Badge>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Call to Action */}
        <div className="text-center mt-12 p-8 bg-white dark:bg-gray-800 rounded-lg shadow-lg">
          <h3 className="text-2xl font-bold text-gray-900 dark:text-white mb-4">
            Хотите попасть в рейтинг?
          </h3>
          <p className="text-gray-600 dark:text-gray-400 mb-6">
            Зарегистрируйтесь и начните проходить тесты ЕНТ
          </p>
          <Link href="/auth">
            <Button size="lg" className="bg-blue-500 text-white hover:bg-blue-700">
              Зарегистрироваться бесплатно
            </Button>
          </Link>
        </div>
      </div>
    </div>
  );
}

