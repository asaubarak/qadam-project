import { useQuery } from "@tanstack/react-query";
import { useAuth } from "@/hooks/use-auth";
import Header from "@/components/layout/header";
import Footer from "@/components/layout/footer";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { ExportDialog } from "@/components/ui/export-dialog";

interface RankingUser {
  userId: string;
  username: string;
  totalScore: number;
  testsCompleted: number;
  averagePercentage: number;
  lastUpdated: string;
}

export default function RankingPage() {
  const { user } = useAuth();

  const { data: rankings, isLoading } = useQuery<RankingUser[]>({
    queryKey: ["/api/rankings"],
  });

  const currentUserRank = rankings?.findIndex(r => r.userId === user?.id) ?? -1;

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background">
        <Header />
        <main className="container mx-auto px-4 lg:px-6 py-8">
          <div className="space-y-6">
            <Skeleton className="h-20 w-full" />
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {[...Array(3)].map((_, i) => (
                <Skeleton key={i} className="h-32" />
              ))}
            </div>
            <Skeleton className="h-96 w-full" />
          </div>
        </main>
      </div>
    );
  }

  const topThree = rankings?.slice(0, 3) || [];
  const restOfRankings = rankings?.slice(3) || [];

  return (
    <div className="min-h-screen bg-background">
      <Header />
      <main className="container mx-auto px-4 lg:px-6 py-8">
        {/* Header */}
        <div className="mb-8">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-4">
            <div className="text-center sm:text-left">
              <h1 className="text-3xl font-bold text-foreground mb-2">
                <i className="fas fa-trophy text-yellow-500 mr-3"></i>
                Рейтинг пользователей
              </h1>
              <p className="text-muted-foreground">
                Лучшие результаты по итогам всех пройденных тестов
              </p>
            </div>
            <ExportDialog 
              defaultType="RANKINGS"
              title="Экспорт рейтинга"
              description="Выберите формат для экспорта рейтинга пользователей"
            />
          </div>
        </div>

        {/* Current User Stats */}
        {currentUserRank >= 0 && (
          <Card className="mb-8 border-primary">
            <CardContent className="p-6">
              <div className="text-center space-y-2">
                <div className="h-16 w-16 mx-auto rounded-full bg-primary flex items-center justify-center">
                  <span className="text-xl font-bold text-primary-foreground">
                    {user?.username?.charAt(0).toUpperCase()}
                  </span>
                </div>
                <h3 className="text-xl font-semibold text-foreground">Ваша позиция</h3>
                <div className="text-3xl font-bold text-primary">#{currentUserRank + 1}</div>
                <div className="grid grid-cols-3 gap-4 mt-4">
                  <div className="text-center">
                    <div className="text-lg font-semibold text-foreground">
                      {rankings?.[currentUserRank]?.totalScore || 0}
                    </div>
                    <div className="text-sm text-muted-foreground">Общий счет</div>
                  </div>
                  <div className="text-center">
                    <div className="text-lg font-semibold text-foreground">
                      {rankings?.[currentUserRank]?.testsCompleted || 0}
                    </div>
                    <div className="text-sm text-muted-foreground">Тестов</div>
                  </div>
                  <div className="text-center">
                    <div className="text-lg font-semibold text-foreground">
                      {rankings?.[currentUserRank]?.averagePercentage?.toFixed(1) || 0}%
                    </div>
                    <div className="text-sm text-muted-foreground">Средний балл</div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Top 3 Podium */}
        {topThree.length > 0 && (
          <div className="mb-8">
            <h2 className="text-2xl font-semibold text-foreground mb-6 text-center">Топ-3</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {/* Second Place */}
              {topThree[1] && (
                <Card className="order-1 md:order-1 transform md:-translate-y-4">
                  <CardContent className="p-6 text-center">
                    <div className="relative mb-4">
                      <Avatar className="h-16 w-16 mx-auto">
                        <AvatarFallback className="bg-gray-100 text-gray-600 text-xl font-bold">
                          {topThree[1].username.charAt(0).toUpperCase()}
                        </AvatarFallback>
                      </Avatar>
                      <div className="absolute -top-2 -right-2 h-8 w-8 rounded-full bg-gray-400 flex items-center justify-center">
                        <span className="text-white font-bold text-sm">2</span>
                      </div>
                    </div>
                    <h3 className="font-semibold text-foreground mb-2">{topThree[1].username}</h3>
                    <div className="space-y-1">
                      <div className="text-xl font-bold text-foreground">{topThree[1].totalScore}</div>
                      <div className="text-sm text-muted-foreground">{topThree[1].testsCompleted} тестов</div>
                      <Badge variant="secondary">{topThree[1].averagePercentage.toFixed(1)}%</Badge>
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* First Place */}
              {topThree[0] && (
                <Card className="order-0 md:order-2 border-yellow-500 bg-gradient-to-b from-yellow-50 to-white dark:from-yellow-950/20 dark:to-background">
                  <CardContent className="p-6 text-center">
                    <div className="relative mb-4">
                      <Avatar className="h-20 w-20 mx-auto">
                        <AvatarFallback className="bg-yellow-100 text-yellow-600 text-2xl font-bold">
                          {topThree[0].username.charAt(0).toUpperCase()}
                        </AvatarFallback>
                      </Avatar>
                      <div className="absolute -top-2 -right-2 h-10 w-10 rounded-full bg-yellow-500 flex items-center justify-center">
                        <i className="fas fa-crown text-white"></i>
                      </div>
                    </div>
                    <h3 className="font-semibold text-foreground mb-2">{topThree[0].username}</h3>
                    <div className="space-y-1">
                      <div className="text-2xl font-bold text-yellow-600">{topThree[0].totalScore}</div>
                      <div className="text-sm text-muted-foreground">{topThree[0].testsCompleted} тестов</div>
                      <Badge className="bg-yellow-500 hover:bg-yellow-600">{topThree[0].averagePercentage.toFixed(1)}%</Badge>
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Third Place */}
              {topThree[2] && (
                <Card className="order-2 md:order-3 transform md:-translate-y-2">
                  <CardContent className="p-6 text-center">
                    <div className="relative mb-4">
                      <Avatar className="h-14 w-14 mx-auto">
                        <AvatarFallback className="bg-orange-100 text-orange-600 text-lg font-bold">
                          {topThree[2].username.charAt(0).toUpperCase()}
                        </AvatarFallback>
                      </Avatar>
                      <div className="absolute -top-2 -right-2 h-7 w-7 rounded-full bg-orange-500 flex items-center justify-center">
                        <span className="text-white font-bold text-xs">3</span>
                      </div>
                    </div>
                    <h3 className="font-semibold text-foreground mb-2">{topThree[2].username}</h3>
                    <div className="space-y-1">
                      <div className="text-lg font-bold text-foreground">{topThree[2].totalScore}</div>
                      <div className="text-sm text-muted-foreground">{topThree[2].testsCompleted} тестов</div>
                      <Badge variant="secondary">{topThree[2].averagePercentage.toFixed(1)}%</Badge>
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          </div>
        )}

        {/* Full Rankings Table */}
        <Card>
          <CardHeader>
            <CardTitle>Полный рейтинг</CardTitle>
          </CardHeader>
          <CardContent>
            {rankings && rankings.length > 0 ? (
              <div className="space-y-2">
                {rankings.map((ranking, index) => (
                  <div
                    key={ranking.userId}
                    className={`flex items-center justify-between p-4 rounded-lg border transition-colors ${
                      ranking.userId === user?.id
                        ? "border-primary bg-primary/5"
                        : "border-border hover:bg-muted/50"
                    }`}
                    data-testid={`ranking-row-${index + 1}`}
                  >
                    <div className="flex items-center space-x-4">
                      <div className={`h-8 w-8 rounded-full flex items-center justify-center font-bold text-sm ${
                        index === 0 ? "bg-yellow-500 text-white" :
                        index === 1 ? "bg-gray-400 text-white" :
                        index === 2 ? "bg-orange-500 text-white" :
                        "bg-muted text-muted-foreground"
                      }`}>
                        {index + 1}
                      </div>
                      
                      <Avatar className="h-10 w-10">
                        <AvatarFallback className="text-sm font-medium">
                          {ranking.username.charAt(0).toUpperCase()}
                        </AvatarFallback>
                      </Avatar>
                      
                      <div>
                        <div className="flex items-center space-x-2">
                          <h3 className="font-medium text-foreground">{ranking.username}</h3>
                          {ranking.userId === user?.id && (
                            <Badge variant="outline" className="text-xs">Вы</Badge>
                          )}
                        </div>
                        <p className="text-sm text-muted-foreground">
                          Последняя активность: {new Date(ranking.lastUpdated).toLocaleDateString()}
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center space-x-6 text-right">
                      <div>
                        <div className="text-lg font-bold text-foreground">{ranking.totalScore}</div>
                        <div className="text-xs text-muted-foreground">Общий счет</div>
                      </div>
                      
                      <div>
                        <div className="text-lg font-medium text-foreground">{ranking.testsCompleted}</div>
                        <div className="text-xs text-muted-foreground">Тестов</div>
                      </div>
                      
                      <div>
                        <Badge 
                          variant={
                            ranking.averagePercentage >= 80 ? "default" :
                            ranking.averagePercentage >= 60 ? "secondary" :
                            "destructive"
                          }
                          className="text-sm"
                        >
                          {ranking.averagePercentage.toFixed(1)}%
                        </Badge>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-12">
                <div className="h-16 w-16 mx-auto rounded-full bg-muted flex items-center justify-center mb-4">
                  <i className="fas fa-trophy text-muted-foreground text-xl"></i>
                </div>
                <h3 className="text-lg font-medium text-foreground mb-2">Рейтинг пуст</h3>
                <p className="text-muted-foreground">
                  Пока никто не прошел ни одного теста. Станьте первым!
                </p>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Stats Footer */}
        {rankings && rankings.length > 0 && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-8">
            <Card>
              <CardContent className="p-6 text-center">
                <div className="h-12 w-12 mx-auto rounded-full bg-primary/10 flex items-center justify-center mb-3">
                  <i className="fas fa-users text-primary"></i>
                </div>
                <div className="text-2xl font-bold text-foreground">{rankings.length}</div>
                <div className="text-sm text-muted-foreground">Активных пользователей</div>
              </CardContent>
            </Card>
            
            <Card>
              <CardContent className="p-6 text-center">
                <div className="h-12 w-12 mx-auto rounded-full bg-accent/10 flex items-center justify-center mb-3">
                  <i className="fas fa-chart-line text-accent"></i>
                </div>
                <div className="text-2xl font-bold text-foreground">
                  {(rankings.reduce((sum, r) => sum + r.averagePercentage, 0) / rankings.length).toFixed(1)}%
                </div>
                <div className="text-sm text-muted-foreground">Средний балл всех</div>
              </CardContent>
            </Card>
            
            <Card>
              <CardContent className="p-6 text-center">
                <div className="h-12 w-12 mx-auto rounded-full bg-blue-500/10 flex items-center justify-center mb-3">
                  <i className="fas fa-file-alt text-blue-500"></i>
                </div>
                <div className="text-2xl font-bold text-foreground">
                  {rankings.reduce((sum, r) => sum + r.testsCompleted, 0)}
                </div>
                <div className="text-sm text-muted-foreground">Всего тестов пройдено</div>
              </CardContent>
            </Card>
          </div>
        )}
      </main>
      <Footer />
    </div>
  );
}
