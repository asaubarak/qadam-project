import { useQuery, useMutation } from "@tanstack/react-query";
import { useAuth } from "@/hooks/use-auth";
import Header from "@/components/layout/header";
import Footer from "@/components/layout/footer";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { NotificationSettings, InsertNotificationSettings } from "@shared/schema";

interface ProfileData {
  user: any;
  testResults: any[];
  ranking: any;
  subjectProgress: any[];
}

export default function ProfilePage() {
  const { user } = useAuth();
  const { toast } = useToast();

  const { data: profileData, isLoading } = useQuery<ProfileData>({
    queryKey: ["/api/profile"],
    enabled: !!user,
  });

  // Fetch rankings to calculate user position
  const { data: rankingsData } = useQuery<any[]>({
    queryKey: ["/api/rankings"],
    enabled: !!user && !!profileData,
  });

  // Query for notification settings
  const { data: notificationSettings, isLoading: settingsLoading } = useQuery<NotificationSettings>({
    queryKey: ["/api/notification-settings"],
    enabled: !!user,
  });

  // Calculate user's position in ranking
  const getUserRankingPosition = () => {
    if (!profileData?.ranking || !rankingsData) return "Тестті тапсырыңыз";
    
    const userTotalScore = profileData.ranking.totalScore;
    if (!userTotalScore) return "Тестті тапсырыңыз";
    
    // Sort rankings by totalScore descending and find user position
    const sortedRankings = rankingsData
      .filter(r => r.totalScore > 0)
      .sort((a, b) => b.totalScore - a.totalScore);
    
    const position = sortedRankings.findIndex(r => r.userId === user?.id) + 1;
    return position > 0 ? `#${position}` : "Не в топе";
  };

  // Calculate total time spent on tests
  const getTotalStudyTime = () => {
    if (!profileData?.testResults?.length) return "0м";
    
    // timeSpent is stored in seconds, convert to minutes and sum up
    const totalMinutes = profileData.testResults.reduce((total, result) => {
      // Convert seconds to minutes and round up (minimum 1 minute per test)
      const testMinutes = Math.max(1, Math.ceil((result.timeSpent || 0) / 60));
      return total + testMinutes;
    }, 0);
    
    if (totalMinutes >= 60) {
      const hours = Math.floor(totalMinutes / 60);
      const minutes = totalMinutes % 60;
      return minutes > 0 ? `${hours}ч ${minutes}м` : `${hours}ч`;
    } else {
      return `${totalMinutes}м`;
    }
  };

  // Mutation to update notification settings
  const updateSettingsMutation = useMutation({
    mutationFn: (settings: Partial<InsertNotificationSettings>) => 
      apiRequest("PUT", "/api/notification-settings", settings),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/notification-settings"] });
      toast({ title: "Хабарландыру баптаулары сақталды" });
    },
    onError: () => {
      toast({ 
        title: "Ошибка", 
        description: "Баптауларды сақтау мүмкін болмады",
        variant: "destructive" 
      });
    },
  });

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background">
        <Header />
        <main className="container mx-auto px-4 lg:px-6 py-8">
          <div className="space-y-6">
            <Skeleton className="h-32 w-full" />
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {[...Array(3)].map((_, i) => (
                <Skeleton key={i} className="h-24" />
              ))}
            </div>
            <Skeleton className="h-96 w-full" />
          </div>
        </main>
      </div>
    );
  }

  const stats = {
    testsCompleted: profileData?.testResults?.length || 0,
    averageScore: profileData?.ranking?.averagePercentage?.toFixed(1) || "0.0",
    totalScore: profileData?.ranking?.totalScore || 0,
    ranking: getUserRankingPosition(),
    studyTime: getTotalStudyTime(),
  };

  return (
    <div className="min-h-screen bg-background">
      <Header />
      <main className="container mx-auto px-4 lg:px-6 py-8">
        {/* Profile Header */}
        <div className="mb-8">
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center space-x-6">
                <div className="h-20 w-20 rounded-full bg-primary flex items-center justify-center">
                  <span className="text-2xl font-bold text-primary-foreground">
                    {user?.username?.charAt(0).toUpperCase()}
                  </span>
                </div>
                <div className="flex-1">
                  <h1 className="text-2xl font-bold text-foreground mb-2">{user?.username}</h1>
                  <p className="text-muted-foreground mb-4">
                    Участник с {new Date(user?.createdAt || Date.now()).toLocaleDateString()}
                  </p>
                  <div className="flex items-center space-x-4">
                    <Badge variant="secondary" className="px-3 py-1">
                      Общий счет: {stats.totalScore}
                    </Badge>
                    <Badge variant="outline" className="px-3 py-1">
                      {stats.ranking}
                    </Badge>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Stats Overview */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Пройдено тестов</p>
                  <p className="text-2xl font-bold text-foreground">{stats.testsCompleted}</p>
                </div>
                <div className="h-12 w-12 rounded-full bg-primary/10 flex items-center justify-center">
                  <i className="fas fa-check-circle text-primary"></i>
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Средний балл</p>
                  <p className="text-2xl font-bold text-foreground">{stats.averageScore}%</p>
                </div>
                <div className="h-12 w-12 rounded-full bg-accent/10 flex items-center justify-center">
                  <i className="fas fa-chart-line text-accent"></i>
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Рейтингтегі орын</p>
                  <p className="text-2xl font-bold text-foreground">{stats.ranking}</p>
                </div>
                <div className="h-12 w-12 rounded-full bg-blue-500/10 flex items-center justify-center">
                  <i className="fas fa-trophy text-blue-500"></i>
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Оқу уақыты</p>
                  <p className="text-2xl font-bold text-foreground">{stats.studyTime}</p>
                </div>
                <div className="h-12 w-12 rounded-full bg-blue-500/10 flex items-center justify-center">
                  <i className="fas fa-clock text-blue-500"></i>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        <Tabs defaultValue="results" className="space-y-6">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="results" data-testid="tab-results">Тест нәтижелері</TabsTrigger>
            <TabsTrigger value="progress" data-testid="tab-progress">Пәндер бойынша прогресс</TabsTrigger>
            <TabsTrigger value="achievements" data-testid="tab-achievements">Жетістіктер</TabsTrigger>
            <TabsTrigger value="settings" data-testid="tab-settings">Баптаулар</TabsTrigger>
          </TabsList>

          <TabsContent value="results" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle>Тестілеу тарихы</CardTitle>
              </CardHeader>
              <CardContent>
                {profileData?.testResults && profileData.testResults.length > 0 ? (
                  <div className="space-y-4">
                    {profileData.testResults.slice().reverse().map((result, index) => (
                      <div key={result.id} className="flex items-center justify-between p-4 rounded-lg border border-border">
                        <div className="flex items-center space-x-4">
                          <div className="h-10 w-10 rounded-lg bg-primary/10 flex items-center justify-center">
                            <i className="fas fa-file-alt text-primary"></i>
                          </div>
                          <div>
                            <p className="font-medium text-foreground">Тест #{result.id.slice(0, 8)}</p>
                            <p className="text-sm text-muted-foreground">
                              {new Date(result.completedAt).toLocaleDateString()} • 
                              Время: {Math.floor(result.timeSpent / 60)}м {result.timeSpent % 60}с
                            </p>
                          </div>
                        </div>
                        
                        <div className="flex items-center space-x-4">
                          <div className="text-right">
                            <Badge 
                              variant={result.percentage >= 80 ? "default" : 
                                      result.percentage >= 60 ? "secondary" : "destructive"}
                            >
                              {result.percentage.toFixed(0)}%
                            </Badge>
                            <p className="text-sm text-muted-foreground mt-1">
                              {result.score}/{result.totalQuestions}
                            </p>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <div className="h-16 w-16 mx-auto rounded-full bg-muted flex items-center justify-center mb-4">
                      <i className="fas fa-file-alt text-muted-foreground text-xl"></i>
                    </div>
                    <p className="text-muted-foreground">Пока нет завершенных тестов</p>
                    <p className="text-sm text-muted-foreground mt-2">
                      Нәтижелерді көру үшін тестілеуді бастаңыз
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="progress" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle>Пәндер бойынша прогресс</CardTitle>
              </CardHeader>
              <CardContent>
                {profileData?.subjectProgress && profileData.subjectProgress.length > 0 ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    {profileData.subjectProgress.map((progress, index) => {
                      const accuracy = progress.totalAnswered > 0 
                        ? (progress.correctAnswered / progress.totalAnswered) * 100 
                        : 0;
                      
                      return (
                        <div key={index} className="p-4 rounded-lg border border-border">
                          <div className="flex items-center justify-between mb-3">
                            <h3 className="font-medium text-foreground">{progress.subjectName}</h3>
                            <Badge variant="outline">{accuracy.toFixed(0)}%</Badge>
                          </div>
                          
                          <div className="space-y-2">
                            <div className="flex justify-between text-sm">
                              <span className="text-muted-foreground">Всего ответов:</span>
                              <span className="text-foreground">{progress.totalAnswered}</span>
                            </div>
                            <div className="flex justify-between text-sm">
                              <span className="text-muted-foreground">Правильных:</span>
                              <span className="text-accent">{progress.correctAnswered}</span>
                            </div>
                            <div className="w-full bg-muted rounded-full h-2 mt-3">
                              <div 
                                className={`h-2 rounded-full transition-all ${
                                  accuracy >= 80 ? 'bg-accent' :
                                  accuracy >= 60 ? 'bg-yellow-500' : 'bg-destructive'
                                }`}
                                style={{ width: `${Math.min(accuracy, 100)}%` }}
                              ></div>
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <div className="h-16 w-16 mx-auto rounded-full bg-muted flex items-center justify-center mb-4">
                      <i className="fas fa-chart-line text-muted-foreground text-xl"></i>
                    </div>
                    <p className="text-muted-foreground">Прогресс деректері жоқ</p>
                    <p className="text-sm text-muted-foreground mt-2">
                      Пройдите несколько тестов, чтобы увидеть статистику по предметам
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="achievements" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle>Достижения</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {/* Sample achievements - would be dynamic in real app */}
                  <div className={`p-4 rounded-lg border border-border ${
                    stats.testsCompleted >= 1 ? 'bg-accent/5 border-accent' : 'opacity-50'
                  }`}>
                    <div className="flex items-center space-x-3">
                      <div className={`h-10 w-10 rounded-full flex items-center justify-center ${
                        stats.testsCompleted >= 1 ? 'bg-accent text-accent-foreground' : 'bg-muted text-muted-foreground'
                      }`}>
                        <i className="fas fa-play"></i>
                      </div>
                      <div>
                        <p className="font-medium text-foreground">Первый тест</p>
                        <p className="text-xs text-muted-foreground">Пройти первый тест</p>
                      </div>
                    </div>
                  </div>

                  <div className={`p-4 rounded-lg border border-border ${
                    stats.testsCompleted >= 5 ? 'bg-accent/5 border-accent' : 'opacity-50'
                  }`}>
                    <div className="flex items-center space-x-3">
                      <div className={`h-10 w-10 rounded-full flex items-center justify-center ${
                        stats.testsCompleted >= 5 ? 'bg-accent text-accent-foreground' : 'bg-muted text-muted-foreground'
                      }`}>
                        <i className="fas fa-fire"></i>
                      </div>
                      <div>
                        <p className="font-medium text-foreground">Активность</p>
                        <p className="text-xs text-muted-foreground">Пройти 5 тестов</p>
                      </div>
                    </div>
                  </div>

                  <div className={`p-4 rounded-lg border border-border ${
                    parseFloat(stats.averageScore) >= 80 ? 'bg-accent/5 border-accent' : 'opacity-50'
                  }`}>
                    <div className="flex items-center space-x-3">
                      <div className={`h-10 w-10 rounded-full flex items-center justify-center ${
                        parseFloat(stats.averageScore) >= 80 ? 'bg-accent text-accent-foreground' : 'bg-muted text-muted-foreground'
                      }`}>
                        <i className="fas fa-star"></i>
                      </div>
                      <div>
                        <p className="font-medium text-foreground">Отличник</p>
                        <p className="text-xs text-muted-foreground">Средний балл 80%+</p>
                      </div>
                    </div>
                  </div>

                  <div className="p-4 rounded-lg border border-border opacity-50">
                    <div className="flex items-center space-x-3">
                      <div className="h-10 w-10 rounded-full bg-muted text-muted-foreground flex items-center justify-center">
                        <i className="fas fa-trophy"></i>
                      </div>
                      <div>
                        <p className="font-medium text-foreground">Топ-10</p>
                        <p className="text-xs text-muted-foreground">Попасть в топ-10 рейтинга</p>
                      </div>
                    </div>
                  </div>

                  <div className="p-4 rounded-lg border border-border opacity-50">
                    <div className="flex items-center space-x-3">
                      <div className="h-10 w-10 rounded-full bg-muted text-muted-foreground flex items-center justify-center">
                        <i className="fas fa-clock"></i>
                      </div>
                      <div>
                        <p className="font-medium text-foreground">Скорость</p>
                        <p className="text-xs text-muted-foreground">Завершить тест за 2 часа</p>
                      </div>
                    </div>
                  </div>

                  <div className="p-4 rounded-lg border border-border opacity-50">
                    <div className="flex items-center space-x-3">
                      <div className="h-10 w-10 rounded-full bg-muted text-muted-foreground flex items-center justify-center">
                        <i className="fas fa-graduation-cap"></i>
                      </div>
                      <div>
                        <p className="font-medium text-foreground">Мастер</p>
                        <p className="text-xs text-muted-foreground">100% по всем предметам</p>
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="settings" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle>Хабарландыру баптаулары</CardTitle>
              </CardHeader>
              <CardContent className="space-y-6">
                {settingsLoading ? (
                  <div className="space-y-4">
                    {Array.from({ length: 6 }).map((_, i) => (
                      <Skeleton key={i} className="h-12 w-full" />
                    ))}
                  </div>
                ) : (
                  <>
                    {/* Notification Types */}
                    <div>
                      <h3 className="text-lg font-medium mb-3">Типы уведомлений</h3>
                      <div className="space-y-3">
                        <div className="flex items-center justify-between">
                          <div className="space-y-0.5">
                            <Label className="text-base">Завершение тестов</Label>
                            <p className="text-sm text-muted-foreground">
                              Уведомления о завершении тестов и результатах
                            </p>
                          </div>
                          <Switch
                            checked={notificationSettings?.testCompletedEnabled ?? true}
                            onCheckedChange={(checked) =>
                              updateSettingsMutation.mutate({ testCompletedEnabled: checked })
                            }
                            data-testid="switch-test-completed"
                          />
                        </div>
                        
                        <Separator />
                        
                        <div className="flex items-center justify-between">
                          <div className="space-y-0.5">
                            <Label className="text-base">Напоминания о тестах</Label>
                            <p className="text-sm text-muted-foreground">
                              Напоминания о предстоящих или назначенных тестах
                            </p>
                          </div>
                          <Switch
                            checked={notificationSettings?.testReminderEnabled ?? true}
                            onCheckedChange={(checked) =>
                              updateSettingsMutation.mutate({ testReminderEnabled: checked })
                            }
                            data-testid="switch-test-reminders"
                          />
                        </div>
                        
                        <Separator />
                        
                        <div className="flex items-center justify-between">
                          <div className="space-y-0.5">
                            <Label className="text-base">Достижения</Label>
                            <p className="text-sm text-muted-foreground">
                              Уведомления о получении новых достижений и наград
                            </p>
                          </div>
                          <Switch
                            checked={notificationSettings?.achievementEnabled ?? true}
                            onCheckedChange={(checked) =>
                              updateSettingsMutation.mutate({ achievementEnabled: checked })
                            }
                            data-testid="switch-achievements"
                          />
                        </div>
                        
                        <Separator />
                        
                        <div className="flex items-center justify-between">
                          <div className="space-y-0.5">
                            <Label className="text-base">Системные сообщения</Label>
                            <p className="text-sm text-muted-foreground">
                              Важные объявления и обновления системы
                            </p>
                          </div>
                          <Switch
                            checked={notificationSettings?.systemMessageEnabled ?? true}
                            onCheckedChange={(checked) =>
                              updateSettingsMutation.mutate({ systemMessageEnabled: checked })
                            }
                            data-testid="switch-system-messages"
                          />
                        </div>
                      </div>
                    </div>

                    <Separator />

                    {/* Delivery Channels */}
                    <div>
                      <h3 className="text-lg font-medium mb-3">Способы доставки</h3>
                      <div className="space-y-3">
                        <div className="flex items-center justify-between">
                          <div className="space-y-0.5">
                            <Label className="text-base">В приложении</Label>
                            <p className="text-sm text-muted-foreground">
                              Показывать уведомления в интерфейсе приложения
                            </p>
                          </div>
                          <Switch
                            checked={notificationSettings?.inAppEnabled ?? true}
                            onCheckedChange={(checked) =>
                              updateSettingsMutation.mutate({ inAppEnabled: checked })
                            }
                            data-testid="switch-in-app"
                          />
                        </div>
                        
                        <Separator />
                        
                        <div className="flex items-center justify-between">
                          <div className="space-y-0.5">
                            <Label className="text-base">Push-уведомления</Label>
                            <p className="text-sm text-muted-foreground">
                              Уведомления в браузере (требуется разрешение)
                            </p>
                          </div>
                          <Switch
                            checked={notificationSettings?.pushEnabled ?? false}
                            onCheckedChange={(checked) =>
                              updateSettingsMutation.mutate({ pushEnabled: checked })
                            }
                            data-testid="switch-push"
                          />
                        </div>
                        
                        <Separator />
                        
                        <div className="flex items-center justify-between">
                          <div className="space-y-0.5">
                            <Label className="text-base">Email</Label>
                            <p className="text-sm text-muted-foreground">
                              Отправка уведомлений на электронную почту
                            </p>
                          </div>
                          <Switch
                            checked={notificationSettings?.emailEnabled ?? false}
                            onCheckedChange={(checked) =>
                              updateSettingsMutation.mutate({ emailEnabled: checked })
                            }
                            data-testid="switch-email"
                          />
                        </div>
                      </div>
                    </div>

                    <Separator />

                    {/* Reminder Settings */}
                    <div>
                      <h3 className="text-lg font-medium mb-3">Еске салу баптаулары</h3>
                      <div className="space-y-4">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div className="space-y-2">
                            <Label htmlFor="reminder-interval">Интервал напоминаний (минуты)</Label>
                            <Input
                              id="reminder-interval"
                              type="number"
                              min="5"
                              max="1440"
                              step="5"
                              value={notificationSettings?.reminderIntervalMinutes ?? 30}
                              onChange={(e) => {
                                const value = parseInt(e.target.value);
                                if (!isNaN(value)) {
                                  updateSettingsMutation.mutate({ reminderIntervalMinutes: value });
                                }
                              }}
                              data-testid="input-reminder-interval"
                            />
                          </div>
                          
                          <div className="space-y-2">
                            <Label htmlFor="max-reminders">Максимум напоминаний в день</Label>
                            <Input
                              id="max-reminders"
                              type="number"
                              min="1"
                              max="10"
                              value={notificationSettings?.maxRemindersPerDay ?? 3}
                              onChange={(e) => {
                                const value = parseInt(e.target.value);
                                if (!isNaN(value)) {
                                  updateSettingsMutation.mutate({ maxRemindersPerDay: value });
                                }
                              }}
                              data-testid="input-max-reminders"
                            />
                          </div>
                        </div>
                      </div>
                    </div>

                    <Separator />

                    {/* Quiet Hours */}
                    <div>
                      <h3 className="text-lg font-medium mb-3">Тихие часы</h3>
                      <p className="text-sm text-muted-foreground mb-4">
                        Уведомления не будут отправляться в указанное время
                      </p>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="space-y-2">
                          <Label htmlFor="quiet-start">Начало тихого времени</Label>
                          <Input
                            id="quiet-start"
                            type="time"
                            value={notificationSettings?.quietHoursStart ?? "22:00"}
                            onChange={(e) =>
                              updateSettingsMutation.mutate({ quietHoursStart: e.target.value })
                            }
                            data-testid="input-quiet-start"
                          />
                        </div>
                        
                        <div className="space-y-2">
                          <Label htmlFor="quiet-end">Конец тихого времени</Label>
                          <Input
                            id="quiet-end"
                            type="time"
                            value={notificationSettings?.quietHoursEnd ?? "08:00"}
                            onChange={(e) =>
                              updateSettingsMutation.mutate({ quietHoursEnd: e.target.value })
                            }
                            data-testid="input-quiet-end"
                          />
                        </div>
                      </div>
                    </div>

                    {/* Save Status */}
                    {updateSettingsMutation.isPending && (
                      <div className="flex items-center justify-center p-4 bg-accent/10 rounded-md">
                        <i className="fas fa-spinner fa-spin mr-2"></i>
                        <span className="text-sm">Сохранение настроек...</span>
                      </div>
                    )}
                  </>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </main>
      <Footer />
    </div>
  );
}
