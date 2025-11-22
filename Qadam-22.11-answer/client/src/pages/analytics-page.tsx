import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { CalendarDays, TrendingUp, Trophy, Clock, BookOpen, Target, Users, Award } from "lucide-react";
import { 
  PieChart, 
  Pie, 
  Cell, 
  ResponsiveContainer, 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  Legend,
  BarChart,
  Bar,
  ComposedChart,
  Area,
  AreaChart
} from "recharts";
import { useState } from "react";
import type { 
  AnalyticsOverview, 
  SubjectAggregate, 
  HistoryPoint, 
  CorrectnessBreakdown, 
  ComparisonStats 
} from "@shared/schema";
import Header from "@/components/layout/header";
import { ExportDialog } from "@/components/ui/export-dialog";

const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884D8', '#82CA9D'];

export default function AnalyticsPage() {
  const [historyRange, setHistoryRange] = useState("30");
  const [correctnessRange, setCorrectnessRange] = useState("30");

  // Data queries
  const { data: overview, isLoading: overviewLoading } = useQuery<AnalyticsOverview>({
    queryKey: ["/api/analytics/overview"],
  });

  const { data: subjects, isLoading: subjectsLoading } = useQuery<SubjectAggregate[]>({
    queryKey: ["/api/analytics/subjects"],
  });

  const { data: history, isLoading: historyLoading } = useQuery<HistoryPoint[]>({
    queryKey: [`/api/analytics/history?range=${historyRange}`],
  });

  const { data: correctness, isLoading: correctnessLoading } = useQuery<CorrectnessBreakdown[]>({
    queryKey: [`/api/analytics/correctness?range=${correctnessRange}`],
  });

  const { data: comparison, isLoading: comparisonLoading } = useQuery<ComparisonStats>({
    queryKey: ["/api/analytics/comparison"],
  });

  const formatTime = (minutes: number) => {
    const hours = Math.floor(minutes / 60);
    const mins = minutes % 60;
    return hours > 0 ? `${hours}ч ${mins}м` : `${mins}м`;
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString("ru-RU", { 
      month: "short", 
      day: "numeric" 
    });
  };

  // Overview cards component
  const OverviewCards = () => {
    if (overviewLoading) {
      return (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {[...Array(8)].map((_, i) => (
            <Card key={i}>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <Skeleton className="h-4 w-[100px]" />
                <Skeleton className="h-4 w-4" />
              </CardHeader>
              <CardContent>
                <Skeleton className="h-8 w-[60px] mb-2" />
                <Skeleton className="h-3 w-[120px]" />
              </CardContent>
            </Card>
          ))}
        </div>
      );
    }

    if (!overview) return null;

    return (
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card data-testid="card-total-tests">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Всего тестов</CardTitle>
            <BookOpen className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="text-total-tests">{overview.totalTests}</div>
            <p className="text-xs text-muted-foreground">
              Завершенных тестирований
            </p>
          </CardContent>
        </Card>

        <Card data-testid="card-average-score">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Средний балл</CardTitle>
            <Target className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="text-average-score">{overview.averageScore.toFixed(1)}%</div>
            <p className="text-xs text-muted-foreground">
              Среднее по всем тестам
            </p>
          </CardContent>
        </Card>

        <Card data-testid="card-time-spent">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Время изучения</CardTitle>
            <Clock className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="text-time-spent">{formatTime(overview.totalTimeSpent)}</div>
            <p className="text-xs text-muted-foreground">
              Общее время за тесты
            </p>
          </CardContent>
        </Card>

        <Card data-testid="card-recent-activity">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Активность</CardTitle>
            <CalendarDays className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="text-recent-activity">{overview.recentActivity}</div>
            <p className="text-xs text-muted-foreground">
              Тестов за неделю
            </p>
          </CardContent>
        </Card>

        <Card data-testid="card-total-questions">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Всего вопросов</CardTitle>
            <BookOpen className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="text-total-questions">{overview.totalQuestions}</div>
            <p className="text-xs text-muted-foreground">
              Общее количество
            </p>
          </CardContent>
        </Card>

        <Card data-testid="card-correct-answers">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Правильных ответов</CardTitle>
            <Trophy className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="text-correct-answers">{overview.correctAnswers}</div>
            <p className="text-xs text-muted-foreground">
              Из {overview.totalQuestions} вопросов
            </p>
          </CardContent>
        </Card>

        <Card data-testid="card-best-subject">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Лучший предмет</CardTitle>
            <Award className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-lg font-bold truncate" data-testid="text-best-subject">
              {overview.bestSubject || "Нет данных"}
            </div>
            <p className="text-xs text-muted-foreground">
              Самый высокий результат
            </p>
          </CardContent>
        </Card>

        <Card data-testid="card-worst-subject">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Слабый предмет</CardTitle>
            <TrendingUp className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-lg font-bold truncate" data-testid="text-worst-subject">
              {overview.worstSubject || "Нет данных"}
            </div>
            <p className="text-xs text-muted-foreground">
              Требует внимания
            </p>
          </CardContent>
        </Card>
      </div>
    );
  };

  // Subjects pie chart component
  const SubjectsChart = () => {
    if (subjectsLoading) {
      return <Skeleton className="h-[400px] w-full" />;
    }

    if (!subjects || subjects.length === 0) {
      return (
        <div className="flex items-center justify-center h-[400px] text-muted-foreground" data-testid="empty-subjects">
          Нет данных по предметам
        </div>
      );
    }

    return (
      <ResponsiveContainer width="100%" height={400} data-testid="chart-subjects">
        <PieChart>
          <Pie
            data={subjects}
            cx="50%"
            cy="50%"
            labelLine={false}
            label={({ subjectName, averageScore }) => `${subjectName}: ${averageScore.toFixed(1)}%`}
            outerRadius={120}
            fill="#8884d8"
            dataKey="averageScore"
            nameKey="subjectName"
          >
            {subjects.map((_, index) => (
              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
            ))}
          </Pie>
          <Tooltip 
            formatter={(value: number, name: string) => [`${value.toFixed(1)}%`, "Средний балл"]}
            labelFormatter={(label) => `Предмет: ${label}`}
          />
          <Legend />
        </PieChart>
      </ResponsiveContainer>
    );
  };

  // History line chart component
  const HistoryChart = () => {
    if (historyLoading) {
      return <Skeleton className="h-[400px] w-full" />;
    }

    if (!history || history.length === 0) {
      return (
        <div className="flex items-center justify-center h-[400px] text-muted-foreground" data-testid="empty-history">
          Нет исторических данных
        </div>
      );
    }

    const chartData = history.map(point => ({
      ...point,
      formattedDate: formatDate(point.date),
    }));

    return (
      <ResponsiveContainer width="100%" height={400} data-testid="chart-history">
        <ComposedChart data={chartData}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="formattedDate" />
          <YAxis yAxisId="score" orientation="left" />
          <YAxis yAxisId="tests" orientation="right" />
          <Tooltip 
            labelFormatter={(label) => `Дата: ${label}`}
            formatter={(value: number, name: string) => {
              if (name === "Средний балл") return [`${value.toFixed(1)}%`, name];
              if (name === "Время") return [formatTime(value), name];
              return [value, name];
            }}
          />
          <Legend />
          <Area
            yAxisId="score"
            type="monotone"
            dataKey="averageScore"
            stroke="#8884d8"
            fill="#8884d8"
            fillOpacity={0.3}
            name="Средний балл"
          />
          <Bar
            yAxisId="tests"
            dataKey="testsCompleted"
            fill="#82ca9d"
            name="Тестов завершено"
          />
          <Line
            yAxisId="score"
            type="monotone"
            dataKey="totalTimeSpent"
            stroke="#ff7300"
            name="Время"
          />
        </ComposedChart>
      </ResponsiveContainer>
    );
  };

  // Correctness breakdown chart component
  const CorrectnessChart = () => {
    if (correctnessLoading) {
      return <Skeleton className="h-[400px] w-full" />;
    }

    if (!correctness || correctness.length === 0) {
      return (
        <div className="flex items-center justify-center h-[400px] text-muted-foreground" data-testid="empty-correctness">
          Нет данных о правильности ответов
        </div>
      );
    }

    const chartData = correctness.map(point => ({
      ...point,
      formattedDate: formatDate(point.date),
    }));

    return (
      <ResponsiveContainer width="100%" height={400} data-testid="chart-correctness">
        <BarChart data={chartData}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="formattedDate" />
          <YAxis />
          <Tooltip 
            labelFormatter={(label) => `Дата: ${label}`}
            formatter={(value: number, name: string) => [value, name]}
          />
          <Legend />
          <Bar dataKey="correctAnswers" stackId="a" fill="#00C49F" name="Правильные ответы" />
          <Bar dataKey="incorrectAnswers" stackId="a" fill="#FF8042" name="Неправильные ответы" />
        </BarChart>
      </ResponsiveContainer>
    );
  };

  // Comparison stats component
  const ComparisonChart = () => {
    if (comparisonLoading) {
      return <Skeleton className="h-[300px] w-full" />;
    }

    if (!comparison) {
      return (
        <div className="flex items-center justify-center h-[300px] text-muted-foreground" data-testid="empty-comparison">
          Нет данных для сравнения
        </div>
      );
    }

    const comparisonData = [
      { name: "Ваш результат", value: comparison.userScore, fill: "#0088FE" },
      { name: "Средний результат", value: comparison.averageScore, fill: "#00C49F" },
      { name: "Лучший результат", value: comparison.topUserScore, fill: "#FFBB28" },
    ];

    return (
      <div className="space-y-6" data-testid="chart-comparison">
        <div className="grid gap-4 md:grid-cols-3">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Ваш рейтинг</CardTitle>
              <Users className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold" data-testid="text-user-rank">{comparison.userRank}</div>
              <p className="text-xs text-muted-foreground">
                из {comparison.totalUsers} пользователей
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Ваш процентиль</CardTitle>
              <Trophy className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold" data-testid="text-percentile">{comparison.percentile.toFixed(1)}%</div>
              <p className="text-xs text-muted-foreground">
                лучше других пользователей
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Статус</CardTitle>
              <Award className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <Badge 
                variant={comparison.percentile >= 75 ? "default" : comparison.percentile >= 50 ? "secondary" : "outline"}
                data-testid="badge-status"
              >
                {comparison.percentile >= 75 ? "Отлично" : comparison.percentile >= 50 ? "Хорошо" : "Нужно подтянуть"}
              </Badge>
              <p className="text-xs text-muted-foreground mt-2">
                Продолжайте учиться!
              </p>
            </CardContent>
          </Card>
        </div>

        <ResponsiveContainer width="100%" height={250}>
          <BarChart data={comparisonData} layout="horizontal">
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis type="number" domain={[0, 100]} />
            <YAxis type="category" dataKey="name" width={150} />
            <Tooltip formatter={(value: number) => [`${value.toFixed(1)}%`, "Результат"]} />
            <Bar dataKey="value" fill="#8884d8" />
          </BarChart>
        </ResponsiveContainer>
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-background">
      <Header />
      <div className="container mx-auto px-4 py-8">
        <div className="mb-8 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold tracking-tight" data-testid="title-analytics">Аналитика результатов</h1>
            <p className="text-muted-foreground">
              Детальная статистика ваших результатов тестирования
            </p>
          </div>
          <ExportDialog 
            defaultType="USER_ANALYTICS"
            title="Экспорт аналитики"
            description="Выберите формат для экспорта вашей аналитики"
          />
        </div>

        <div className="space-y-8">
          <OverviewCards />

          <Tabs defaultValue="subjects" className="space-y-4" data-testid="tabs-analytics">
            <TabsList className="grid w-full grid-cols-4">
              <TabsTrigger value="subjects" data-testid="tab-subjects">Предметы</TabsTrigger>
              <TabsTrigger value="history" data-testid="tab-history">История</TabsTrigger>
              <TabsTrigger value="correctness" data-testid="tab-correctness">Правильность</TabsTrigger>
              <TabsTrigger value="comparison" data-testid="tab-comparison">Сравнение</TabsTrigger>
            </TabsList>

            <TabsContent value="subjects" className="space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle>Результаты по предметам</CardTitle>
                  <CardDescription>
                    Средние баллы и статистика по каждому предмету
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <SubjectsChart />
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="history" className="space-y-4">
              <Card>
                <CardHeader className="flex flex-row items-center justify-between">
                  <div>
                    <CardTitle>История результатов</CardTitle>
                    <CardDescription>
                      Динамика ваших результатов за выбранный период
                    </CardDescription>
                  </div>
                  <Select value={historyRange} onValueChange={setHistoryRange} data-testid="select-history-range">
                    <SelectTrigger className="w-32">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="7">7 дней</SelectItem>
                      <SelectItem value="30">30 дней</SelectItem>
                      <SelectItem value="90">90 дней</SelectItem>
                    </SelectContent>
                  </Select>
                </CardHeader>
                <CardContent>
                  <HistoryChart />
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="correctness" className="space-y-4">
              <Card>
                <CardHeader className="flex flex-row items-center justify-between">
                  <div>
                    <CardTitle>Анализ правильности ответов</CardTitle>
                    <CardDescription>
                      Соотношение правильных и неправильных ответов
                    </CardDescription>
                  </div>
                  <Select value={correctnessRange} onValueChange={setCorrectnessRange} data-testid="select-correctness-range">
                    <SelectTrigger className="w-32">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="7">7 дней</SelectItem>
                      <SelectItem value="30">30 дней</SelectItem>
                      <SelectItem value="90">90 дней</SelectItem>
                    </SelectContent>
                  </Select>
                </CardHeader>
                <CardContent>
                  <CorrectnessChart />
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="comparison" className="space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle>Сравнение с другими</CardTitle>
                  <CardDescription>
                    Как ваши результаты сравниваются с другими пользователями
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <ComparisonChart />
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </div>
      </div>
    </div>
  );
}
