import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { Notification, NotificationType } from "@shared/schema";

export default function NotificationsPage() {
  const [, setLocation] = useLocation();
  const { toast } = useToast();
  const [currentPage, setCurrentPage] = useState(1);
  const [filterType, setFilterType] = useState<NotificationType | "all">("all");
  const [searchQuery, setSearchQuery] = useState("");
  const pageSize = 10;

  // Query for notifications with pagination and filters
  const { 
    data: notificationsData, 
    isLoading,
    error 
  } = useQuery({
    queryKey: ["/api/notifications", {
      page: currentPage,
      limit: pageSize,
      ...(filterType !== "all" && { type: filterType }),
    }],
  });

  // Query for unread count
  // На странице уведомлений обновляем каждые 2 минуты (когда пользователь активно смотрит)
  const { data: unreadCountRaw = 0 } = useQuery<number>({
    queryKey: ["/api/notifications/unread-count"],
    refetchInterval: 120000, // 2 минуты вместо 30 секунд
  });
  const unreadCount = Number(unreadCountRaw || 0);

  // Mutation to mark notification as read
  const markAsReadMutation = useMutation({
    mutationFn: (notificationId: string) => 
      apiRequest("POST", `/api/notifications/${notificationId}/mark-read`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/notifications"] });
      queryClient.invalidateQueries({ queryKey: ["/api/notifications/unread-count"] });
    },
  });

  // Mutation to mark all as read
  const markAllAsReadMutation = useMutation({
    mutationFn: () => 
      apiRequest("POST", "/api/notifications/mark-all-read"),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/notifications"] });
      queryClient.invalidateQueries({ queryKey: ["/api/notifications/unread-count"] });
      toast({ title: "Все уведомления отмечены как прочитанные" });
    },
  });

  // Mutation to delete notification
  const deleteNotificationMutation = useMutation({
    mutationFn: (notificationId: string) => 
      apiRequest("DELETE", `/api/notifications/${notificationId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/notifications"] });
      queryClient.invalidateQueries({ queryKey: ["/api/notifications/unread-count"] });
      toast({ title: "Уведомление удалено" });
    },
  });

  const handleNotificationClick = (notification: Notification) => {
    // Mark as read if unread
    if (!notification.isRead) {
      markAsReadMutation.mutate(notification.id);
    }

    // Handle navigation based on notification type and metadata
    if (notification.type === "TEST_COMPLETED" || notification.type === "TEST_REMINDER") {
      const variantId = (notification.metadata && (notification.metadata as any).variantId) || null;
      if (variantId) {
        setLocation(`/test/${variantId}`);
      } else {
        setLocation("/");
      }
    } else if (notification.type === "ACHIEVEMENT") {
      setLocation("/profile");
    }
  };

  const getNotificationIcon = (type: NotificationType) => {
    switch (type) {
      case "TEST_COMPLETED":
        return "fas fa-check-circle text-blue-500";
      case "TEST_REMINDER":
        return "fas fa-clock text-blue-500";
      case "ACHIEVEMENT":
        return "fas fa-trophy text-blue-500";
      case "SYSTEM_MESSAGE":
        return "fas fa-info-circle text-gray-500";
      default:
        return "fas fa-bell text-gray-500";
    }
  };

  const getTypeLabel = (type: NotificationType) => {
    switch (type) {
      case "TEST_COMPLETED":
        return "Тест завершен";
      case "TEST_REMINDER":
        return "Напоминание";
      case "ACHIEVEMENT":
        return "Достижение";
      case "SYSTEM_MESSAGE":
        return "Системное";
      default:
        return type;
    }
  };

  const getTypeBadgeVariant = (type: NotificationType) => {
    switch (type) {
      case "TEST_COMPLETED":
        return "default";
      case "TEST_REMINDER":
        return "secondary";
      case "ACHIEVEMENT":
        return "destructive";
      case "SYSTEM_MESSAGE":
        return "outline";
      default:
        return "outline";
    }
  };

  const formatTimeAgo = (date: string | Date) => {
    const now = new Date();
    const notificationDate = new Date(date);
    const diffInMinutes = Math.floor((now.getTime() - notificationDate.getTime()) / (1000 * 60));
    
    if (diffInMinutes < 1) return "только что";
    if (diffInMinutes < 60) return `${diffInMinutes} мин назад`;
    
    const diffInHours = Math.floor(diffInMinutes / 60);
    if (diffInHours < 24) return `${diffInHours} ч назад`;
    
    const diffInDays = Math.floor(diffInHours / 24);
    if (diffInDays < 7) return `${diffInDays} д назад`;
    
    return notificationDate.toLocaleDateString();
  };

  const notifications = (notificationsData && (notificationsData as any).notifications) || [];
  const totalNotifications = (notificationsData && (notificationsData as any).total) || 0;
  const totalPages = Math.ceil(totalNotifications / pageSize);

  // Filter notifications by search query
  const filteredNotifications = notifications.filter((notification: Notification) =>
    (notification.title || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
    (notification.message || '').toLowerCase().includes(searchQuery.toLowerCase())
  );

  const NotificationSkeleton = () => (
    <Card className="mb-4">
      <CardContent className="p-4">
        <div className="flex items-start space-x-3">
          <Skeleton className="h-4 w-4 rounded-full" />
          <div className="flex-1 space-y-2">
            <Skeleton className="h-4 w-3/4" />
            <Skeleton className="h-3 w-full" />
            <Skeleton className="h-3 w-1/2" />
          </div>
        </div>
      </CardContent>
    </Card>
  );

  if (error) {
    return (
      <div className="container mx-auto p-6">
        <Card>
          <CardContent className="p-6 text-center">
            <i className="fas fa-exclamation-triangle text-2xl text-destructive mb-4"></i>
            <p className="text-destructive">Ошибка загрузки уведомлений</p>
            <Button 
              variant="outline" 
              className="mt-4"
              onClick={() => window.location.reload()}
            >
              Попробовать снова
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setLocation("/dashboard")}
            data-testid="button-back"
          >
            <i className="fas fa-arrow-left"></i>
          </Button>
          <div>
            <h1 className="text-3xl font-bold">Уведомления</h1>
            <p className="text-muted-foreground mt-1">
              Управляйте своими уведомлениями и напоминаниями
            </p>
          </div>
        </div>
        <div className="flex items-center space-x-2">
          {unreadCount > 0 && (
            <Button
              variant="outline"
              onClick={() => markAllAsReadMutation.mutate()}
              disabled={markAllAsReadMutation.isPending}
              data-testid="button-mark-all-read"
            >
              <i className="fas fa-check mr-2"></i>
              Отметить все как прочитанные
            </Button>
          )}
          <Button
            variant="outline"
            onClick={() => setLocation("/profile")}
            data-testid="button-notification-settings"
          >
            <i className="fas fa-cog mr-2"></i>
            Настройки
          </Button>
        </div>
      </div>

      {/* Filters and Search */}
      <Card>
        <CardContent className="p-4">
          <div className="flex flex-col md:flex-row gap-4">
            <div className="flex-1">
              <Input
                placeholder="Поиск уведомлений..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                data-testid="input-search-notifications"
              />
            </div>
            <Select value={filterType} onValueChange={(value) => setFilterType(value as NotificationType | "all")}>
              <SelectTrigger className="w-full md:w-48" data-testid="select-notification-type">
                <SelectValue placeholder="Тип уведомления" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Все типы</SelectItem>
                <SelectItem value="TEST_COMPLETED">Тесты завершены</SelectItem>
                <SelectItem value="TEST_REMINDER">Напоминания</SelectItem>
                <SelectItem value="ACHIEVEMENT">Достижения</SelectItem>
                <SelectItem value="SYSTEM_MESSAGE">Системные</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Всего уведомлений</p>
                <p className="text-2xl font-bold">{totalNotifications}</p>
              </div>
              <i className="fas fa-bell text-2xl text-muted-foreground"></i>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Непрочитанные</p>
                <p className="text-2xl font-bold text-primary">{unreadCount}</p>
              </div>
              <i className="fas fa-envelope text-2xl text-primary"></i>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Прочитанные</p>
                <p className="text-2xl font-bold text-blue-500">{totalNotifications - unreadCount}</p>
              </div>
              <i className="fas fa-check-circle text-2xl text-blue-500"></i>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Notifications List */}
      <div className="space-y-4">
        {isLoading ? (
          <>
            {Array.from({ length: 5 }).map((_, i) => (
              <NotificationSkeleton key={i} />
            ))}
          </>
        ) : filteredNotifications.length === 0 ? (
          <Card>
            <CardContent className="p-8 text-center">
              <i className="fas fa-bell-slash text-4xl text-muted-foreground mb-4"></i>
              <h3 className="text-lg font-semibold mb-2">Уведомлений нет</h3>
              <p className="text-muted-foreground">
                {searchQuery || filterType !== "all" 
                  ? "Попробуйте изменить фильтры поиска" 
                  : "У вас пока нет уведомлений"}
              </p>
            </CardContent>
          </Card>
        ) : (
          filteredNotifications.map((notification: Notification) => (
            <Card 
              key={notification.id} 
              className={`transition-all cursor-pointer hover:shadow-md ${
                !notification.isRead ? "border-primary/50 bg-accent/30" : ""
              }`}
              onClick={() => handleNotificationClick(notification)}
              data-testid={`notification-card-${notification.id}`}
            >
              <CardContent className="p-4">
                <div className="flex items-start space-x-3">
                  <div className="flex-shrink-0 mt-1">
                    <i className={`${getNotificationIcon(notification.type as NotificationType)} text-lg`}></i>
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center space-x-2">
                        <h3 className="font-semibold text-foreground truncate">
                          {notification.title}
                        </h3>
                        {!notification.isRead && (
                          <div className="w-2 h-2 bg-primary rounded-full flex-shrink-0"></div>
                        )}
                      </div>
                      <div className="flex items-center space-x-2">
                        <Badge variant={getTypeBadgeVariant(notification.type as NotificationType)}>
                          {getTypeLabel(notification.type as NotificationType)}
                        </Badge>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={(e) => {
                            e.stopPropagation();
                            deleteNotificationMutation.mutate(notification.id);
                          }}
                          className="text-destructive hover:text-destructive h-auto p-1"
                          data-testid={`button-delete-${notification.id}`}
                        >
                          <i className="fas fa-trash text-xs"></i>
                        </Button>
                      </div>
                    </div>
                    <p className="text-sm text-muted-foreground mb-2">
                      {notification.message}
                    </p>
                    <div className="flex items-center justify-between text-xs text-muted-foreground">
                      <span>{formatTimeAgo(notification.createdAt || new Date())}</span>
                      {notification.readAt && (
                        <span>Прочитано {formatTimeAgo(notification.readAt || new Date())}</span>
                      )}
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <p className="text-sm text-muted-foreground">
                Показано {Math.min((currentPage - 1) * pageSize + 1, totalNotifications)} - {Math.min(currentPage * pageSize, totalNotifications)} из {totalNotifications}
              </p>
              <div className="flex items-center space-x-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setCurrentPage(currentPage - 1)}
                  disabled={currentPage === 1}
                  data-testid="button-prev-page"
                >
                  <i className="fas fa-chevron-left mr-1"></i>
                  Назад
                </Button>
                <span className="text-sm">
                  {currentPage} из {totalPages}
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setCurrentPage(currentPage + 1)}
                  disabled={currentPage === totalPages}
                  data-testid="button-next-page"
                >
                  Далее
                  <i className="fas fa-chevron-right ml-1"></i>
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
