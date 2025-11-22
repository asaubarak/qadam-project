import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { 
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
  DropdownMenuLabel,
  DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { Notification, NotificationType } from "@shared/schema";

export default function NotificationBell() {
  const [, setLocation] = useLocation();
  const { toast } = useToast();
  const [isOpen, setIsOpen] = useState(false);

  // Query for unread notification count
  // Обновляется только при открытии dropdown и после действий (mark as read, delete)
  const { data: unreadCountRaw = 0 } = useQuery<number>({
    queryKey: ["/api/notifications/unread-count"],
    // refetchInterval убран - обновление только по действиям пользователя
  });
  const unreadCount = Number(unreadCountRaw || 0);

  // Query for recent notifications (for dropdown)
  const { data: notificationsData, isLoading } = useQuery<any>({
    queryKey: ["/api/notifications", { limit: 10 }],
    enabled: isOpen, // Only fetch when dropdown is open
    refetchOnMount: true, // Обновить при открытии dropdown
  });

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
    
    setIsOpen(false);
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

  return (
    <DropdownMenu open={isOpen} onOpenChange={setIsOpen}>
      <DropdownMenuTrigger asChild>
        <Button 
          variant="ghost" 
          size="icon" 
          className="relative"
          data-testid="button-notifications"
        >
          <i className="fas fa-bell text-lg"></i>
          {unreadCount > 0 && (
            <Badge 
              variant="destructive" 
              className="absolute -top-1 -right-1 h-5 w-5 flex items-center justify-center p-0 text-xs"
              data-testid="badge-unread-count"
            >
              {unreadCount > 99 ? "99+" : unreadCount}
            </Badge>
          )}
        </Button>
      </DropdownMenuTrigger>
      
      <DropdownMenuContent align="end" className="w-96 p-0" data-testid="dropdown-notifications">
        <DropdownMenuLabel className="flex items-center justify-between p-4 pb-2">
          <span className="font-semibold">Уведомления</span>
          {unreadCount > 0 && (
            <Button
              variant="ghost"
              size="sm"
              onClick={(e) => {
                e.stopPropagation();
                markAllAsReadMutation.mutate();
              }}
              className="text-xs h-auto p-1"
              data-testid="button-mark-all-read"
            >
              Отметить все
            </Button>
          )}
        </DropdownMenuLabel>
        
        <DropdownMenuSeparator />
        
        <ScrollArea className="max-h-96">
          {isLoading ? (
            <div className="p-4 text-center text-muted-foreground">
              <i className="fas fa-spinner fa-spin mr-2"></i>
              Загрузка...
            </div>
          ) : notifications.length === 0 ? (
            <div className="p-8 text-center text-muted-foreground">
              <i className="fas fa-bell-slash text-2xl mb-2 block"></i>
              <p>Нет уведомлений</p>
            </div>
          ) : (
            <div className="space-y-1 p-2">
              {notifications.map((notification: Notification) => (
                <div
                  key={notification.id}
                  className={`p-3 rounded-md cursor-pointer transition-colors hover:bg-accent ${
                    !notification.isRead ? "bg-accent/50" : ""
                  }`}
                  onClick={() => handleNotificationClick(notification)}
                  data-testid={`notification-${notification.id}`}
                >
                  <div className="flex items-start space-x-3">
                    <div className="flex-shrink-0 mt-1">
                      <i className={`${getNotificationIcon(notification.type as NotificationType)} text-sm`}></i>
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between">
                        <p className="text-sm font-medium text-foreground truncate">
                          {notification.title}
                        </p>
                        {!notification.isRead && (
                          <div className="w-2 h-2 bg-primary rounded-full flex-shrink-0 ml-2"></div>
                        )}
                      </div>
                      <p className="text-xs text-muted-foreground mt-1 line-clamp-2">
                        {notification.message}
                      </p>
                      <p className="text-xs text-muted-foreground mt-1">
                        {formatTimeAgo(notification.createdAt || new Date())}
                      </p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </ScrollArea>
        
        {notifications.length > 0 && (
          <>
            <DropdownMenuSeparator />
            <div className="p-2">
              <Button
                variant="ghost"
                className="w-full justify-center text-sm"
                onClick={() => {
                  setLocation("/notifications");
                  setIsOpen(false);
                }}
                data-testid="button-view-all-notifications"
              >
                Посмотреть все уведомления
              </Button>
            </div>
          </>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
